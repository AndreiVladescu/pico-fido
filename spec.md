# Pico FIDO Bio: ESP32-S3 fingerprint fork

## 1. Goal

Build a USB FIDO2 security key on ESP32-S3 that reuses the pico-fido firmware and adds an optional
SFM-V1.7 capacitive fingerprint sensor. One PCB design, two population options:

| Variant | Sensor | User presence (UP) | User verification (UV) |
|---|---|---|---|
| Button | not fitted | press button (GPIO0) | PIN only (stock) |
| Fingerprint | SFM-V1.7 | fingerprint match once enrolled; button/touch before | PIN or fingerprint (CTAP 2.1 built-in UV) |

The fingerprint variant is the more secure one: after you enrol a finger, nobody else can use the
key just by touching it.

## 2. Repository strategy

- This repo is a fork (`origin` = AndreiVladescu/pico-fido, `upstream` = polhenarejos/pico-fido).
  Upstream releases are merged in; our changes are mostly new files plus small `#ifdef ENABLE_BIO`
  hooks in upstream files.
- Only ESP32-S3 is built (`build_esp32.sh`). The Pico code stays in the tree, unbuilt. ESP32-S3 is
  required: native USB, plus secure boot / flash encryption support already in pico-keys-sdk.
- `pico-keys-sdk` (submodule) gets one patch: the board button read becomes a weak function
  `picokey_button_read()`. The SDK already provides the other hooks we need: weak
  `picokey_init()`, and the `SIGNAL_USER_PRESENCE_{REQUEST,COMPLETED,CANCELLED,TIMEOUT}` signals.
  The user forks pico-keys-sdk and pushes that commit there.

## 3. Architecture

```
        ┌──────────── upstream FIDO code (card task) ─────────────┐
        │ makeCredential / getAssertion / U2F register / reset ... │
        │        check_user_presence() → wait_button_pressed()     │
        └──────────────┬───────────────────────────────────────────┘
                       │ EV_PRESS_BUTTON (queue)
        ┌──────────────▼─────────────── core0 task (SDK) ──────────┐
        │ button_wait_start → SIGNAL_USER_PRESENCE_REQUEST          │
        │ button_wait_poll  → picokey_button_read() every 10 ms     │
        └──────────────┬───────────────────────────────────────────┘
                       │ weak override
        ┌──────────────▼────────┐        ┌───────────────────────┐
        │ src/bio/presence.c    │◄──────►│ src/bio/bio.c         │
        │ button vs fingerprint │        │ policy + match task   │
        └───────────────────────┘        └──────────┬────────────┘
                                                    │
                                         ┌──────────▼────────────┐
                                         │ src/bio/sfm.c (UART)  │
                                         └───────────────────────┘
```

### 3.1 Modes (decided at boot, re-evaluated on enrol/reset)

| State | Condition | UP satisfied by |
|---|---|---|
| `BIO_MODE_BUTTON` | sensor absent and not bound | button (stock) |
| `BIO_MODE_UNBOUND` | sensor present, no owned templates | button or finger touch on sensor |
| `BIO_MODE_BOUND` | sensor present, ≥1 owned template, unique id matches | fingerprint match only |
| `BIO_MODE_LOCKED` | bound, but sensor missing or unique id differs | nothing (UP fails) |

`authenticatorReset` always accepts the button, in every mode. A reset wipes all credentials, deletes
all templates on the sensor and clears the binding, so allowing it can't leak anything and stops
a LOCKED device from being bricked.

### 3.2 Persistent state

A new flash file `EF_BIO` (FID `0xCF20`) holds:

```
struct bio_state {
    uint8_t  version;            // 1
    uint8_t  sensor_uid[8];      // SFM 0x60 unique id at bind time
    uint8_t  uv_retries;         // remaining built-in UV attempts
    uint8_t  count;              // number of owned templates
    struct { uint16_t id; char name[BIO_NAME_MAX]; } t[BIO_MAX_TEMPLATES];
};
```

"Bound" = `count > 0`. Only ids listed here count as a match.

### 3.3 Match task

`bio.c` runs a FreeRTOS task that owns the UART. Requests come in through a queue:

- `SIGNAL_USER_PRESENCE_REQUEST` (bound mode) → loop `0x0C` 1:N matches (each waits up to 8 s)
  until a match on an owned id, or until stopped. On a match, set a pulse latch that
  `picokey_button_read()` reports as pressed then released. Ring LED: blue breathing while waiting,
  green on match, red on mismatch.
- `SIGNAL_USER_PRESENCE_{COMPLETED,CANCELLED,TIMEOUT}` → send `0xFE` abort and go idle.
- Synchronous UV requests (`bio_verify()`), used by `getPinUvAuthTokenUsingUv` and by
  makeCredential/getAssertion with `uv=true`, block the card task until match/fail/timeout/cancel.
- Enrol steps (`bio_enroll_*`), driven by `authenticatorBioEnrollment`.

## 4. Level 1: fingerprint as user presence

- In `BOUND`, every UP needs a match. This also covers U2F (`cmd_register`/`cmd_authenticate`) and
  hosts that never ask for UV.
- `check_user_presence_internal()` in `fido.c`: when `bio_requires_match()` is true, force the wait
  (`force_button_wait = true`) even if `up_btn` was never commissioned.
- `check_user_presence_for_credential(false)` (credential with "no button" policy) still requires a
  match in BOUND mode.

## 5. Level 2: CTAP 2.1 built-in UV

### 5.1 getInfo (`cbor_get_info.c`)

When the sensor is present (not BUTTON mode):

- options `uv`: true if bound, false if not (capable but not configured).
- options `bioEnroll`: true if bound, false if not.
- `uvModality` (0x0E): `0x02` (fingerprint internal).
- `preferredPlatformUvAttempts` (0x11): 3. `maxUvAttemptsForInternalDetection`? Not needed.
- `uvCountSinceLastPinEntry`: not implemented.

### 5.2 clientPIN (`cbor_client_pin.c`)

- `0x06 getPinUvAuthTokenUsingUvWithPermissions`: requires bound + uv_retries > 0. Calls
  `bio_verify()`; on success the token is issued exactly like subcommand 0x09 (same permissions/rpId
  handling), and `uv_retries` is reset. On failure → decrement `uv_retries`, return
  `CTAP2_ERR_UV_INVALID`, or `CTAP2_ERR_UV_BLOCKED` at 0.
- `0x07 getUVRetries`: returns `uvRetries` (0x05).
- A successful PIN token (0x05/0x09) resets `uv_retries`.

### 5.3 makeCredential / getAssertion

`options.uv == true` currently returns `CTAP2_ERR_INVALID_OPTION`. With a bound sensor:

- `bio_verify()` → success sets `FIDO2_AUT_FLAG_UV`, and since a finger was presented also
  `FIDO2_AUT_FLAG_UP` (no second touch needed).
- Failure → `CTAP2_ERR_UV_INVALID` / `CTAP2_ERR_UV_BLOCKED`.
- `pinUvAuthParam` still takes priority (spec order).

### 5.4 authenticatorBioEnrollment (0x09, new `cbor_bio_enroll.c`)

Every subcommand except `getFingerprintSensorInfo` needs a pinUvAuthToken with the `be` permission
(0x08), verified the same way as `cbor_cred_mgmt.c`.

| subCommand | Behaviour | SFM |
|---|---|---|
| 0x01 enrollBegin | allocate id, capture 1 → `templateId`, `lastEnrollSampleStatus`, `remainingSamples=2` | `0x2D` deny dup, `0x01` |
| 0x02 enrollCaptureNextSample | capture 2 or 3 → `remainingSamples` 1/0; on 0, record id in `EF_BIO` | `0x02`, `0x03` |
| 0x03 cancelCurrentEnrollment | abort | `0xFE` |
| 0x04 enumerateEnrollments | list owned ids + names | (flash) |
| 0x05 setFriendlyName | rename | (flash) |
| 0x06 removeEnrollment | delete | `0x04` |
| 0x07 getFingerprintSensorInfo | `fingerprintKind=1` (touch), `maxCaptureSamplesRequiredForEnroll=3`, `maxTemplateFriendlyName` | — |

The first successful enrolment records the sensor unique id (bind). Removing the last template
returns the device to UNBOUND. Sample status mapping: SFM `ACK_SUCCESS`→`CTAP2_ENROLL_FEEDBACK_FP_GOOD`,
`ACK_TIMEOUT`→`NO_USER_ACTIVITY` (error `CTAP2_ERR_USER_ACTION_TIMEOUT`), `ACK_HOMOLOGYFAIL`→
`FP_TOO_SIMILAR`/mismatch, `ACK_USER_EXIST`→`MATCHED`, other→`FP_POOR_QUALITY`.

`authenticatorReset` additionally sends `0x05` (delete all) and erases `EF_BIO`.

## 6. Security

1. **No downgrade:** see the LOCKED state. Swapping in a sensor pre-enrolled with an attacker's
   finger changes the unique id → LOCKED.
2. **Foreign templates:** a matched id that isn't in `EF_BIO` is treated as no match.
3. **Retry limit:** `BIO_MAX_UV_RETRIES` = 5. At 0, built-in UV is blocked until PIN is used.
   UP-only matching (Level 1) is not counted, because each attempt needs a fresh touch and gives no UV.
4. **Unverifiable match result:** the SFM matches on the module and answers over plain UART, so an
   attacker who opens the device can fake "match OK". Accepted risk for this project; mitigate by
   enclosing or potting the sensor-to-MCU wiring. Enable ESP32-S3 secure boot + flash encryption to
   protect key material.
5. **Anti-spoof:** enable SFM film-attack detection (`0x3F 00 04 01`) before enrolment and matching
   level 2 (default, 1/1M FAR).

## 7. Hardware

- ESP32-S3-MINI-1 (N8), USB-C straight to GPIO19/20, USBLC6-2SC6 ESD, 3.3 V LDO ≥ 500 mA.
- Tactile button on GPIO0 (UP on the button board, BOOT/recovery on both).
- WS2812/SK6805 status LED (SDK default GPIO48 on S3).
- 6-pin 1.0 mm sensor connector: V_TOUCH → 3V3; VCC → 3V3 via P-MOSFET (AO3401) switched by
  `BIO_EN_GPIO`; TX/RX → UART1; TOUCH_OUT → RTC-capable GPIO.
- Default pins (CMake options): UART1 TX=GPIO17, RX=GPIO18, EN=-1 (always on), TOUCH=-1.
- Keep free: strapping 0/3/45/46 (except the button on 0), USB 19/20.

## 8. Plan

1. ✅ Fork setup, ESP32-only build script, SDK button hook; stock firmware builds.
2. SFM driver + self-test at boot (unique id, user count, ring LED) logged over serial.
3. Level 1: presence provider, binding, LOCKED state, reset escape.
4. Level 2: `bioEnroll`, `uv` in getInfo, clientPIN 0x06/0x07, UV flag in makeCredential/getAssertion.
5. PCB, using pins validated on a dev board.

Other to-dos before shipping: own AAGUID, own USB VID/PID (0x2E8A is Raspberry Pi's).
