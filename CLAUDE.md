# CLAUDE.md

Notes for working on this fork. The full design is in [spec.md](spec.md).

## What this fork is

A fork of [pico-fido](https://github.com/polhenarejos/pico-fido) (remote `upstream`) that targets
**ESP32-S3 only** and adds an optional **SFM-V1.7 fingerprint sensor**. One firmware image serves
two PCB variants:

- **Button board:** no sensor. User presence = press the button on GPIO0 (stock behaviour).
- **Fingerprint board:** SFM-V1.7 fitted. After the first finger is enrolled, every user-presence
  check needs a fingerprint match, and the authenticator offers CTAP 2.1 built-in user verification
  (`uv`, `bioEnroll`).

The variant is detected at runtime by probing the sensor over UART at boot.

## Ground rules

- **Keep upstream mergeable.** Prefer new files over edits to existing ones. Every edit to an
  upstream file is wrapped in `#ifdef ENABLE_BIO` and kept as small as possible.
- **Pico (RP2040/RP2350) code stays in the tree but is not built.** Don't delete it, and don't
  spend effort keeping it compiling with `ENABLE_BIO`.
- **`pico-keys-sdk` is a submodule.** It carries one small patch: `picokey_button_read()` is a weak
  function so this repo can override the button. That commit must be pushed to the user's SDK fork
  before the submodule pointer in this repo is pushed. Don't add more SDK changes unless unavoidable.
- Match the surrounding C style: 4-space indent, `snake_case`, `PICOKEYS_OK`/`CTAP2_ERR_*` return
  codes, `CBOR_*` helper macros in `cbor_*.c`.
- License: AGPL-3.0 (inherited). Distributed binaries must ship with source.

## Build

ESP-IDF v5.5.x, installed with EIM under `~/.espressif` (`IDF_PATH` is not set in the shell).

```sh
./build_esp32.sh                    # build + release/pico_fido_bio_esp32s3-<ver>.bin
./build_esp32.sh flash /dev/ttyACM0 # build + flash
IDF_CMAKE_ARGS="-DENABLE_BIO=OFF" ./build_esp32.sh   # stock build, no fingerprint code
```

The build directory is `build_esp32/`. The first build fetches mbedtls/tinycbor into
`pico-keys-sdk/third-party/` and IDF managed components into `managed_components/`.

Board pin options (CMake cache, see `CMakeLists.txt`): `BIO_UART_NUM`, `BIO_UART_TX_GPIO`,
`BIO_UART_RX_GPIO`, `BIO_EN_GPIO` (sensor VCC load switch, -1 = always powered),
`BIO_TOUCH_GPIO` (sensor TOUCH_OUT, -1 = not wired).

## Code map

| Path | What |
|---|---|
| `src/fido/` | Upstream FIDO2/U2F/OATH/OTP application. |
| `src/fido/fido.c` | `wait_button_pressed_timeout()` / `check_user_presence*()`: every UP check goes through here. |
| `src/fido/cbor_*.c` | One file per CTAP2 command. Dispatch is in `cbor.c`. |
| `src/bio/sfm.c` | SFM-V1.7 UART driver (blocking calls, ESP-IDF `uart_driver`). |
| `src/bio/bio.c` | Fingerprint policy: probe, binding, match task, UV retries, template store. |
| `src/bio/presence.c` | Overrides `picokey_button_read()` / `picokey_init()`; picks button vs fingerprint. |
| `src/fido/cbor_bio_enroll.c` | CTAP `authenticatorBioEnrollment` (0x09). |
| `pico-keys-sdk/src/button.c` | Async button wait, driven from the core0 task every 10 ms. |
| `pico-keys-sdk/src/signal.h` | `SIGNAL_USER_PRESENCE_*` events; `bio.c` subscribes to start/stop matching. |

## How user presence flows

1. FIDO code (card task) calls `wait_button_pressed_timeout()` → posts `EV_PRESS_BUTTON` to the
   USB/core0 task and blocks on the queue.
2. core0 calls `button_wait_start_timeout()` → emits `SIGNAL_USER_PRESENCE_REQUEST`, then polls
   `picokey_button_read()` every 10 ms until pressed→released, timeout, or CTAPHID cancel.
3. In fingerprint mode `bio.c` starts a 1:N match on the REQUEST signal. A match on an id we own
   produces one pressed→released pulse from `picokey_button_read()`.

A timeout of 0 means "don't wait" upstream (`up_btn` not commissioned). Bound fingerprint mode
forces the wait with `force_button_wait`.

## SFM-V1.7 quick reference

8-byte frames `F5 cmd p1 p2 p3 00 chk F5`, where chk = XOR of bytes 2..6. 115200 8N1, 3.3 V.
Data packets: `F5 <data> chk F5`. Commands used: `0x01/0x02/0x03` (3-capture enroll),
`0x04` (delete id), `0x05` (delete all), `0x09` (user count), `0x0C` (1:N match), `0x2B` (list ids),
`0x2D` (deny duplicate enroll), `0x30` (finger present?), `0x60` (module unique id), `0xC3` (ring LED),
`0xFE` (abort). The capture commands wait up to 8 s for a finger. The protocol PDF (Chinese) is in
<https://github.com/Matrixchung/SFM-V1.7/tree/main/extras>.

Connector: 6-pin, 1.0 mm pitch. V_TOUCH (3V3 always on), TOUCH_OUT, VCC (switched 3V3), TX, RX, GND.
Check the pin order against the datasheet drawing before laying out a PCB.

## Security invariants (don't break these)

- Once a finger is enrolled ("bound"), the button alone must never satisfy user presence, except
  for `authenticatorReset` (wiping the device is always allowed and clears the binding).
- Bound + sensor missing or sensor unique id changed → user presence fails (no silent downgrade).
- Only template ids recorded in our flash file count as a match. Ids already on the sensor from
  elsewhere are ignored.
- After `BIO_MAX_UV_RETRIES` failed matches, built-in UV is blocked until a PIN token is obtained.
