/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2026 Andrei Vladescu.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/* Fingerprint policy layer. See spec.md, sections 3-5.
 *
 * Every fingerprint action (user presence, user verification, enrolment
 * capture) runs inside the SDK's normal button wait: the card task calls
 * wait_button_pressed_timeout(), the SDK emits SIGNAL_USER_PRESENCE_REQUEST,
 * and the bio task runs the queued job against the sensor. Success produces a
 * pressed/released pulse through picokey_button_read(); failure sets
 * cancel_button. Keepalives, CTAPHID_CANCEL, timeouts and the LED therefore
 * behave exactly like a button press. */

#ifndef _BIO_H_
#define _BIO_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define BIO_MAX_TEMPLATES       10
#define BIO_NAME_MAX            32
#define BIO_MAX_UV_RETRIES      5
#define BIO_ENROLL_SAMPLES      3
#define BIO_TEMPLATE_ID_LEN     2

/* CTAP 2.1 lastEnrollSampleStatus values */
#define CTAP2_ENROLL_FEEDBACK_FP_GOOD           0x00
#define CTAP2_ENROLL_FEEDBACK_FP_POOR_QUALITY   0x07
#define CTAP2_ENROLL_FEEDBACK_FP_EXISTS         0x0B
#define CTAP2_ENROLL_FEEDBACK_NO_USER_ACTIVITY  0x0D

typedef enum {
    BIO_MODE_PROBING = 0,   // boot, sensor not probed yet
    BIO_MODE_BUTTON,        // no sensor, never bound: stock button
    BIO_MODE_UNBOUND,       // sensor present, nothing enrolled: button or any finger
    BIO_MODE_BOUND,         // sensor present and enrolled: fingerprint match only
    BIO_MODE_LOCKED,        // enrolled but sensor missing/replaced: presence denied
} bio_mode_t;

typedef struct {
    uint16_t id;
    uint8_t name_len;
    char name[BIO_NAME_MAX];
} bio_template_t;

/* Result of the last verification/enrolment capture */
typedef enum {
    BIO_RES_NONE = 0,
    BIO_RES_OK,
    BIO_RES_NO_MATCH,
    BIO_RES_TIMEOUT,
    BIO_RES_CANCELLED,
    BIO_RES_EXISTS,         // enrol: finger already enrolled
    BIO_RES_POOR_QUALITY,   // enrol: bad capture, sample discarded
    BIO_RES_FULL,
    BIO_RES_ERROR,
} bio_result_t;

extern void bio_init(void);
extern bio_mode_t bio_mode(void);
extern bool bio_sensor_present(void);
extern bool bio_is_bound(void);

/* Presence hooks used by fido.c / presence.c */
extern bool bio_requires_match(void);    // bound or locked: button alone never counts
extern bool bio_presence_denied(void);
extern bool bio_presence_forced(void);
extern bool bio_button_read(bool raw_button);
extern void bio_allow_button(bool allow);

/* Built-in user verification */
extern bool bio_uv_configured(void);   // bound and device key unlocked
extern uint8_t bio_uv_retries(void);
extern void bio_uv_retries_reset(void);
/* Returns 0 on match, or a CTAP2_ERR_* code. */
extern int bio_verify(void);

/* Enrolment (authenticatorBioEnrollment) */
extern int bio_enroll_begin(uint16_t *template_id, uint8_t *status, uint8_t *remaining);
extern int bio_enroll_next(uint16_t template_id, uint8_t *status, uint8_t *remaining);
extern void bio_enroll_cancel(void);

extern size_t bio_template_count(void);
extern const bio_template_t *bio_template_at(size_t index);
extern const bio_template_t *bio_template_find(uint16_t id);
extern int bio_template_set_name(uint16_t id, const uint8_t *name, size_t len);
extern int bio_template_remove(uint16_t id);

/* authenticatorReset: delete all templates on the sensor and unbind */
extern void bio_reset(void);

#endif // _BIO_H_
