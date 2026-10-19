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

/* Driver for the SFM-V1.7 capacitive fingerprint module (UART, 115200 8N1).
 * Frames: F5 cmd p1 p2 p3 00 chk F5, chk = XOR of bytes 2..6.
 * All calls except sfm_abort() are blocking and serialised by a mutex. */

#ifndef _SFM_H_
#define _SFM_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define SFM_UID_LEN             8
#define SFM_MAX_USERS           100

#define SFM_CMD_ENROLL_1        0x01
#define SFM_CMD_ENROLL_2        0x02
#define SFM_CMD_ENROLL_3        0x03
#define SFM_CMD_DELETE_USER     0x04
#define SFM_CMD_DELETE_ALL      0x05
#define SFM_CMD_USER_COUNT      0x09
#define SFM_CMD_MATCH_1_1       0x0B
#define SFM_CMD_MATCH_1_N       0x0C
#define SFM_CMD_FREE_ID         0x0D
#define SFM_CMD_LIST_USERS      0x2B
#define SFM_CMD_ENROLL_MODE     0x2D
#define SFM_CMD_FINGER_DETECT   0x30
#define SFM_CMD_CONFIG          0x3F
#define SFM_CMD_UNIQUE_ID       0x60
#define SFM_CMD_RING_LED        0xC3
#define SFM_CMD_ABORT           0xFE

/* Q3 result codes returned by the module */
#define SFM_ACK_SUCCESS         0x00
#define SFM_ACK_FAIL            0x01
#define SFM_ACK_FULL            0x04
#define SFM_ACK_NOUSER          0x05
#define SFM_ACK_USER_EXIST      0x07
#define SFM_ACK_TIMEOUT         0x08
#define SFM_ACK_HWERROR         0x0A
#define SFM_ACK_IMGERROR        0x10
#define SFM_ACK_ALGORITHMFAIL   0x11
#define SFM_ACK_HOMOLOGYFAIL    0x12
#define SFM_ACK_BREAK           0x18
/* Driver-side errors (not sent by the module) */
#define SFM_ERR_NO_RESPONSE     0xF0
#define SFM_ERR_BAD_FRAME       0xF1
#define SFM_ERR_NOT_READY       0xF2

/* Ring LED colours: low 3 bits are R,G,B, active low */
#define SFM_RING_YELLOW         0x01
#define SFM_RING_PURPLE         0x02
#define SFM_RING_RED            0x03
#define SFM_RING_CYAN           0x04
#define SFM_RING_GREEN          0x05
#define SFM_RING_BLUE           0x06
#define SFM_RING_OFF            0x07

/* User role stored with each template. We use a single role for everything. */
#define SFM_ROLE                0x01

/* Time the module waits for a finger in capture commands is ~8 s. */
#define SFM_CAPTURE_TIMEOUT_MS  10000
#define SFM_CMD_TIMEOUT_MS      1000

typedef struct {
    int uart_num;
    int tx_gpio;
    int rx_gpio;
    int en_gpio;      /* sensor VCC load switch, -1 if always powered */
    int touch_gpio;   /* TOUCH_OUT, -1 if not wired */
} sfm_config_t;

extern int sfm_init(const sfm_config_t *cfg);
extern bool sfm_is_ready(void);
extern void sfm_power(bool on);

/* Low level: send a command and wait for the matching ACK. Returns Q3 (SFM_ACK_*)
 * or SFM_ERR_*. q1/q2 may be NULL. */
extern uint8_t sfm_cmd(uint8_t cmd, uint8_t p1, uint8_t p2, uint8_t p3, uint8_t *q1, uint8_t *q2, uint32_t timeout_ms);

/* Interrupt a pending capture (match/enrol). Safe to call from any task. */
extern void sfm_abort(void);

extern uint8_t sfm_get_unique_id(uint8_t uid[SFM_UID_LEN]);
extern uint8_t sfm_get_user_count(uint16_t *count);
extern uint8_t sfm_list_users(uint16_t *ids, size_t max, size_t *count);
extern uint8_t sfm_match_1n(uint16_t *uid);
extern uint8_t sfm_enroll_step(uint8_t step, uint16_t id_req, uint16_t *id_out);
extern uint8_t sfm_delete_user(uint16_t id);
extern uint8_t sfm_delete_all(void);
extern uint8_t sfm_ring(uint8_t start_color, uint8_t end_color, uint16_t period_ms);
extern uint8_t sfm_set_deny_duplicates(bool deny);
extern uint8_t sfm_enable_film_detection(void);
extern bool sfm_finger_present(void);

#endif // _SFM_H_
