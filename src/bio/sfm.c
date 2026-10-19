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

#include "sfm.h"
#include <string.h>

#ifdef ESP_PLATFORM

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"

static const char *TAG = "sfm";

#define SFM_FRAME_LEN   8
#define SFM_START       0xF5
#define SFM_RX_BUF      512
#define SFM_BOOT_MS     200

static sfm_config_t sfm_cfg = { .uart_num = -1, .en_gpio = -1, .touch_gpio = -1 };
static SemaphoreHandle_t sfm_mutex = NULL;
static bool sfm_ready = false;

static uint8_t sfm_checksum(const uint8_t *buf, size_t len) {
    uint8_t chk = 0;
    for (size_t i = 0; i < len; i++) {
        chk ^= buf[i];
    }
    return chk;
}

static void sfm_write_frame(uint8_t cmd, uint8_t p1, uint8_t p2, uint8_t p3) {
    uint8_t frame[SFM_FRAME_LEN] = { SFM_START, cmd, p1, p2, p3, 0x00, 0x00, SFM_START };
    frame[6] = sfm_checksum(frame + 1, 5);
    uart_write_bytes(sfm_cfg.uart_num, frame, sizeof(frame));
    uart_wait_tx_done(sfm_cfg.uart_num, pdMS_TO_TICKS(50));
}

/* Read one F5..F5 frame of exactly `len` bytes (start and end markers included).
 * Bytes before the start marker are dropped. For ACK frames, back-to-back
 * markers (the end of a frame we missed followed by the start of the next)
 * collapse into one; data packets may legitimately start with 0xF5. */
static bool sfm_read_frame(uint8_t *buf, size_t len, TickType_t deadline, bool collapse) {
    size_t got = 0;
    while (got < len) {
        TickType_t now = xTaskGetTickCount();
        if ((int32_t)(deadline - now) <= 0) {
            return false;
        }
        uint8_t b;
        if (uart_read_bytes(sfm_cfg.uart_num, &b, 1, deadline - now) != 1) {
            continue;
        }
        if (got == 0 && b != SFM_START) {
            continue;
        }
        if (collapse && got == 1 && b == SFM_START) {
            continue;
        }
        buf[got++] = b;
    }
    return buf[len - 1] == SFM_START;
}

/* Wait for the 8-byte ACK of `cmd`. Frames for other commands (e.g. the
 * answer to an abort sent while idle) are skipped. */
static uint8_t sfm_read_ack(uint8_t cmd, uint8_t *ack, TickType_t deadline) {
    while (true) {
        if (!sfm_read_frame(ack, SFM_FRAME_LEN, deadline, true)) {
            return SFM_ERR_NO_RESPONSE;
        }
        if (sfm_checksum(ack + 1, 5) != ack[6]) {
            uart_flush_input(sfm_cfg.uart_num);
            return SFM_ERR_BAD_FRAME;
        }
        if (ack[1] == cmd || (cmd == SFM_CMD_ENROLL_2 && ack[1] == SFM_CMD_ENROLL_3)) {
            return SFM_ACK_SUCCESS;
        }
        ESP_LOGD(TAG, "skipping ack for 0x%02x while waiting for 0x%02x", ack[1], cmd);
    }
}

static uint8_t sfm_transact(uint8_t cmd, uint8_t p1, uint8_t p2, uint8_t p3, uint8_t *ack, uint32_t timeout_ms) {
    uart_flush_input(sfm_cfg.uart_num);
    sfm_write_frame(cmd, p1, p2, p3);
    uint8_t ret = sfm_read_ack(cmd, ack, xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms));
    if (ret != SFM_ACK_SUCCESS) {
        return ret;
    }
    return ack[4];
}

uint8_t sfm_cmd(uint8_t cmd, uint8_t p1, uint8_t p2, uint8_t p3, uint8_t *q1, uint8_t *q2, uint32_t timeout_ms) {
    if (sfm_mutex == NULL) {
        return SFM_ERR_NOT_READY;
    }
    uint8_t ack[SFM_FRAME_LEN] = { 0 };
    xSemaphoreTake(sfm_mutex, portMAX_DELAY);
    uint8_t ret = sfm_transact(cmd, p1, p2, p3, ack, timeout_ms);
    xSemaphoreGive(sfm_mutex);
    if (q1) {
        *q1 = ack[2];
    }
    if (q2) {
        *q2 = ack[3];
    }
    return ret;
}

/* Commands answered by an 8-byte header followed by "F5 <data> chk F5". */
static uint8_t sfm_cmd_data(uint8_t cmd, uint8_t *data, size_t max, size_t *len, bool len_in_header) {
    if (sfm_mutex == NULL) {
        return SFM_ERR_NOT_READY;
    }
    uint8_t ack[SFM_FRAME_LEN] = { 0 };
    xSemaphoreTake(sfm_mutex, portMAX_DELAY);
    uint8_t ret = sfm_transact(cmd, 0, 0, 0, ack, SFM_CMD_TIMEOUT_MS);
    if (ret == SFM_ACK_SUCCESS) {
        size_t dlen = len_in_header ? ((size_t)ack[2] << 8 | ack[3]) : *len;
        if (dlen > max) {
            ret = SFM_ERR_BAD_FRAME;
        }
        else {
            uint8_t pkt[SFM_FRAME_LEN + 2 * SFM_MAX_USERS * 3];
            TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(SFM_CMD_TIMEOUT_MS);
            if (dlen + 3 > sizeof(pkt) || !sfm_read_frame(pkt, dlen + 3, deadline, false)) {
                ret = SFM_ERR_NO_RESPONSE;
            }
            else if (sfm_checksum(pkt + 1, dlen) != pkt[dlen + 1]) {
                ret = SFM_ERR_BAD_FRAME;
            }
            else {
                memcpy(data, pkt + 1, dlen);
                *len = dlen;
            }
        }
    }
    xSemaphoreGive(sfm_mutex);
    return ret;
}

void sfm_abort(void) {
    if (!sfm_ready) {
        return;
    }
    /* No mutex: the owner of the mutex is blocked reading the capture ACK,
     * which the module sends with ACK_BREAK once it sees this frame. */
    sfm_write_frame(SFM_CMD_ABORT, 0, 0, 0);
}

void sfm_power(bool on) {
    if (sfm_cfg.en_gpio >= 0) {
        gpio_set_level(sfm_cfg.en_gpio, on ? 1 : 0);
    }
}

int sfm_init(const sfm_config_t *cfg) {
    sfm_cfg = *cfg;
    if (sfm_cfg.uart_num < 0) {
        return -1;
    }
    if (sfm_cfg.en_gpio >= 0) {
        gpio_reset_pin(sfm_cfg.en_gpio);
        gpio_set_direction(sfm_cfg.en_gpio, GPIO_MODE_OUTPUT);
    }
    if (sfm_cfg.touch_gpio >= 0) {
        gpio_reset_pin(sfm_cfg.touch_gpio);
        gpio_set_direction(sfm_cfg.touch_gpio, GPIO_MODE_INPUT);
        gpio_pulldown_en(sfm_cfg.touch_gpio);
    }
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    if (uart_driver_install(sfm_cfg.uart_num, SFM_RX_BUF, 0, 0, NULL, 0) != ESP_OK ||
        uart_param_config(sfm_cfg.uart_num, &uart_config) != ESP_OK ||
        uart_set_pin(sfm_cfg.uart_num, sfm_cfg.tx_gpio, sfm_cfg.rx_gpio, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE) != ESP_OK) {
        ESP_LOGE(TAG, "UART%d setup failed", sfm_cfg.uart_num);
        return -1;
    }
    /* Keep RX idle-high when the connector is empty, so we read nothing rather than noise. */
    gpio_pullup_en(sfm_cfg.rx_gpio);
    sfm_mutex = xSemaphoreCreateMutex();
    sfm_power(true);
    vTaskDelay(pdMS_TO_TICKS(SFM_BOOT_MS));

    uint8_t uid[SFM_UID_LEN];
    sfm_ready = true;
    if (sfm_get_unique_id(uid) != SFM_ACK_SUCCESS) {
        sfm_ready = false;
        ESP_LOGI(TAG, "no sensor detected on UART%d", sfm_cfg.uart_num);
        return -1;
    }
    return 0;
}

bool sfm_is_ready(void) {
    return sfm_ready;
}

uint8_t sfm_get_unique_id(uint8_t uid[SFM_UID_LEN]) {
    size_t len = SFM_UID_LEN;
    uint8_t buf[SFM_UID_LEN];
    uint8_t ret = sfm_cmd_data(SFM_CMD_UNIQUE_ID, buf, sizeof(buf), &len, false);
    if (ret == SFM_ACK_SUCCESS) {
        memcpy(uid, buf, SFM_UID_LEN);
    }
    return ret;
}

uint8_t sfm_get_user_count(uint16_t *count) {
    uint8_t q1 = 0, q2 = 0;
    uint8_t ret = sfm_cmd(SFM_CMD_USER_COUNT, 0, 0, 0, &q1, &q2, SFM_CMD_TIMEOUT_MS);
    *count = ret == SFM_ACK_SUCCESS ? (uint16_t)(q1 << 8 | q2) : 0;
    return ret;
}

uint8_t sfm_list_users(uint16_t *ids, size_t max, size_t *count) {
    uint8_t buf[2 + SFM_MAX_USERS * 3];
    size_t len = 0;
    *count = 0;
    uint8_t ret = sfm_cmd_data(SFM_CMD_LIST_USERS, buf, sizeof(buf), &len, true);
    if (ret == SFM_ACK_FAIL) {
        return SFM_ACK_SUCCESS; // empty database
    }
    if (ret != SFM_ACK_SUCCESS || len < 2) {
        return ret;
    }
    size_t n = (size_t)(buf[0] << 8 | buf[1]);
    for (size_t i = 0; i < n && i < max && 4 + 3 * i < len; i++) {
        ids[i] = (uint16_t)(buf[2 + 3 * i] << 8 | buf[3 + 3 * i]);
        (*count)++;
    }
    return SFM_ACK_SUCCESS;
}

uint8_t sfm_match_1n(uint16_t *uid) {
    uint8_t q1 = 0, q2 = 0;
    uint8_t ret = sfm_cmd(SFM_CMD_MATCH_1_N, 0, 0, 0, &q1, &q2, SFM_CAPTURE_TIMEOUT_MS);
    *uid = (uint16_t)(q1 << 8 | q2);
    /* On a 1:N match Q3 carries the user role, not ACK_SUCCESS. A non-zero id is the match. */
    if (*uid != 0) {
        return SFM_ACK_SUCCESS;
    }
    if (ret == SFM_ACK_SUCCESS || ret == SFM_ROLE) {
        return SFM_ACK_FAIL;
    }
    return ret;
}

/* 3C3R enrolment. step is 1, 2 or 3. On step 1 id_req picks the id (0 = auto).
 * On the last step (or an early ACK of type 0x03) id_out gets the stored id. */
uint8_t sfm_enroll_step(uint8_t step, uint16_t id_req, uint16_t *id_out) {
    uint8_t ack[SFM_FRAME_LEN] = { 0 };
    uint8_t cmd = step == 1 ? SFM_CMD_ENROLL_1 : step == 2 ? SFM_CMD_ENROLL_2 : SFM_CMD_ENROLL_3;
    if (sfm_mutex == NULL) {
        return SFM_ERR_NOT_READY;
    }
    xSemaphoreTake(sfm_mutex, portMAX_DELAY);
    uint8_t ret = step == 1
        ? sfm_transact(cmd, id_req >> 8, id_req & 0xFF, SFM_ROLE, ack, SFM_CAPTURE_TIMEOUT_MS)
        : sfm_transact(cmd, 0, 0, 0, ack, SFM_CAPTURE_TIMEOUT_MS);
    xSemaphoreGive(sfm_mutex);
    if (id_out) {
        *id_out = (uint16_t)(ack[2] << 8 | ack[3]);
    }
    /* An ACK of type 0x03 to step 2 means the enrolment ended early. */
    if (step == 2 && ack[1] == SFM_CMD_ENROLL_3 && ret == SFM_ACK_SUCCESS) {
        return SFM_ACK_FAIL;
    }
    return ret;
}

uint8_t sfm_delete_user(uint16_t id) {
    return sfm_cmd(SFM_CMD_DELETE_USER, id >> 8, id & 0xFF, 0, NULL, NULL, SFM_CMD_TIMEOUT_MS);
}

uint8_t sfm_delete_all(void) {
    return sfm_cmd(SFM_CMD_DELETE_ALL, 0, 0, 0, NULL, NULL, SFM_CMD_TIMEOUT_MS);
}

uint8_t sfm_ring(uint8_t start_color, uint8_t end_color, uint16_t period_ms) {
    uint16_t period = period_ms / 10;
    if (period < 30) {
        period = 30;
    }
    else if (period > 200) {
        period = 200;
    }
    return sfm_cmd(SFM_CMD_RING_LED, start_color, end_color, (uint8_t)period, NULL, NULL, SFM_CMD_TIMEOUT_MS);
}

uint8_t sfm_set_deny_duplicates(bool deny) {
    return sfm_cmd(SFM_CMD_ENROLL_MODE, 0, deny ? 1 : 0, 0, NULL, NULL, SFM_CMD_TIMEOUT_MS);
}

uint8_t sfm_enable_film_detection(void) {
    return sfm_cmd(SFM_CMD_CONFIG, 0x00, 0x04, 0x01, NULL, NULL, SFM_CMD_TIMEOUT_MS);
}

bool sfm_finger_present(void) {
    if (sfm_cfg.touch_gpio >= 0) {
        return gpio_get_level(sfm_cfg.touch_gpio) == 1;
    }
    return sfm_cmd(SFM_CMD_FINGER_DETECT, 0, 0, 0, NULL, NULL, SFM_CMD_TIMEOUT_MS) == SFM_ACK_SUCCESS;
}

#else // !ESP_PLATFORM

int sfm_init(const sfm_config_t *cfg) { (void)cfg; return -1; }
bool sfm_is_ready(void) { return false; }
void sfm_power(bool on) { (void)on; }
uint8_t sfm_cmd(uint8_t cmd, uint8_t p1, uint8_t p2, uint8_t p3, uint8_t *q1, uint8_t *q2, uint32_t timeout_ms) {
    (void)cmd; (void)p1; (void)p2; (void)p3; (void)q1; (void)q2; (void)timeout_ms;
    return SFM_ERR_NOT_READY;
}
void sfm_abort(void) {}
uint8_t sfm_get_unique_id(uint8_t uid[SFM_UID_LEN]) { (void)uid; return SFM_ERR_NOT_READY; }
uint8_t sfm_get_user_count(uint16_t *count) { *count = 0; return SFM_ERR_NOT_READY; }
uint8_t sfm_list_users(uint16_t *ids, size_t max, size_t *count) { (void)ids; (void)max; *count = 0; return SFM_ERR_NOT_READY; }
uint8_t sfm_match_1n(uint16_t *uid) { *uid = 0; return SFM_ERR_NOT_READY; }
uint8_t sfm_enroll_step(uint8_t step, uint16_t id_req, uint16_t *id_out) { (void)step; (void)id_req; (void)id_out; return SFM_ERR_NOT_READY; }
uint8_t sfm_delete_user(uint16_t id) { (void)id; return SFM_ERR_NOT_READY; }
uint8_t sfm_delete_all(void) { return SFM_ERR_NOT_READY; }
uint8_t sfm_ring(uint8_t start_color, uint8_t end_color, uint16_t period_ms) { (void)start_color; (void)end_color; (void)period_ms; return SFM_ERR_NOT_READY; }
uint8_t sfm_set_deny_duplicates(bool deny) { (void)deny; return SFM_ERR_NOT_READY; }
uint8_t sfm_enable_film_detection(void) { return SFM_ERR_NOT_READY; }
bool sfm_finger_present(void) { return false; }

#endif // ESP_PLATFORM
