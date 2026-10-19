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

#include "picokeys.h"
#include "bio.h"
#include "sfm.h"
#include "fido.h"
#include "files.h"
#include "ctap.h"
#include "button.h"
#include "signal.h"
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#ifndef BIO_UART_NUM
#define BIO_UART_NUM        1
#endif
#ifndef BIO_UART_TX_GPIO
#define BIO_UART_TX_GPIO    17
#endif
#ifndef BIO_UART_RX_GPIO
#define BIO_UART_RX_GPIO    18
#endif
#ifndef BIO_EN_GPIO
#define BIO_EN_GPIO         -1
#endif
#ifndef BIO_TOUCH_GPIO
#define BIO_TOUCH_GPIO      -1
#endif

#define BIO_STATE_VERSION   1
#define BIO_PROBE_WAIT_MS   3000
#define BIO_RING_PERIOD_MS  1000
#define BIO_RESULT_SHOW_MS  400

static const char *TAG = "bio";

/* Persistent state (EF_BIO). Only the card task writes it. */
typedef struct {
    uint8_t sensor_uid[SFM_UID_LEN];
    uint8_t uv_retries;
    uint8_t count;
    bio_template_t t[BIO_MAX_TEMPLATES];
} bio_state_t;

static bio_state_t st;
static volatile bio_mode_t mode = BIO_MODE_PROBING;
static bool sensor_present = false;
static uint8_t sensor_uid[SFM_UID_LEN] = { 0 };

/* Job handed from the card task to the bio task through a button wait */
typedef enum {
    BIO_JOB_PRESENCE = 0,
    BIO_JOB_VERIFY,
    BIO_JOB_ENROLL,
} bio_job_t;

static volatile bio_job_t job_next = BIO_JOB_PRESENCE;   // set by card task
static volatile bio_job_t job_kind = BIO_JOB_PRESENCE;   // latched on REQUEST
static volatile bool job_active = false;
static volatile bool job_busy = false;
static volatile bio_result_t job_result = BIO_RES_NONE;
static volatile uint8_t enroll_step = 0;                 // 1..3 while enrolling
static volatile uint16_t enroll_id = 0;
static volatile uint16_t job_uid = 0;
static volatile uint8_t pulse = 0;                       // 0 idle, 1 press, 2 release
static volatile bool allow_button = false;
static TaskHandle_t bio_task_handle = NULL;

/* ---------------------------------------------------------------- storage */

static file_t *bio_file(void) {
    return file_search_by_fid(EF_BIO, NULL, SPECIFY_EF);
}

static void bio_state_clear(void) {
    memset(&st, 0, sizeof(st));
    st.uv_retries = BIO_MAX_UV_RETRIES;
}

static void bio_load(void) {
    bio_state_clear();
    file_t *ef = bio_file();
    if (!file_has_data(ef)) {
        return;
    }
    const uint8_t *p = file_get_data(ef);
    size_t len = file_get_size(ef);
    if (len < 2 + SFM_UID_LEN + 1 || p[0] != BIO_STATE_VERSION) {
        ESP_LOGW(TAG, "EF_BIO unreadable, ignoring");
        return;
    }
    size_t off = 1;
    memcpy(st.sensor_uid, p + off, SFM_UID_LEN);
    off += SFM_UID_LEN;
    st.uv_retries = p[off++];
    uint8_t count = p[off++];
    for (uint8_t i = 0; i < count && i < BIO_MAX_TEMPLATES && off + 3 <= len; i++) {
        bio_template_t *t = &st.t[st.count];
        t->id = (uint16_t)(p[off] << 8 | p[off + 1]);
        t->name_len = p[off + 2];
        off += 3;
        if (t->name_len > BIO_NAME_MAX || off + t->name_len > len) {
            break;
        }
        memcpy(t->name, p + off, t->name_len);
        off += t->name_len;
        st.count++;
    }
    if (st.uv_retries > BIO_MAX_UV_RETRIES) {
        st.uv_retries = BIO_MAX_UV_RETRIES;
    }
}

static int bio_save(void) {
    uint8_t buf[3 + SFM_UID_LEN + BIO_MAX_TEMPLATES * (3 + BIO_NAME_MAX)];
    size_t off = 0;
    buf[off++] = BIO_STATE_VERSION;
    memcpy(buf + off, st.sensor_uid, SFM_UID_LEN);
    off += SFM_UID_LEN;
    buf[off++] = st.uv_retries;
    buf[off++] = st.count;
    for (uint8_t i = 0; i < st.count; i++) {
        buf[off++] = st.t[i].id >> 8;
        buf[off++] = st.t[i].id & 0xFF;
        buf[off++] = st.t[i].name_len;
        memcpy(buf + off, st.t[i].name, st.t[i].name_len);
        off += st.t[i].name_len;
    }
    file_t *ef = bio_file();
    if (ef == NULL) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    int ret = file_put_data(ef, CONST_BYTE_ARRAY(buf, (uint16_t)off));
    flash_commit();
    return ret;
}

/* ------------------------------------------------------------------- mode */

static void bio_update_mode(void) {
    bio_mode_t m;
    if (!sensor_present) {
        m = st.count > 0 ? BIO_MODE_LOCKED : BIO_MODE_BUTTON;
    }
    else if (st.count == 0) {
        m = BIO_MODE_UNBOUND;
    }
    else if (memcmp(st.sensor_uid, sensor_uid, SFM_UID_LEN) != 0) {
        m = BIO_MODE_LOCKED;
    }
    else {
        m = BIO_MODE_BOUND;
    }
    if (m != mode) {
        static const char *names[] = { "probing", "button", "unbound", "bound", "locked" };
        ESP_LOGI(TAG, "mode: %s", names[m]);
    }
    mode = m;
}

static void bio_wait_probe(void) {
    for (int i = 0; mode == BIO_MODE_PROBING && i < BIO_PROBE_WAIT_MS / 10; i++) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

bio_mode_t bio_mode(void) {
    return mode;
}

bool bio_sensor_present(void) {
    return sensor_present;
}

bool bio_is_bound(void) {
    return mode == BIO_MODE_BOUND;
}

static bool bio_owns(uint16_t id) {
    return id != 0 && bio_template_find(id) != NULL;
}

/* --------------------------------------------------------------- presence */

bool bio_requires_match(void) {
    bio_wait_probe();
    return mode == BIO_MODE_BOUND || mode == BIO_MODE_LOCKED || (mode == BIO_MODE_PROBING && st.count > 0);
}

bool bio_presence_denied(void) {
    bio_wait_probe();
    if (allow_button) {
        return false;
    }
    return mode == BIO_MODE_LOCKED || (mode == BIO_MODE_PROBING && st.count > 0);
}

bool bio_presence_forced(void) {
    return mode == BIO_MODE_BOUND || job_next != BIO_JOB_PRESENCE;
}

void bio_allow_button(bool allow) {
    allow_button = allow;
}

static bool bio_pulse_read(void) {
    if (pulse == 1) {
        pulse = 2;
        return true;
    }
    if (pulse == 2) {
        pulse = 0;
    }
    return false;
}

bool bio_button_read(bool raw) {
    bool button_ok = job_kind == BIO_JOB_PRESENCE || !job_active;
    switch (mode) {
        case BIO_MODE_BUTTON:
            return raw;
        case BIO_MODE_UNBOUND:
            return bio_pulse_read() || (button_ok && raw);
        case BIO_MODE_BOUND:
            return bio_pulse_read() || (allow_button && button_ok && raw);
        case BIO_MODE_PROBING:
            return st.count == 0 ? raw : (allow_button && raw);
        case BIO_MODE_LOCKED:
        default:
            return allow_button && raw;
    }
}

/* ---------------------------------------------------------------- bio task */

static void bio_ring_idle(void) {
    sfm_ring(SFM_RING_OFF, SFM_RING_OFF, BIO_RING_PERIOD_MS);
}

static void bio_ring_flash(uint8_t color) {
    sfm_ring(color, color, BIO_RING_PERIOD_MS);
    vTaskDelay(pdMS_TO_TICKS(BIO_RESULT_SHOW_MS));
}

/* Returns false if the job was stopped (wait finished elsewhere). */
static bool bio_job_begin(void) {
    job_busy = true;
    __sync_synchronize();
    if (!job_active) {
        job_busy = false;
        return false;
    }
    return true;
}

static void bio_job_end(void) {
    job_busy = false;
    __sync_synchronize();
}

static void bio_finish(bio_result_t res, bool success) {
    if (!job_active) {
        return;
    }
    job_result = res;
    job_active = false;
    if (success) {
        pulse = 1;
    }
    else {
        cancel_button = true;
    }
}

static void bio_run_presence(void) {
    while (job_active) {
        uint16_t uid = 0;
        if (!bio_job_begin()) {
            break;
        }
        uint8_t ret = sfm_match_1n(&uid);
        bio_job_end();
        if (!job_active) {
            break;
        }
        bool captured = ret == SFM_ACK_SUCCESS || ret == SFM_ACK_FAIL;
        if ((mode == BIO_MODE_UNBOUND && captured) || (ret == SFM_ACK_SUCCESS && bio_owns(uid))) {
            job_uid = uid;
            bio_finish(BIO_RES_OK, true);
            bio_ring_flash(SFM_RING_GREEN);
        }
        else if (captured) {
            /* Wrong finger: show it and keep waiting. Not counted as a UV failure. */
            bio_ring_flash(SFM_RING_RED);
            sfm_ring(SFM_RING_BLUE, SFM_RING_OFF, BIO_RING_PERIOD_MS);
        }
        else if (ret != SFM_ACK_TIMEOUT && ret != SFM_ACK_BREAK) {
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }
}

static void bio_run_verify(void) {
    while (job_active) {
        uint16_t uid = 0;
        if (!bio_job_begin()) {
            break;
        }
        uint8_t ret = sfm_match_1n(&uid);
        bio_job_end();
        if (!job_active) {
            break;
        }
        if (ret == SFM_ACK_SUCCESS && bio_owns(uid)) {
            job_uid = uid;
            bio_finish(BIO_RES_OK, true);
            bio_ring_flash(SFM_RING_GREEN);
        }
        else if (ret == SFM_ACK_SUCCESS || ret == SFM_ACK_FAIL) {
            bio_finish(BIO_RES_NO_MATCH, false);
            bio_ring_flash(SFM_RING_RED);
        }
        else if (ret != SFM_ACK_TIMEOUT && ret != SFM_ACK_BREAK) {
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }
}

static void bio_run_enroll(void) {
    uint16_t id_out = 0;
    if (!bio_job_begin()) {
        return;
    }
    uint8_t ret = sfm_enroll_step(enroll_step, enroll_id, &id_out);
    bio_job_end();
    if (!job_active) {
        return;
    }
    switch (ret) {
        case SFM_ACK_SUCCESS:
            job_uid = id_out;
            bio_finish(BIO_RES_OK, true);
            bio_ring_flash(SFM_RING_GREEN);
            return;
        case SFM_ACK_TIMEOUT:
            bio_finish(BIO_RES_TIMEOUT, false);
            break;
        case SFM_ACK_USER_EXIST:
            bio_finish(BIO_RES_EXISTS, false);
            break;
        case SFM_ACK_FULL:
            bio_finish(BIO_RES_FULL, false);
            break;
        case SFM_ACK_BREAK:
            bio_finish(BIO_RES_CANCELLED, false);
            break;
        case SFM_ERR_NO_RESPONSE:
        case SFM_ERR_BAD_FRAME:
        case SFM_ACK_HWERROR:
            bio_finish(BIO_RES_ERROR, false);
            break;
        default: // FAIL, IMGERROR, ALGORITHMFAIL, HOMOLOGYFAIL
            bio_finish(BIO_RES_POOR_QUALITY, false);
            break;
    }
    bio_ring_flash(SFM_RING_RED);
}

static void bio_probe(void) {
    sfm_config_t cfg = {
        .uart_num = BIO_UART_NUM,
        .tx_gpio = BIO_UART_TX_GPIO,
        .rx_gpio = BIO_UART_RX_GPIO,
        .en_gpio = BIO_EN_GPIO,
        .touch_gpio = BIO_TOUCH_GPIO,
    };
    if (sfm_init(&cfg) == 0 && sfm_get_unique_id(sensor_uid) == SFM_ACK_SUCCESS) {
        uint16_t users = 0;
        sfm_get_user_count(&users);
        sfm_set_deny_duplicates(true);
#ifdef BIO_FILM_DETECTION
        sfm_enable_film_detection();
#endif
        sensor_present = true;
        ESP_LOGI(TAG, "SFM-V1.7 found: uid %02x%02x%02x%02x%02x%02x%02x%02x, %u template(s) on sensor, %u owned",
                 sensor_uid[0], sensor_uid[1], sensor_uid[2], sensor_uid[3],
                 sensor_uid[4], sensor_uid[5], sensor_uid[6], sensor_uid[7], users, st.count);
        /* Self-test: cyan sweep so you can see the sensor is alive. */
        bio_ring_flash(SFM_RING_CYAN);
        bio_ring_idle();
    }
    bio_update_mode();
}

static void bio_task(void *arg) {
    (void)arg;
    bio_probe();
    while (true) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        if (!job_active) {
            continue;
        }
        sfm_ring(job_kind == BIO_JOB_ENROLL ? SFM_RING_PURPLE : SFM_RING_BLUE, SFM_RING_OFF, BIO_RING_PERIOD_MS);
        switch (job_kind) {
            case BIO_JOB_PRESENCE:
                bio_run_presence();
                break;
            case BIO_JOB_VERIFY:
                bio_run_verify();
                break;
            case BIO_JOB_ENROLL:
                bio_run_enroll();
                break;
        }
        bio_ring_idle();
    }
}

/* SDK signals, called from the core0 task: keep them short. */
static int bio_on_request(signal_code_t code, void *data) {
    (void)code;
    (void)data;
    pulse = 0;
    job_kind = job_next;
    job_result = BIO_RES_NONE;
    if (sensor_present && (mode == BIO_MODE_UNBOUND || mode == BIO_MODE_BOUND)) {
        job_active = true;
        xTaskNotifyGive(bio_task_handle);
    }
    return 0;
}

static int bio_on_done(signal_code_t code, void *data) {
    (void)data;
    if (!job_active) {
        return 0;
    }
    job_active = false;
    __sync_synchronize();
    if (code != SIGNAL_USER_PRESENCE_COMPLETED && job_result == BIO_RES_NONE) {
        job_result = code == SIGNAL_USER_PRESENCE_TIMEOUT ? BIO_RES_TIMEOUT : BIO_RES_CANCELLED;
    }
    if (job_busy) {
        sfm_abort();
    }
    return 0;
}

void bio_init(void) {
    bio_load();
    signal_add(SIGNAL_USER_PRESENCE_REQUEST, SIGNAL_FLAG_ERROR_CONTINUE, bio_on_request);
    signal_add(SIGNAL_USER_PRESENCE_COMPLETED, SIGNAL_FLAG_ERROR_CONTINUE, bio_on_done);
    signal_add(SIGNAL_USER_PRESENCE_CANCELLED, SIGNAL_FLAG_ERROR_CONTINUE, bio_on_done);
    signal_add(SIGNAL_USER_PRESENCE_TIMEOUT, SIGNAL_FLAG_ERROR_CONTINUE, bio_on_done);
    xTaskCreate(bio_task, "bio", 4096, NULL, tskIDLE_PRIORITY + 2, &bio_task_handle);
}

/* Run one job inside a forced button wait. Returns the wait_button result. */
static int bio_run_job(bio_job_t kind) {
    job_next = kind;
    job_result = BIO_RES_NONE;
    int ret = wait_button_pressed_timeout(0);
    job_next = BIO_JOB_PRESENCE;
    return ret;
}

/* ---------------------------------------------------------------------- UV */

bool bio_uv_configured(void) {
    return mode == BIO_MODE_BOUND && (!file_has_data(ef_pin) || keydev_unlocked);
}

uint8_t bio_uv_retries(void) {
    return st.uv_retries;
}

void bio_uv_retries_reset(void) {
    if (st.uv_retries != BIO_MAX_UV_RETRIES) {
        st.uv_retries = BIO_MAX_UV_RETRIES;
        bio_save();
    }
}

int bio_verify(void) {
    if (!bio_uv_configured()) {
        return CTAP2_ERR_PUAT_REQUIRED;
    }
    if (st.uv_retries == 0) {
        return CTAP2_ERR_UV_BLOCKED;
    }
    int ret = bio_run_job(BIO_JOB_VERIFY);
    if (ret == 0 && job_result == BIO_RES_OK) {
        bio_uv_retries_reset();
        return 0;
    }
    if (job_result == BIO_RES_NO_MATCH) {
        st.uv_retries--;
        bio_save();
        return st.uv_retries == 0 ? CTAP2_ERR_UV_BLOCKED : CTAP2_ERR_UV_INVALID;
    }
    if (ret == 1 || job_result == BIO_RES_TIMEOUT) {
        return CTAP2_ERR_USER_ACTION_TIMEOUT;
    }
    return CTAP2_ERR_KEEPALIVE_CANCEL;
}

/* -------------------------------------------------------------- enrolment */

static uint8_t bio_samples_remaining(void) {
    return enroll_step == 0 ? 0 : (uint8_t)(BIO_ENROLL_SAMPLES - (enroll_step - 1));
}

static int bio_enroll_capture(uint8_t *status, uint8_t *remaining) {
    int ret = bio_run_job(BIO_JOB_ENROLL);
    bio_result_t res = job_result;
    if (ret == 0 && res == BIO_RES_OK) {
        if (enroll_step < BIO_ENROLL_SAMPLES) {
            enroll_step++;
        }
        else {
            bio_template_t *t = &st.t[st.count];
            memset(t, 0, sizeof(*t));
            t->id = job_uid != 0 ? job_uid : enroll_id;
            if (st.count == 0) {
                memcpy(st.sensor_uid, sensor_uid, SFM_UID_LEN);
                st.uv_retries = BIO_MAX_UV_RETRIES;
            }
            st.count++;
            if (bio_save() != PICOKEYS_OK) {
                st.count--;
                enroll_step = 0;
                return CTAP2_ERR_PROCESSING;
            }
            enroll_step = 0;
            bio_update_mode();
        }
        *status = CTAP2_ENROLL_FEEDBACK_FP_GOOD;
        *remaining = bio_samples_remaining();
        return 0;
    }
    /* The SFM aborts the whole enrolment on any failed capture, so start over. */
    enroll_step = 1;
    *remaining = BIO_ENROLL_SAMPLES;
    switch (res) {
        case BIO_RES_EXISTS:
            *status = CTAP2_ENROLL_FEEDBACK_FP_EXISTS;
            return 0;
        case BIO_RES_POOR_QUALITY:
            *status = CTAP2_ENROLL_FEEDBACK_FP_POOR_QUALITY;
            return 0;
        case BIO_RES_FULL:
            enroll_step = 0;
            return CTAP2_ERR_FP_DATABASE_FULL;
        case BIO_RES_ERROR:
            enroll_step = 0;
            return CTAP2_ERR_PROCESSING;
        case BIO_RES_TIMEOUT:
            *status = CTAP2_ENROLL_FEEDBACK_NO_USER_ACTIVITY;
            return CTAP2_ERR_USER_ACTION_TIMEOUT;
        default:
            if (ret == 1) {
                return CTAP2_ERR_USER_ACTION_TIMEOUT;
            }
            enroll_step = 0;
            return CTAP2_ERR_KEEPALIVE_CANCEL;
    }
}

int bio_enroll_begin(uint16_t *template_id, uint8_t *status, uint8_t *remaining) {
    bio_wait_probe();
    if (!sensor_present || mode == BIO_MODE_LOCKED) {
        return CTAP2_ERR_UNSUPPORTED_OPTION;
    }
    if (st.count >= BIO_MAX_TEMPLATES) {
        return CTAP2_ERR_FP_DATABASE_FULL;
    }
    if (st.count == 0) {
        /* First finger: drop anything a previous owner left on the sensor. */
        sfm_delete_all();
    }
    uint8_t q1 = 0, q2 = 0;
    if (sfm_cmd(SFM_CMD_FREE_ID, 0, 0, 0, &q1, &q2, SFM_CMD_TIMEOUT_MS) != SFM_ACK_SUCCESS) {
        return CTAP2_ERR_FP_DATABASE_FULL;
    }
    enroll_id = (uint16_t)(q1 << 8 | q2);
    enroll_step = 1;
    *template_id = enroll_id;
    return bio_enroll_capture(status, remaining);
}

int bio_enroll_next(uint16_t template_id, uint8_t *status, uint8_t *remaining) {
    if (enroll_step == 0 || template_id != enroll_id) {
        return CTAP2_ERR_INVALID_OPTION;
    }
    return bio_enroll_capture(status, remaining);
}

void bio_enroll_cancel(void) {
    enroll_step = 0;
    enroll_id = 0;
    sfm_abort();
}

/* -------------------------------------------------------------- templates */

size_t bio_template_count(void) {
    return st.count;
}

const bio_template_t *bio_template_at(size_t index) {
    return index < st.count ? &st.t[index] : NULL;
}

const bio_template_t *bio_template_find(uint16_t id) {
    for (uint8_t i = 0; i < st.count; i++) {
        if (st.t[i].id == id) {
            return &st.t[i];
        }
    }
    return NULL;
}

int bio_template_set_name(uint16_t id, const uint8_t *name, size_t len) {
    bio_template_t *t = (bio_template_t *)bio_template_find(id);
    if (t == NULL) {
        return CTAP2_ERR_INVALID_OPTION;
    }
    if (len > BIO_NAME_MAX) {
        return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    memcpy(t->name, name, len);
    t->name_len = (uint8_t)len;
    return bio_save() == PICOKEYS_OK ? 0 : CTAP2_ERR_PROCESSING;
}

int bio_template_remove(uint16_t id) {
    uint8_t i = 0;
    for (; i < st.count && st.t[i].id != id; i++);
    if (i == st.count) {
        return CTAP2_ERR_INVALID_OPTION;
    }
    if (sensor_present) {
        uint8_t ret = sfm_delete_user(id);
        if (ret != SFM_ACK_SUCCESS && ret != SFM_ACK_NOUSER) {
            return CTAP2_ERR_PROCESSING;
        }
    }
    memmove(&st.t[i], &st.t[i + 1], (st.count - i - 1) * sizeof(bio_template_t));
    st.count--;
    if (st.count == 0) {
        memset(st.sensor_uid, 0, SFM_UID_LEN);
        st.uv_retries = BIO_MAX_UV_RETRIES;
    }
    int ret = bio_save();
    bio_update_mode();
    return ret == PICOKEYS_OK ? 0 : CTAP2_ERR_PROCESSING;
}

void bio_reset(void) {
    enroll_step = 0;
    if (sensor_present) {
        sfm_delete_all();
    }
    bio_state_clear();
    bio_save();
    bio_update_mode();
}
