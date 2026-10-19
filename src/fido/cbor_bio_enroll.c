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

/* authenticatorBioEnrollment (CTAP 2.1, 6.7) for the SFM-V1.7 sensor. */

#include "picokeys.h"
#include "fido.h"
#include "ctap.h"
#include "ctap2_cbor.h"
#include "hid/ctap_hid.h"
#include "apdu.h"
#include "bio.h"
#include <string.h>

#define BIO_MODALITY_FINGERPRINT    0x01
#define BIO_FINGERPRINT_KIND_TOUCH  0x01

#define BIO_SUB_ENROLL_BEGIN        0x01
#define BIO_SUB_ENROLL_NEXT         0x02
#define BIO_SUB_ENROLL_CANCEL       0x03
#define BIO_SUB_ENUMERATE           0x04
#define BIO_SUB_SET_NAME            0x05
#define BIO_SUB_REMOVE              0x06
#define BIO_SUB_SENSOR_INFO         0x07

#define BIO_AUTH_MSG_MAX            128

static bool bio_template_id_decode(const CborByteString *id, uint16_t *out) {
    if (!id->present || id->len != BIO_TEMPLATE_ID_LEN) {
        return false;
    }
    *out = (uint16_t)(id->data[0] << 8 | id->data[1]);
    return true;
}

int cbor_bio_enroll(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    uint64_t modality = 0, subcommand = 0, pinUvAuthProtocol = 0, timeout_ms = 0;
    CborByteString pinUvAuthParam = { 0 }, templateId = { 0 };
    CborCharString friendlyName = { 0 };
    const bool *getModality = NULL;
    const uint8_t *raw_subpara = NULL;
    size_t raw_subpara_len = 0, resp_size = 0;
    bool pinUvAuthProtocol_present = false;
    CborEncoder encoder, mapEncoder, arrayEncoder, mapEncoder2;

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(modality, 1);
        }
        else if (val_u == 0x02) {
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x03) {
            uint64_t subpara = 0;
            raw_subpara = cbor_value_get_next_byte(&_f1);
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_UINT(subpara, 2);
                if (subpara == 0x01) {
                    CBOR_FIELD_GET_BYTES(templateId, 2);
                }
                else if (subpara == 0x02) {
                    CBOR_FIELD_GET_TEXT(friendlyName, 2);
                }
                else if (subpara == 0x03) {
                    CBOR_FIELD_GET_UINT(timeout_ms, 2);
                }
                else {
                    CBOR_ADVANCE(2);
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
            raw_subpara_len = cbor_value_get_next_byte(&_f1) - raw_subpara;
        }
        else if (val_u == 0x04) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
            pinUvAuthProtocol_present = true;
        }
        else if (val_u == 0x05) {
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else if (val_u == 0x06) {
            CBOR_FIELD_GET_BOOL(getModality, 1);
        }
        else {
            CBOR_ADVANCE(1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);
    (void)timeout_ms; // the sensor has a fixed ~8 s capture timeout

    if (!bio_sensor_present() || bio_mode() == BIO_MODE_LOCKED) {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    }

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);

    if (getModality == ptrue) {
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_MODALITY_FINGERPRINT));
        goto done;
    }
    if (modality == 0 || subcommand == 0) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }
    if (modality != BIO_MODALITY_FINGERPRINT) {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    }

    if (subcommand == BIO_SUB_SENSOR_INFO) {
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 4));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_MODALITY_FINGERPRINT));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_FINGERPRINT_KIND_TOUCH));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_ENROLL_SAMPLES));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_NAME_MAX));
        goto done;
    }

    /* Everything else needs a pinUvAuthToken with the "be" permission over
       modality || subCommand || subCommandParams. */
    if (pinUvAuthParam.present == false) {
        CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
    }
    if (pinUvAuthProtocol_present == false) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }
    if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }
    uint8_t auth_msg[BIO_AUTH_MSG_MAX];
    if (raw_subpara_len + 2 > sizeof(auth_msg)) {
        CBOR_ERROR(CTAP2_ERR_LIMIT_EXCEEDED);
    }
    auth_msg[0] = (uint8_t)modality;
    auth_msg[1] = (uint8_t)subcommand;
    if (raw_subpara_len > 0) {
        memcpy(auth_msg + 2, raw_subpara, raw_subpara_len);
    }
    if (verify((uint8_t)pinUvAuthProtocol, paut.data, auth_msg, (uint16_t)(raw_subpara_len + 2), pinUvAuthParam.data) != CborNoError) {
        CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
    }
    if (!(paut.permissions & CTAP_PERMISSION_BE)) {
        CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
    }

    if (subcommand == BIO_SUB_ENROLL_BEGIN || subcommand == BIO_SUB_ENROLL_NEXT) {
        uint16_t id = 0;
        uint8_t status = 0, remaining = 0;
        int ret;
        if (subcommand == BIO_SUB_ENROLL_BEGIN) {
            ret = bio_enroll_begin(&id, &status, &remaining);
        }
        else {
            if (!bio_template_id_decode(&templateId, &id)) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }
            ret = bio_enroll_next(id, &status, &remaining);
        }
        if (ret != 0) {
            CBOR_ERROR(ret);
        }
        uint8_t id_bytes[BIO_TEMPLATE_ID_LEN] = { id >> 8, id & 0xFF };
        bool begin = subcommand == BIO_SUB_ENROLL_BEGIN;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, begin ? 3 : 2));
        if (begin) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, id_bytes, sizeof(id_bytes)));
        }
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, status));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, remaining));
    }
    else if (subcommand == BIO_SUB_ENROLL_CANCEL) {
        bio_enroll_cancel();
        goto err; // empty response
    }
    else if (subcommand == BIO_SUB_ENUMERATE) {
        size_t count = bio_template_count();
        if (count == 0) {
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
        CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, count));
        for (size_t i = 0; i < count; i++) {
            const bio_template_t *t = bio_template_at(i);
            uint8_t id_bytes[BIO_TEMPLATE_ID_LEN] = { t->id >> 8, t->id & 0xFF };
            CBOR_CHECK(cbor_encoder_create_map(&arrayEncoder, &mapEncoder2, t->name_len > 0 ? 2 : 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder2, 0x01));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, id_bytes, sizeof(id_bytes)));
            if (t->name_len > 0) {
                CBOR_CHECK(cbor_encode_uint(&mapEncoder2, 0x02));
                CBOR_CHECK(cbor_encode_text_string(&mapEncoder2, t->name, t->name_len));
            }
            CBOR_CHECK(cbor_encoder_close_container(&arrayEncoder, &mapEncoder2));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));
    }
    else if (subcommand == BIO_SUB_SET_NAME || subcommand == BIO_SUB_REMOVE) {
        uint16_t id = 0;
        if (!bio_template_id_decode(&templateId, &id)) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        int ret;
        if (subcommand == BIO_SUB_SET_NAME) {
            if (friendlyName.present == false) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }
            ret = bio_template_set_name(id, (const uint8_t *)friendlyName.data, friendlyName.len);
        }
        else {
            ret = bio_template_remove(id);
        }
        if (ret != 0) {
            CBOR_ERROR(ret);
        }
        goto err; // empty response
    }
    else {
        CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
    }

done:
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(templateId);
    CBOR_FREE_BYTE_STRING(friendlyName);
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}
