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

/* Overrides of the weak pico-keys-sdk hooks. This is the only place where the
 * SDK hands control to the fingerprint code. */

#include "picokeys.h"
#include "button.h"
#include "bio.h"
#include "driver/gpio.h"

int picokey_init(void) {
    bio_init();
    return 0;
}

bool picokey_button_read(void) {
    return bio_button_read(gpio_get_level(BOOT_PIN) == 0);
}
