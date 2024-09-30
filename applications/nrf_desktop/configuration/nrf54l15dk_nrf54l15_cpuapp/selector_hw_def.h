/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "selector_hw.h"

/* This configuration file is included only once from selector_hw module
 * and holds information about pins used by module.
 */

/* This structure enforces the header file is included only once in the build.
 * Violating this requirement triggers a multiple definition error at link time.
 */
const struct {} selector_hw_def_include_once;

static const struct gpio_pin pins0[] = {
	{ .port = 0, .pin = 2 },
	{ .port = 0, .pin = 3 },
};
static const struct selector_config config0 = {
#if defined(CONFIG_DESKTOP_BLE_GZP_SELECTOR_ENABLE)
	.id = CONFIG_DESKTOP_BLE_GZP_SELECTOR_ID,
#else
	.id = CONFIG_DESKTOP_BLE_ESB_SELECTOR_ID,
#endif
	.pins = pins0,
	.pins_size = ARRAY_SIZE(pins0)
};

static const struct selector_config *selector_config[] = {
	&config0,
};
