/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <app_event_manager.h>

#define MODULE main
#include <caf/events/module_state_event.h>

#include <zephyr/logging/log.h>
#include "retained.h"
LOG_MODULE_REGISTER(MODULE);


int main(void)
{
	retained_validate();
	retained.boots += 1;
	retained_update();

	if (app_event_manager_init()) {
		LOG_ERR("Application Event Manager not initialized");
	} else {
		module_set_state(MODULE_STATE_READY);
	}
	return 0;
}
