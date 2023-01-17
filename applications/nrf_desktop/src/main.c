/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <app_event_manager.h>
#include <nrf_profiler.h>

#define MODULE main
#include <caf/events/module_state_event.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(MODULE);

uint16_t data_put_id;
uint16_t app_sent_id;
uint16_t ble_recv_id;

void profile_no_data_event(uint16_t evt_id)
{
	struct log_event_buf buf;

	nrf_profiler_log_start(&buf);
	nrf_profiler_log_send(&buf, evt_id);
}

void main(void)
{
	nrf_profiler_init();

	data_put_id = nrf_profiler_register_event_type("data_put", NULL, NULL, 0);
	ble_recv_id = nrf_profiler_register_event_type("ble_recv", NULL, NULL, 0);
	app_sent_id = nrf_profiler_register_event_type("app_sent", NULL, NULL, 0);

	if (app_event_manager_init()) {
		LOG_ERR("Application Event Manager not initialized");
	} else {
		module_set_state(MODULE_STATE_READY);
	}
}
