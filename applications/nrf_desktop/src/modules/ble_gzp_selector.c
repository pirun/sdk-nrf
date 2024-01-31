/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/sys/reboot.h>

#define MODULE ble_gzp_selector
#include <caf/events/module_state_event.h>
#include <caf/events/module_suspend_event.h>
#include "selector_event.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(MODULE, CONFIG_DESKTOP_BLE_GZP_SELECTOR_LOG_LEVEL);

static enum module_state ble_adv_state = MODULE_STATE_COUNT;
static enum module_state ble_state_state = MODULE_STATE_COUNT;
static enum module_state ble_bond_state = MODULE_STATE_COUNT;
static enum module_state gzp_state = MODULE_STATE_COUNT;

enum protocol {
	PROTOCOL_BLE,
	PROTOCOL_GZP,

	PROTOCOL_COUNT,
};

static enum protocol selected_protocol = PROTOCOL_COUNT;


static void suspend_req(const void *module_id)
{
	struct module_suspend_req_event *event = new_module_suspend_req_event();

	event->module_id = module_id;
	APP_EVENT_SUBMIT(event);
}

static void resume_req(const void *module_id)
{
	struct module_resume_req_event *event = new_module_resume_req_event();

	event->module_id = module_id;
	APP_EVENT_SUBMIT(event);
}

static void update_radio_protocol(void)
{
	static enum protocol used_protocol = PROTOCOL_COUNT;

	if ((ble_state_state == MODULE_STATE_COUNT) ||
	    (ble_adv_state == MODULE_STATE_COUNT) ||
	    (gzp_state == MODULE_STATE_COUNT)) {
		return;
	}

	/* Do not perform any operations before ble_bond module is ready. Bluetooth must be enabled
	 * to ensure proper load of Bluetooth settings from non-volatile memory.
	 * TODO: For now, ble_bond suspend is not yet supported, feature will be added later.
	 */
	if (ble_bond_state == MODULE_STATE_COUNT) {
		return;
	}

	if (selected_protocol == PROTOCOL_BLE) {
		if (gzp_state != MODULE_STATE_SUSPENDED) {
			suspend_req(MODULE_ID(gzp));
		} else if (ble_state_state != MODULE_STATE_READY) {
			resume_req(MODULE_ID(ble_state));
		} else if (ble_adv_state != MODULE_STATE_READY) {
			resume_req(MODULE_ID(ble_adv));
		 }
	} else if (selected_protocol == PROTOCOL_GZP) {
		if (ble_adv_state != MODULE_STATE_SUSPENDED) {
			suspend_req(MODULE_ID(ble_adv));
		} else if (ble_state_state != MODULE_STATE_SUSPENDED) {
			k_msleep(50);
			suspend_req(MODULE_ID(ble_state));
		} else if (gzp_state != MODULE_STATE_READY) {
			resume_req(MODULE_ID(gzp));
		}
	}

	if ((selected_protocol == PROTOCOL_BLE) &&
	    (gzp_state == MODULE_STATE_SUSPENDED) &&
	    (ble_state_state == MODULE_STATE_READY) &&
	    (ble_adv_state == MODULE_STATE_READY)) {
		used_protocol = PROTOCOL_BLE;
	} else if ((selected_protocol == PROTOCOL_GZP) &&
		   (ble_adv_state == MODULE_STATE_SUSPENDED) &&
		   (ble_state_state == MODULE_STATE_SUSPENDED) &&
		   (gzp_state == MODULE_STATE_READY)) {
		used_protocol = PROTOCOL_GZP;
	} else {
		used_protocol = PROTOCOL_COUNT;
	}
}

static bool handle_module_state_event(const struct module_state_event *event)
{
	if (event->module_id == MODULE_ID(ble_adv)) {
		ble_adv_state = event->state;
		update_radio_protocol();
	} else if (event->module_id == MODULE_ID(gzp)) {
		gzp_state = event->state;
		update_radio_protocol();
	} else if (event->module_id == MODULE_ID(ble_state)) {
		ble_state_state = event->state;
		update_radio_protocol();
	} else if (event->module_id == MODULE_ID(ble_bond)) {
		ble_bond_state = event->state;
		update_radio_protocol();
	}

	return false;
}

static bool handle_selector_event(const struct selector_event *event)
{
	if (event->selector_id != CONFIG_DESKTOP_BLE_GZP_SELECTOR_ID) {
		return false;
	}

	if (event->position == CONFIG_DESKTOP_BLE_GZP_SELECTOR_POS_BLE) {
		selected_protocol = PROTOCOL_BLE;
	} else if (event->position == CONFIG_DESKTOP_BLE_GZP_SELECTOR_POS_GZP) {
		selected_protocol = PROTOCOL_GZP;
	} else {
		LOG_WRN("Unhandled selector position");
		selected_protocol = PROTOCOL_COUNT;
	}

	update_radio_protocol();

	return false;
}

static bool app_event_handler(const struct app_event_header *aeh)
{
	if (is_module_state_event(aeh)) {
		return handle_module_state_event(cast_module_state_event(aeh));
	}

	if (is_selector_event(aeh)) {
		return handle_selector_event(cast_selector_event(aeh));
	}

	/* If event is unhandled, unsubscribe. */
	__ASSERT_NO_MSG(false);

	return false;
}

APP_EVENT_LISTENER(MODULE, app_event_handler);
APP_EVENT_SUBSCRIBE(MODULE, module_state_event);
APP_EVENT_SUBSCRIBE(MODULE, selector_event);
