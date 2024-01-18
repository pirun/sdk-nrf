/*
 * Copyright (c) 2019 - 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <assert.h>
#include <limits.h>

#include <zephyr/kernel.h>
#include <zephyr/types.h>
#include <string.h>

#include <gzll_glue.h>
#include <gzp.h>

#include "hid_event.h"

#define MODULE gzp
#include <caf/events/module_state_event.h>
#include <caf/events/click_event.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(MODULE, CONFIG_DESKTOP_GZP_LOG_LEVEL);

#define NRF_GZLLDE_RXPERIOD_DIV_2	504 /* RXPERIOD/2 on LU1 = timeslot period on nRF5x. */
#define MAX_TX_ATTEMPTS			400
#define SYNC_LIFETIME			1000
#define LEGACY_UNENCRYPTED_MOUSE_PIPE	2
/* Interval between subsequent keep alives will be up to twice as big as this define's value. */
#define KEEP_ALIVE_TIMEOUT_MS		(100 / 2)

#define MAX_HID_REPORT_LENGTH		(MAX(REPORT_SIZE_MOUSE + 1, REPORT_SIZE_KEYBOARD_KEYS + 1))
#define ON_START_CLICK_UPTIME_MAX	(6 * MSEC_PER_SEC)

/* Gazell is currently supported only for HID peripherals that act as Gazell Devices. */
BUILD_ASSERT(IS_ENABLED(CONFIG_DESKTOP_ROLE_HID_PERIPHERAL) &&
	     IS_ENABLED(CONFIG_GAZELL_PAIRING_DEVICE));

enum state {
	STATE_DISABLED,
	STATE_GET_SYSTEM_ADDRESS,
	STATE_GET_HOST_ID,
	STATE_ACTIVE,
	STATE_ERROR,
};

struct sent_hid_report {
	uint8_t packet_cnt;
	uint8_t id;
	bool keep_alive;
	bool error;
};

struct sent_hid_report sent_hid_report = {
	.packet_cnt = 0,
	.id = REPORT_ID_COUNT,
	.keep_alive = false,
	.error = false
};
static enum state state;
static struct k_work_delayable periodic_work;

/* Add an extra byte for HID report ID. */
static uint8_t mouse_data[REPORT_SIZE_MOUSE + 1] = {REPORT_ID_MOUSE};
static uint8_t keyboard_data[REPORT_SIZE_KEYBOARD_KEYS + 1] = {REPORT_ID_KEYBOARD_KEYS};

static uint8_t queued_report_id = REPORT_ID_COUNT;
static bool keep_alive_needed;
static bool pairing_erase_pending;

static void periodic_work_fn(struct k_work *work);
static void gzp_encrypted_sent_cb(bool success, void *context);


static void broadcast_hid_subscriber(bool enable)
{
	struct hid_report_subscriber_event *event = new_hid_report_subscriber_event();

	event->subscriber = &state;
	event->params.pipeline_size = 1;
	event->params.priority = CONFIG_DESKTOP_GZP_SUBSCRIBER_PRIORITY;
	event->params.report_max = 1;
	event->connected = enable;

	APP_EVENT_SUBMIT(event);
}

static void broadcast_hid_subscription(bool enable)
{
	if (IS_ENABLED(CONFIG_DESKTOP_HID_REPORT_MOUSE_SUPPORT)) {
		struct hid_report_subscription_event *event = new_hid_report_subscription_event();

		event->report_id  = REPORT_ID_MOUSE;
		event->enabled    = enable;
		event->subscriber = &state;

		APP_EVENT_SUBMIT(event);
	}

	if (IS_ENABLED(CONFIG_DESKTOP_HID_REPORT_KEYBOARD_SUPPORT)) {
		struct hid_report_subscription_event *event = new_hid_report_subscription_event();

		event->report_id  = REPORT_ID_KEYBOARD_KEYS;
		event->enabled    = enable;
		event->subscriber = &state;

		APP_EVENT_SUBMIT(event);
	}
}

static void broadcast_hid_report_sent(uint8_t report_id, bool error)
{
	__ASSERT_NO_MSG(report_id != REPORT_ID_COUNT);

	struct hid_report_sent_event *event = new_hid_report_sent_event();

	event->report_id = report_id;
	event->subscriber = &state;
	event->error = error;

	APP_EVENT_SUBMIT(event);
}

static void update_hid_report_data(const uint8_t *data, size_t size)
{
	uint8_t report_id = data[0];

	switch (report_id) {
	case REPORT_ID_MOUSE:
		__ASSERT_NO_MSG(sizeof(mouse_data) == size);
		memcpy(mouse_data, data, size);
		break;

	case REPORT_ID_KEYBOARD_KEYS:
		__ASSERT_NO_MSG(sizeof(keyboard_data) == size);
		memcpy(keyboard_data, data, size);
		break;

	default:
		LOG_ERR("Unhandled report %" PRIu8, report_id);
		/* Should not happen. */
		__ASSERT_NO_MSG(false);
		break;
	}
}

static void clear_hid_report_data(uint8_t report_id, bool relative_only)
{
	switch (report_id) {
	case REPORT_ID_MOUSE:
		if (relative_only) {
			/* Clear mouse wheel. */
			mouse_data[2] = 0x00;
			/* Clear mouse motion. */
			memset(&mouse_data[3], 0x00, 3);
		} else {
			/* Leave only report ID. */
			memset(&mouse_data[1], 0x00, sizeof(mouse_data) - 1);
		}
		break;

	case REPORT_ID_KEYBOARD_KEYS:
		if (relative_only) {
			/* Nothing to do. */
		} else {
			/* Leave only report ID. */
			memset(&keyboard_data[1], 0x00, sizeof(keyboard_data) - 1);
		}
		break;

	default:
		LOG_ERR("Unhandled report %" PRIu8, report_id);
		/* Should not happen. */
		__ASSERT_NO_MSG(false);
		break;
	}
}

static bool hid_report_update_needed(uint8_t report_id)
{
	uint8_t zeros[MAX_HID_REPORT_LENGTH];
	bool update_needed = false;

	memset(zeros, 0x00, sizeof(zeros));

	switch (report_id) {
	case REPORT_ID_MOUSE:
		__ASSERT_NO_MSG((sizeof(mouse_data) - 1) <= sizeof(zeros));
		/* Omit HID report ID in the comparison. */
		update_needed = (memcmp(zeros, &mouse_data[1], sizeof(mouse_data) - 1) != 0);
		break;

	case REPORT_ID_KEYBOARD_KEYS:
		__ASSERT_NO_MSG((sizeof(keyboard_data) - 1) <= sizeof(zeros));
		/* Omit HID report ID in the comparison. */
		update_needed = (memcmp(zeros, &keyboard_data[1], sizeof(keyboard_data) - 1) != 0);
		break;

	default:
		LOG_ERR("Unhandled report %" PRIu8, report_id);
		/* Should not happen. */
		__ASSERT_NO_MSG(false);
		break;
	}

	return update_needed;
}

static void update_hid_subscription(bool enable)
{
	static bool enabled;

	if (enabled == enable) {
		/* No action needed. */
		return;
	}

	if (enable) {
		broadcast_hid_subscriber(true);
		broadcast_hid_subscription(true);
	} else {
		/* Clear queued HID report. */
		if (queued_report_id != REPORT_ID_COUNT) {
			broadcast_hid_report_sent(queued_report_id, true);
			queued_report_id = REPORT_ID_COUNT;
		}

		broadcast_hid_subscription(false);
		broadcast_hid_subscriber(false);

		keep_alive_needed = false;

		/* Clear remembered report data. */
		if (IS_ENABLED(CONFIG_DESKTOP_HID_REPORT_MOUSE_SUPPORT)) {
			clear_hid_report_data(REPORT_ID_MOUSE, false);
		}
		if (IS_ENABLED(CONFIG_DESKTOP_HID_REPORT_MOUSE_SUPPORT)) {
			clear_hid_report_data(REPORT_ID_KEYBOARD_KEYS, false);
		}
	}

	enabled = enable;
}

static void finalize_hid_report_sent(struct sent_hid_report *report)
{
	__ASSERT_NO_MSG(report->packet_cnt == 0);

	if (!report->keep_alive) {
		broadcast_hid_report_sent(report->id, report->error);
		/* Clear all data on error to align with HID state's approach. */
		clear_hid_report_data(report->id, !report->error);
	}

	/* Clear internal state. */
	report->id = REPORT_ID_COUNT;
	report->error = false;
	report->keep_alive = false;
}

static bool send_mouse_motion_legacy(const uint8_t *data, size_t size)
{
	BUILD_ASSERT(NRF_GZLL_CONST_MAX_PAYLOAD_LENGTH >= 4, "GZLL payload length too small");
	uint8_t payload[4];

	/* Set expected report ID. */
	payload[0] = 2;

	/* Set motion data. */
	memcpy(&payload[1], &data[3], 3);

	/* Legacy implementation used not to encrypt mouse data. */
	return nrf_gzll_add_packet_to_tx_fifo(LEGACY_UNENCRYPTED_MOUSE_PIPE,
					      payload, sizeof(payload));
}

static bool send_mouse_buttons_wheel_legacy(const uint8_t *data, size_t size)
{
	BUILD_ASSERT(NRF_GZLL_CONST_MAX_PAYLOAD_LENGTH >= 4, "GZLL payload length too small");
	uint8_t payload[4];

	/* Set expected report ID. */
	payload[0] = 1;
	/* Set buttons. */
	payload[1] = data[1];
	/* Set wheel. */
	payload[2] = data[2];
	/* Set AC pan. */
	payload[3] = 0;

	/* Legacy implementation used not to encrypt mouse data. */
	return nrf_gzll_add_packet_to_tx_fifo(LEGACY_UNENCRYPTED_MOUSE_PIPE,
					      payload, sizeof(payload));
}

static bool send_hid_report_legacy_mouse(const uint8_t *data, size_t size, uint8_t *packet_cnt)
{
	uint8_t report_id = data[0];

	__ASSERT_NO_MSG(report_id == REPORT_ID_MOUSE);
	__ASSERT_NO_MSG(size == 6);

	/* Report is sent as 2 packets instead of 1. */
	*packet_cnt = 2;

	if (!send_mouse_buttons_wheel_legacy(data, size)) {
		LOG_ERR("send_mouse_buttons_wheel_legacy failed");
		/* No packets were sent. */
		*packet_cnt = 0;
		return false;
	}

	if (!send_mouse_motion_legacy(data, size)) {
		LOG_ERR("send_mouse_motion_legacy failed");
		/* Only one of the packets was sent. */
		*packet_cnt = 1;
		return false;
	}

	return true;
}

static void send_hid_report_legacy_keyboard_keys(const uint8_t *data, size_t size)
{
	BUILD_ASSERT(NRF_GZLL_CONST_MAX_PAYLOAD_LENGTH >= 8, "GZLL payload length too small");
	/* gzp_crypt_data_send_async requires buffer to be valid until data is sent. */
	static uint8_t payload[8];
	uint8_t report_id = data[0];

	__ASSERT_NO_MSG(report_id == REPORT_ID_KEYBOARD_KEYS);
	__ASSERT_NO_MSG(size == 9);

	/* Legacy HID report format was the same, but did not include report ID. */
	memcpy(&payload[0], &data[1], sizeof(payload));

	/* Send encrypted HID data. */
	gzp_crypt_data_send_async(payload, sizeof(payload), gzp_encrypted_sent_cb, NULL);
}

static bool send_hid_report_legacy(const uint8_t *data, size_t size, uint8_t *packet_cnt)
{
	bool success = true;
	uint8_t report_id = data[0];

	switch (report_id) {
	case REPORT_ID_MOUSE:
		success = send_hid_report_legacy_mouse(data, size, packet_cnt);
		break;

	case REPORT_ID_KEYBOARD_KEYS:
		send_hid_report_legacy_keyboard_keys(data, size);
		break;

	default:
		LOG_ERR("Unhandled report %" PRIu8, report_id);
		/* Should not happen. */
		__ASSERT_NO_MSG(false);
		break;
	}

	return success;
}

static void send_hid_report_new(const uint8_t *data, size_t size, uint8_t *packet_cnt)
{
	/* gzp_crypt_data_send_async requires buffer to be valid until data is sent. */
	static uint8_t payload[MAX_HID_REPORT_LENGTH];

	__ASSERT_NO_MSG(sizeof(payload) >= size);
	memcpy(payload, data, size);

	/* Send encrypted HID data. */
	gzp_crypt_data_send_async(payload, size, gzp_encrypted_sent_cb, NULL);
}

static void send_hid_report(const uint8_t *data, size_t size, bool keep_alive)
{
	__ASSERT_NO_MSG(data && (size > 0));

	uint8_t report_id = data[0];
	struct sent_hid_report *report = &sent_hid_report;

	__ASSERT_NO_MSG(report->packet_cnt == 0);
	__ASSERT_NO_MSG((report->id == REPORT_ID_COUNT) && !report->keep_alive && !report->error);

	/* Packet counter needs to be increased further if a HID report is sent as multiple
	 * Gazell packets.
	 */
	report->packet_cnt = 1;
	report->keep_alive = keep_alive;
	report->id = report_id;

	bool success;

	if (IS_ENABLED(CONFIG_DESKTOP_GZP_LEGACY_HID_REPORT_MAP)) {
		success = send_hid_report_legacy(data, size, &report->packet_cnt);
	} else {
		send_hid_report_new(data, size, &report->packet_cnt);
	}

	if (!success) {
		/* Instantly propagate information about Gazell transmission error only in case
		 * there are no packets queued to be sent. Otherwise, the information will be
		 * propagated as soon as the queued packets are sent.
		 */
		report->error = !success;
		if (report->packet_cnt == 0) {
			finalize_hid_report_sent(report);
		}

		if (keep_alive) {
			LOG_ERR("Failed to send keep alive");
		} else {
			LOG_ERR("Failed to send HID report (ID: %" PRIu8, report->id);
		}
	}
}

static void send_hid_report_buffered(uint8_t report_id, bool keep_alive)
{
	const uint8_t *data;
	size_t size;

	switch (report_id) {
	case REPORT_ID_MOUSE:
		data = mouse_data;
		size = sizeof(mouse_data);
		break;

	case REPORT_ID_KEYBOARD_KEYS:
		data = keyboard_data;
		size = sizeof(keyboard_data);
		break;

	default:
		LOG_ERR("Unhandled report %" PRIu8, report_id);
		/* Should not happen. */
		__ASSERT_NO_MSG(false);
		return;
	}

	send_hid_report(data, size, keep_alive);
}

static void gzp_id_req_cb(enum gzp_id_req_res result, void *context)
{
	__ASSERT_NO_MSG(!k_is_in_isr());
	__ASSERT_NO_MSG(!k_is_preempt_thread());

	__ASSERT_NO_MSG(state == STATE_GET_HOST_ID);

	if (pairing_erase_pending) {
		(void)k_work_reschedule(&periodic_work, K_NO_WAIT);
		return;
	}

	if (result == GZP_ID_RESP_GRANTED) {
		LOG_INF("Host ID request was successful");
		state = STATE_ACTIVE;
		update_hid_subscription(true);
		(void)k_work_reschedule(&periodic_work, K_MSEC(KEEP_ALIVE_TIMEOUT_MS));
	} else {
		/* Retry after some time. */
		(void)k_work_reschedule(&periodic_work, K_MSEC(500));
	}
}

static void gzp_address_req_cb(bool result, void *context)
{
	__ASSERT_NO_MSG(!k_is_in_isr());
	__ASSERT_NO_MSG(!k_is_preempt_thread());

	__ASSERT_NO_MSG(state == STATE_GET_SYSTEM_ADDRESS);

	if (pairing_erase_pending) {
		(void)k_work_reschedule(&periodic_work, K_NO_WAIT);
		return;
	}

	if (result) {
		LOG_INF("Address request was successful");
		state = STATE_GET_HOST_ID;
		(void)k_work_reschedule(&periodic_work, K_NO_WAIT);
	} else {
		/* Retry after some time. */
		(void)k_work_reschedule(&periodic_work, K_MSEC(500));
	}
}

static void sent_cb(bool success)
{
	__ASSERT_NO_MSG(!k_is_in_isr());
	__ASSERT_NO_MSG(!k_is_preempt_thread());

	struct sent_hid_report *report = &sent_hid_report;

	report->error = (report->error || !success);
	__ASSERT_NO_MSG(report->packet_cnt > 0);
	report->packet_cnt--;

	if (report->packet_cnt == 0) {
		if (report->error) {
			if (report->keep_alive) {
				LOG_ERR("Keep alive transmission failed");
			} else {
				LOG_ERR("sent_cb reported failure for report ID: %" PRIu8,
					report->id);
			}
		}

		finalize_hid_report_sent(report);
		keep_alive_needed = false;
		/* Send subsequent HID report as quickly as possible. */
		if (queued_report_id != REPORT_ID_COUNT) {
			send_hid_report_buffered(queued_report_id, false);
			queued_report_id = REPORT_ID_COUNT;
		}

		if (pairing_erase_pending) {
			(void)k_work_reschedule(&periodic_work, K_NO_WAIT);
		}
	}
}

static void gzp_encrypted_sent_cb(bool success, void *context)
{
	ARG_UNUSED(context);

	sent_cb(success);
}

static void gzp_unencrypted_sent_cb(bool success, uint32_t pipe,
				    const nrf_gzll_device_tx_info_t *tx_info)
{
	ARG_UNUSED(tx_info);

	__ASSERT_NO_MSG(!k_is_in_isr());
	__ASSERT_NO_MSG(!k_is_preempt_thread());

	/* The callback is used only for unencrypted data. */
	if (pipe == LEGACY_UNENCRYPTED_MOUSE_PIPE) {
		sent_cb(success);
	}
}

static void keep_alive_send_dummy_report(void)
{
	/* A Gazell nRF Desktop Device may be either HID mouse or HID keyboard, but not both. */
	BUILD_ASSERT(IS_ENABLED(CONFIG_DESKTOP_HID_REPORT_MOUSE_SUPPORT) !=
		     IS_ENABLED(CONFIG_DESKTOP_HID_REPORT_KEYBOARD_SUPPORT));

	uint8_t report_id = REPORT_ID_MOUSE;

	if (IS_ENABLED(CONFIG_DESKTOP_HID_REPORT_KEYBOARD_SUPPORT)) {
		report_id = REPORT_ID_KEYBOARD_KEYS;
	}

	send_hid_report_buffered(report_id, true);
}

static void keep_alive(void)
{
	if (sent_hid_report.packet_cnt > 0) {
		/* Cannot send at this point, the work will rerun later. */
	} else if (keep_alive_needed) {
		keep_alive_send_dummy_report();
	}

	keep_alive_needed = (hid_report_update_needed(REPORT_ID_MOUSE) ||
			     hid_report_update_needed(REPORT_ID_KEYBOARD_KEYS));

	(void)k_work_reschedule(&periodic_work, K_MSEC(KEEP_ALIVE_TIMEOUT_MS));
}

static void gazell_pairing_erase(void)
{
	__ASSERT_NO_MSG(sent_hid_report.packet_cnt == 0);

	gzp_erase_pairing_data();

	if (gzp_get_pairing_status() == -2) {
		LOG_INF("Erased Gazell pairing data");
		state = STATE_GET_SYSTEM_ADDRESS;
	} else {
		LOG_ERR("Failed to erase Gazell pairing data");
		state = STATE_ERROR;
	}
}

static void periodic_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	__ASSERT_NO_MSG(!k_is_in_isr());
	__ASSERT_NO_MSG(!k_is_preempt_thread());

	if (pairing_erase_pending) {
		gazell_pairing_erase();
		pairing_erase_pending = false;

		if (state == STATE_ERROR) {
			return;
		}
	}

	if (state == STATE_ACTIVE) {
		keep_alive();
	} else if (state == STATE_GET_SYSTEM_ADDRESS) {
		gzp_address_req_send_async(gzp_address_req_cb, NULL);
	} else if (state == STATE_GET_HOST_ID) {
		gzp_id_req_send_async(gzp_id_req_cb, NULL);
	}
}

static bool gazell_initial_configuration(void)
{
	if (!gzll_glue_init()) {
		LOG_ERR("gzll_glue_init failed");
		return false;
	}

	if (!nrf_gzll_init(NRF_GZLL_MODE_DEVICE)) {
		LOG_ERR("nrf_gzll_init failed");
		return false;
	}

	nrf_gzll_set_max_tx_attempts(MAX_TX_ATTEMPTS);

	if (!nrf_gzll_set_device_channel_selection_policy(
		NRF_GZLL_DEVICE_CHANNEL_SELECTION_POLICY_USE_SUCCESSFUL)) {
		LOG_ERR("nrf_gzll_set_device_channel_selection_policy failed");
		return false;
	};

	if (!nrf_gzll_set_timeslot_period(NRF_GZLLDE_RXPERIOD_DIV_2)) {
		LOG_ERR("nrf_gzll_set_timeslot_period failed");
		return false;
	}

	if (!nrf_gzll_set_sync_lifetime(SYNC_LIFETIME)) {
		LOG_ERR("nrf_gzll_set_sync_lifetime failed");
		return false;
	}

	gzp_tx_result_callback_register(gzp_unencrypted_sent_cb);

	/* Initialize the Gazell Pairing Library */
	gzp_init();

	return true;
}

static bool gazell_state_update(bool enable)
{
	bool success = true;

	if (enable) {
		success = nrf_gzll_enable();
		if (!success) {
			LOG_ERR("nrf_gzll_enable failed");
		}
	} else {
		nrf_gzll_disable();
	}

	return success;
}

static int module_init(void)
{
	k_work_init_delayable(&periodic_work, periodic_work_fn);

	if (!gazell_initial_configuration()) {
		return -EIO;
	}

	if (pairing_erase_pending) {
		periodic_work_fn(NULL);
		return 0;
	}

	if (pairing_erase_pending) {
		periodic_work_fn(NULL);
		return 0;
	}

	state = gazell_get_pairing_module_state();

	int res = 0;

	switch (state) {
	case STATE_GET_HOST_ID:
	case STATE_GET_SYSTEM_ADDRESS:
		/* The work finalizes initialization. */
		(void)k_work_reschedule(&periodic_work, K_NO_WAIT);
		break;

	case STATE_ACTIVE:
		update_hid_subscription(true);
		(void)k_work_reschedule(&periodic_work, K_MSEC(KEEP_ALIVE_TIMEOUT_MS));
		break;

	case STATE_ERROR:
		/* Propagate information about an error. */
		res = -EIO;
		break;

	default:
		/* Should not happen. */
		__ASSERT_NO_MSG(false);
		break;
	}

	return res;
}

static bool hid_report_event_handler(const struct hid_report_event *event)
{
	__ASSERT_NO_MSG(!k_is_in_isr());
	__ASSERT_NO_MSG(!k_is_preempt_thread());

	uint8_t report_id = event->dyndata.data[0];

	if (&state != event->subscriber) {
		/* It's not us */
		return false;
	}

	if ((state != STATE_ACTIVE) || pairing_erase_pending) {
		/* Gazell is not active, report error. */
		broadcast_hid_report_sent(report_id, true);
		return false;
	}

	__ASSERT_NO_MSG((sent_hid_report.packet_cnt == 0) || (sent_hid_report.keep_alive));

	/* Buffer HID report internally. */
	update_hid_report_data(event->dyndata.data, event->dyndata.size);

	if (sent_hid_report.packet_cnt == 0) {
		send_hid_report_buffered(report_id, false);
	} else {
		queued_report_id = report_id;
	}

	return false;
}

static bool module_state_event_handler(const struct module_state_event *event)
{
	if (check_state(event, MODULE_ID(settings_loader), MODULE_STATE_READY) &&
	    (state == STATE_DISABLED)) {
		int err = module_init();

		if (err) {
			module_set_state(MODULE_STATE_ERROR);
		} else {
			module_set_state(MODULE_STATE_READY);
		}
	}

	return false;
}

static bool click_event_handler(const struct click_event *event)
{
	if (state == STATE_ERROR) {
		/* Ignore event. */
		return false;
	}

	if (event->key_id != CONFIG_DESKTOP_GZP_PAIRING_DATA_ERASE_CLICK_KEY_ID) {
		return false;
	}

	if (event->click != CLICK_LONG) {
		return false;
	}

	if (IS_ENABLED(CONFIG_DESKTOP_GZP_PAIRING_DATA_ERASE_CLICK_ON_BOOT_ONLY) &&
	    (k_uptime_get() > ON_START_CLICK_UPTIME_MAX)) {
		LOG_INF("Pairing data erase button pressed too late");
		return false;
	}

	update_hid_subscription(false);
	pairing_erase_pending = true;

	if ((state == STATE_ACTIVE) && (sent_hid_report.packet_cnt == 0)) {
		/* Finalize pairing data erase. */
		periodic_work_fn(NULL);
	} else if (state == STATE_ACTIVE) {
		/* Make sure that work would not be triggered before Gazell transmission is done. */
		(void)k_work_cancel_delayable(&periodic_work);
	} else {
		/* Pairing data will be erased on system address (or Host ID) get retry or during
		 * module's initialization.
		 */
	}

	return false;
}

static bool event_handler(const struct app_event_header *aeh)
{
	if (is_hid_report_event(aeh)) {
		return hid_report_event_handler(cast_hid_report_event(aeh));
	}

	if (is_module_state_event(aeh)) {
		return module_state_event_handler(cast_module_state_event(aeh));
	}

	if (IS_ENABLED(CONFIG_DESKTOP_GZP_PAIRING_DATA_ERASE_CLICK) && is_click_event(aeh)) {
		return click_event_handler(cast_click_event(aeh));
	}

	/* If event is unhandled, unsubscribe. */
	__ASSERT_NO_MSG(false);

	return false;
}

APP_EVENT_LISTENER(MODULE, event_handler);
APP_EVENT_SUBSCRIBE(MODULE, hid_report_event);
APP_EVENT_SUBSCRIBE(MODULE, module_state_event);
#ifdef CONFIG_DESKTOP_GZP_PAIRING_DATA_ERASE_CLICK
APP_EVENT_SUBSCRIBE(MODULE, click_event);
#endif /* CONFIG_DESKTOP_GZP_PAIRING_DATA_ERASE_CLICK */
