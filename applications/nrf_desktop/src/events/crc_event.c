/*
 * Copyright (c) 2018-2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <assert.h>
#include <zephyr/sys/util.h>
#include <stdio.h>

#include "crc_event.h"

#if CONFIG_DESKTOP_CRC_ERROR_EVENT

static void profile_ble_crc_event(struct log_event_buf *buf, const struct app_event_header *aeh)
{
	const struct ble_crc_event *event = cast_ble_crc_event(aeh);

	nrf_profiler_log_encode_uint32(buf, (uint32_t)event->crc_ok_count);
	nrf_profiler_log_encode_uint32(buf, (uint32_t)event->crc_error_count);
	nrf_profiler_log_encode_uint16(buf, (uint16_t)event->crc_nak_count);
	nrf_profiler_log_encode_uint8(buf, (uint8_t)event->crc_rx_timeout);
}

APP_EVENT_INFO_DEFINE(ble_crc_event,
		      ENCODE(NRF_PROFILER_ARG_U32, NRF_PROFILER_ARG_U32, NRF_PROFILER_ARG_U16,
			     NRF_PROFILER_ARG_U8),
		      ENCODE("crc_ok_count", "crc_error_count", "crc_nak_count", "crc_rx_timeout"),
		      profile_ble_crc_event);

APP_EVENT_TYPE_DEFINE(ble_crc_event, NULL, &ble_crc_event_info,
		      APP_EVENT_FLAGS_CREATE(IF_ENABLED(false,
							(APP_EVENT_TYPE_FLAGS_INIT_LOG_ENABLE))));
#endif
