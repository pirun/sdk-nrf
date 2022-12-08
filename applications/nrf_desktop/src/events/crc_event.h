/*
 * Copyright (c) 2018-2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef _CRC_EVENT_H_
#define _CRC_EVENT_H_

/**
 * @brief CRC Event
 * @defgroup crc_event CRC Event
 * @{
 */

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>

#include <app_event_manager.h>
#include <app_event_manager_profiler_tracer.h>
#include "hwid.h"


#ifdef __cplusplus
extern "C" {
#endif


#if CONFIG_DESKTOP_CRC_ERROR_EVENT
/** @brief CRC count event. */
struct ble_crc_event {
	struct app_event_header header;

	uint32_t crc_ok_count;
	uint32_t crc_error_count;
	uint16_t crc_nak_count;
	uint8_t crc_rx_timeout;
};
APP_EVENT_TYPE_DECLARE(ble_crc_event);
#endif

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* _CRC_EVENT_H_ */
