/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>
#include <assert.h>
#include <zephyr/sys/util.h>

#include <caf/events/module_suspend_event.h>
#include <caf/events/module_state_event.h>

static void log_module_suspend_req_event(const struct app_event_header *aeh)
{
	const struct module_suspend_req_event *event = cast_module_suspend_req_event(aeh);

	APP_EVENT_MANAGER_LOG(aeh, "module_suspend_req: %s", module_name_get(event->module_id));
}

APP_EVENT_TYPE_DEFINE(module_suspend_req_event,
		      log_module_suspend_req_event,
		      NULL,
		      APP_EVENT_FLAGS_CREATE(
			IF_ENABLED(CONFIG_CAF_INIT_LOG_MODULE_SUSPEND_EVENTS,
				(APP_EVENT_TYPE_FLAGS_INIT_LOG_ENABLE))));

static void log_module_resume_req_event(const struct app_event_header *aeh)
{
	const struct module_resume_req_event *event = cast_module_resume_req_event(aeh);

	APP_EVENT_MANAGER_LOG(aeh, "module_resume_req: %s", module_name_get(event->module_id));
}

APP_EVENT_TYPE_DEFINE(module_resume_req_event,
		      log_module_resume_req_event,
		      NULL,
		      APP_EVENT_FLAGS_CREATE(
			IF_ENABLED(CONFIG_CAF_INIT_LOG_MODULE_SUSPEND_EVENTS,
				(APP_EVENT_TYPE_FLAGS_INIT_LOG_ENABLE))));
