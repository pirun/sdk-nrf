/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SLM_AT_GPIO_
#define SLM_AT_GPIO_

/**@file slm_at_GPIO.h
 *
 * @brief Vendor-specific AT command for GPIO service.
 * @{
 */

#include <drivers/gpio.h>

#define MAX_GPIO_PIN 31

/* Regular GPIO */
#define SLM_GPIO_FN_DISABLE	0	/* Disables pin for both input and output. */
#define SLM_GPIO_FN_OUT		1	/* Enables pin as output. */
#define SLM_GPIO_FN_IN_PU	21	/* Enables pin as input. Use internal pull up resistor. */
#define SLM_GPIO_FN_IN_PD	22	/* Enables pin as input. Use internal pull down resistor. */
#if defined(CONFIG_SLM_CUSTOMIZED_RS232)
/* RS-232 GPIO */
#define SLM_GPIO_FN_RS232_DTR	310	/* Enables pin as RS-232 DTR pin */
#endif
#if defined(CONFIG_SLM_UI)
/* Default UI GPIO */
#define SLM_GPIO_FN_LTE		400	/* Enables pin as LTE state pin */
#define SLM_GPIO_FN_DATA	401	/* Enables pin as DATA pin */
#define SLM_GPIO_FN_SIGNAL	402	/* Enables pin as LTE signal strength pin */
#if defined(CONFIG_SLM_CUSTOMIZED)
#define SLM_GPIO_FN_DIAG	403	/* Enables pin as ERROR pin */
#define SLM_GPIO_FN_MOD_FLASH	410	/* Enables pin as MOD FLASHLED pin */
#endif
#endif

/**@brief GPIO operations. */
enum slm_gpio_operations {
	SLM_GPIO_OP_WRITE,
	SLM_GPIO_OP_READ,
	SLM_GPIO_OP_TOGGLE
};

#if defined(CONFIG_SLM_UI)
int slm_gpio_get_ui_pin(uint16_t fn);
#endif

/**
 * @brief Initialize GPIO AT command parser.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int slm_at_gpio_init(void);

/**
 * @brief Uninitialize GPIO AT command parser.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int slm_at_gpio_uninit(void);

int do_gpio_pin_configure_set(gpio_pin_t pin, uint16_t fn);

/** @} */

#endif /* SLM_AT_GPIO_ */
