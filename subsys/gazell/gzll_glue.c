/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/clock_control.h>
#include <zephyr/drivers/clock_control/nrf_clock_control.h>

#include <nrf_gzll_glue.h>
#include <gzll_glue.h>
#include <helpers/nrfx_gppi.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(gzll, CONFIG_GAZELL_LOG_LEVEL);

#if defined(CONFIG_GAZELL_ZERO_LATENCY_IRQS)
#define GAZELL_HIGH_IRQ_FLAGS IRQ_ZERO_LATENCY
#else
#define GAZELL_HIGH_IRQ_FLAGS 0
#endif

#if defined(CONFIG_GAZELL_TIMER0)
#define GAZELL_TIMER_IRQN           TIMER0_IRQn
NRF_TIMER_Type * const nrf_gzll_timer = NRF_TIMER0;
#elif defined(CONFIG_GAZELL_TIMER1)
#define GAZELL_TIMER_IRQN           TIMER1_IRQn
NRF_TIMER_Type * const nrf_gzll_timer = NRF_TIMER1;
#elif defined(CONFIG_GAZELL_TIMER2)
#define GAZELL_TIMER_IRQN           TIMER2_IRQn
NRF_TIMER_Type * const nrf_gzll_timer = NRF_TIMER2;
#elif defined(CONFIG_GAZELL_TIMER3)
#define GAZELL_TIMER_IRQN           TIMER3_IRQn
NRF_TIMER_Type * const nrf_gzll_timer = NRF_TIMER3;
#elif defined(CONFIG_GAZELL_TIMER4)
#define GAZELL_TIMER_IRQN           TIMER4_IRQn
NRF_TIMER_Type * const nrf_gzll_timer = NRF_TIMER4;
#elif defined(CONFIG_GAZELL_TIMER10)
#define GAZELL_TIMER_IRQN           TIMER10_IRQn
NRF_TIMER_Type *const nrf_gzll_timer = NRF_TIMER10;
#elif defined(CONFIG_GAZELL_TIMER20)
#define GAZELL_TIMER_IRQN           TIMER20_IRQn
NRF_TIMER_Type *const nrf_gzll_timer = NRF_TIMER20;
#elif defined(CONFIG_GAZELL_TIMER21)
#define GAZELL_TIMER_IRQN           TIMER21_IRQn
NRF_TIMER_Type *const nrf_gzll_timer = NRF_TIMER21;
#elif defined(CONFIG_GAZELL_TIMER22)
#define GAZELL_TIMER_IRQN           TIMER22_IRQn
NRF_TIMER_Type *const nrf_gzll_timer = NRF_TIMER22;
#elif defined(CONFIG_GAZELL_TIMER23)
#define GAZELL_TIMER_IRQN           TIMER23_IRQn
NRF_TIMER_Type *const nrf_gzll_timer = NRF_TIMER23;
#elif defined(CONFIG_GAZELL_TIMER24)
#define GAZELL_TIMER_IRQN           TIMER24_IRQn
NRF_TIMER_Type *const nrf_gzll_timer = NRF_TIMER24;

#else
#error "Gazell timer is undefined."
#endif
IRQn_Type        const nrf_gzll_timer_irqn = GAZELL_TIMER_IRQN;

#if defined(CONFIG_SOC_SERIES_NRF54LX)
	#if defined(CONFIG_GAZELL_SWI0)
	#define GAZELL_SWI_IRQN             SWI00_IRQn
	#elif defined(CONFIG_GAZELL_SWI1)
	#define GAZELL_SWI_IRQN             SWI01_IRQn
	#elif defined(CONFIG_GAZELL_SWI2)
	#define GAZELL_SWI_IRQN             SWI02_IRQn
	#elif defined(CONFIG_GAZELL_SWI3)
	#define GAZELL_SWI_IRQN             SWI03_IRQn
	#else
	#error "Gazell software interrupt is undefined."
	#endif
#define GAZELL_RADIO_IRQN RADIO_0_IRQn
#else
	#if defined(CONFIG_GAZELL_SWI0)
	#define GAZELL_SWI_IRQN             SWI0_IRQn
	#elif defined(CONFIG_GAZELL_SWI1)
	#define GAZELL_SWI_IRQN             SWI1_IRQn
	#elif defined(CONFIG_GAZELL_SWI2)
	#define GAZELL_SWI_IRQN             SWI2_IRQn
	#elif defined(CONFIG_GAZELL_SWI3)
	#define GAZELL_SWI_IRQN             SWI3_IRQn
	#elif defined(CONFIG_GAZELL_SWI4)
	#define GAZELL_SWI_IRQN             SWI4_IRQn
	#elif defined(CONFIG_GAZELL_SWI5)
	#define GAZELL_SWI_IRQN             SWI5_IRQn
	#else
	#error "Gazell software interrupt is undefined."
	#endif
#define GAZELL_RADIO_IRQN RADIO_IRQn
#endif /* CONFIG_SOC_SERIES_NRF54LX */
IRQn_Type        const nrf_gzll_swi_irqn   = GAZELL_SWI_IRQN;

#if defined(CONFIG_NRFX_PPI)
__IOM uint32_t *nrf_gzll_ppi_eep0;
__IOM uint32_t *nrf_gzll_ppi_tep0;
__IOM uint32_t *nrf_gzll_ppi_eep1;
__IOM uint32_t *nrf_gzll_ppi_tep1;
__IOM uint32_t *nrf_gzll_ppi_eep2;
__IOM uint32_t *nrf_gzll_ppi_tep2;

uint32_t nrf_gzll_ppi_chen_msk_0_and_1;
uint32_t nrf_gzll_ppi_chen_msk_2;
#endif

#if defined(CONFIG_NRFX_DPPI) || defined(CONFIG_SOC_SERIES_NRF54LX)
uint8_t nrf_gzll_dppi_ch0;
uint8_t nrf_gzll_dppi_ch1;
uint8_t nrf_gzll_dppi_ch2;

uint32_t nrf_gzll_dppi_chen_msk_0_and_1;
uint32_t nrf_gzll_dppi_chen_msk_2;
#endif

static bool initial_setup_done;
static bool m_turn_off_constant = true;

#if !defined(CONFIG_NRFX_DPPI)
/** Use fixed DPPI channels and groups since nrf-dppic-global driver is not ready yet. */
#define GAZELL_DPPI_FIXED
/** First fixed DPPI channel, total used channels: 7. */
#define GAZELL_DPPI_FIRST_FIXED_CHANNEL 0
#endif

bool nrf_gzll_gpio_debug_enabled = IS_ENABLED(CONFIG_GAZELL_GPIO_DEBUG);
uint32_t nrf_gzll_flw_debug_pin = CONFIG_GAZELL_DEBUG_FLY_PIN;
uint32_t nrf_gzll_lcore_pin_irq = CONFIG_GAZELL_LCORE_DEBUG_IRQ_PIN;
uint32_t nrf_gzll_lcore_pin_1 = CONFIG_GAZELL_LCORE_DEBUG_PIN_1;
uint32_t nrf_gzll_lcore_pin_2 = CONFIG_GAZELL_LCORE_DEBUG_PIN_2;
uint32_t nrf_gzll_lcore_pin_3 = CONFIG_GAZELL_LCORE_DEBUG_PIN_3;
uint32_t nrf_gzll_lcore_pin_4 = CONFIG_GAZELL_LCORE_DEBUG_PIN_4;
uint32_t nrf_gzll_dbg_pin = CONFIG_GAZELL_DEBUG_PIN;

#ifdef CONFIG_GAZELL_DYNAMIC_RADIO_INTERRUPT
static void gazell_radio_irq_handler(const void *args)
{
	ARG_UNUSED(args);
	nrf_gzll_radio_irq_handler();
}

#else /* !CONFIG_GAZELL_DYNAMIC_RADIO_INTERRUPT */

ISR_DIRECT_DECLARE(gazell_radio_irq_handler)
{
	nrf_gzll_radio_irq_handler();

	return 0;
}

#endif /* CONFIG_GAZELL_DYNAMIC_RADIO_INTERRUPT */

ISR_DIRECT_DECLARE(gazell_timer_irq_handler)
{
	nrf_gzll_timer_irq_handler();

	return 0;
}

static void gazell_swi_irq_handler(void *args)
{
	ARG_UNUSED(args);

	nrf_gzll_swi_irq_handler();
}

bool gzll_glue_init(void)
{
	bool is_ok = true;
	const struct device *clkctrl = DEVICE_DT_GET_ONE(nordic_nrf_clock);
#if !defined(GAZELL_DPPI_FIXED)
	nrfx_err_t err_code;
#endif
	uint8_t ppi_channel[3];
	uint8_t i;

	irq_disable(GAZELL_RADIO_IRQN);
	if (!initial_setup_done) {
		irq_disable(GAZELL_TIMER_IRQN);
		irq_disable(GAZELL_SWI_IRQN);
	}

#if !defined(CONFIG_GAZELL_ZERO_LATENCY_IRQS)
	BUILD_ASSERT(CONFIG_GAZELL_HIGH_IRQ_PRIO < CONFIG_GAZELL_LOW_IRQ_PRIO,
		"High IRQ priority value is not lower than low IRQ priority value");
#endif

	IRQ_CONNECT(GAZELL_SWI_IRQN,
		    CONFIG_GAZELL_LOW_IRQ_PRIO,
		    gazell_swi_irq_handler,
		    NULL,
		    0);

	IRQ_DIRECT_CONNECT(GAZELL_TIMER_IRQN,
			   CONFIG_GAZELL_HIGH_IRQ_PRIO,
			   gazell_timer_irq_handler,
			   GAZELL_HIGH_IRQ_FLAGS);

#if CONFIG_GAZELL_DYNAMIC_RADIO_INTERRUPT
	ARM_IRQ_DIRECT_DYNAMIC_CONNECT(GAZELL_RADIO_IRQN, CONFIG_GAZELL_HIGH_IRQ_PRIO,
				       GAZELL_HIGH_IRQ_FLAGS, reschedule);
	irq_connect_dynamic(GAZELL_RADIO_IRQN, CONFIG_GAZELL_HIGH_IRQ_PRIO,
			    gazell_radio_irq_handler, NULL, GAZELL_HIGH_IRQ_FLAGS);
#else /* !CONFIG_GAZELL_DYNAMIC_RADIO_INTERRUPT */
	IRQ_DIRECT_CONNECT(GAZELL_RADIO_IRQN,
			   CONFIG_GAZELL_HIGH_IRQ_PRIO,
			   gazell_radio_irq_handler,
			   GAZELL_HIGH_IRQ_FLAGS);
#endif /* CONFIG_GAZELL_DYNAMIC_RADIO_INTERRUPT */

	if (initial_setup_done) {
		return is_ok;
	}

	if (!device_is_ready(clkctrl)) {
		is_ok = false;
	}

	for (i = 0; i < 3; i++) {
#if defined(GAZELL_DPPI_FIXED)
		ppi_channel[i] = GAZELL_DPPI_FIRST_FIXED_CHANNEL + i;
#else
		err_code = nrfx_gppi_channel_alloc(&ppi_channel[i]);
		if (err_code != NRFX_SUCCESS) {
			is_ok = false;
			break;
		}
#endif /* ESB_DPPI_FIXED */
	}

	if (is_ok) {
#if defined(CONFIG_NRFX_PPI)
		nrf_gzll_ppi_eep0 = &NRF_PPI->CH[ppi_channel[0]].EEP;
		nrf_gzll_ppi_tep0 = &NRF_PPI->CH[ppi_channel[0]].TEP;
		nrf_gzll_ppi_eep1 = &NRF_PPI->CH[ppi_channel[1]].EEP;
		nrf_gzll_ppi_tep1 = &NRF_PPI->CH[ppi_channel[1]].TEP;
		nrf_gzll_ppi_eep2 = &NRF_PPI->CH[ppi_channel[2]].EEP;
		nrf_gzll_ppi_tep2 = &NRF_PPI->CH[ppi_channel[2]].TEP;

		nrf_gzll_ppi_chen_msk_0_and_1 = ((1 << ppi_channel[0]) |
						 (1 << ppi_channel[1]));
		nrf_gzll_ppi_chen_msk_2 = (1 << ppi_channel[2]);
#endif

#if defined(CONFIG_NRFX_DPPI) || defined(CONFIG_SOC_SERIES_NRF54LX)
		nrf_gzll_dppi_ch0 = ppi_channel[0];
		nrf_gzll_dppi_ch1 = ppi_channel[1];
		nrf_gzll_dppi_ch2 = ppi_channel[2];

		nrf_gzll_dppi_chen_msk_0_and_1 = ((1 << ppi_channel[0]) | (1 << ppi_channel[1]));
		nrf_gzll_dppi_chen_msk_2 = (1 << ppi_channel[2]);
#endif
	}

	if (is_ok) {
		initial_setup_done = true;
	}

	return is_ok;
}

bool gzll_glue_uninit(void)
{
	if (!IS_ENABLED(CONFIG_GAZELL_DYNAMIC_RADIO_INTERRUPT)) {
		return false;
	}

	irq_disable(GAZELL_RADIO_IRQN);

	return true;
}

void nrf_gzll_delay_us(uint32_t usec_to_wait)
{
	k_busy_wait(usec_to_wait);
}

void nrf_gzll_request_xosc(void)
{
	z_nrf_clock_bt_ctlr_hf_request();
#if defined(CONFIG_SOC_SERIES_NRF54LX)
	NRF_POWER->TASKS_CONSTLAT = 1;
#endif

	/* Wait 1.5ms with 9% tolerance.
	 * 1500 * 1.09 = 1635
	 */
	k_busy_wait(1635);
}

void nrf_gzll_release_xosc(void)
{
	z_nrf_clock_bt_ctlr_hf_release();
#if defined(CONFIG_SOC_SERIES_NRF54LX)
	if (m_turn_off_constant) {
		NRF_POWER->TASKS_LOWPWR = 1;
	}
#endif
}

#define GAZELL_CH_DEBUG
#if defined(GAZELL_CH_DEBUG)
uint32_t nrf_gzll_get_channel_table_size(void);
bool nrf_gzll_get_channel_table(uint8_t *p_out_channel_table, uint32_t *p_out_size);

void nrf_gzll_dump_channels(void)
{
	uint32_t ch_size;
	bool ch_ok;
	uint8_t channels[16];

	ch_size = nrf_gzll_get_channel_table_size();
	ch_ok = nrf_gzll_get_channel_table(channels, &ch_size);
	LOG_INF("gazell table size %d, %d", ch_size, ch_ok);
	for(size_t i = 0; i < ch_size; i++) {
		LOG_INF("gazell channel %d: %d", i, channels[i]);
	}
}

#endif /* GAZELL_CH_DEBUG */
