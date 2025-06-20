/**
 * Copyright (c) 2016 - 2018, Nordic Semiconductor ASA
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 *
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include "jetstr.h"
#if defined(CONFIG_SOC_SERIES_NRF54LX) || defined(CONFIG_SOC_SERIES_NRF54HX)
#include "hal/nrf_gpio.h"
#else
#include "nrf_gpio.h"
#endif /* NRF54L15_ENGA_XXAA */
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(jetstr, CONFIG_JETSTREAM_LOG_LEVEL);

static uint8_t pipe0_addr[] = SYSTEM_ADDRESS;

static bool first_rnd_sw = false;
static uint8_t chan_sw_cnt = 0;

static uint8_t channel_cnt;

// Debug helper variables
static volatile uint32_t push_ok;

static jetstr_cfg_params_t m_jetstr_cfg_params;

static uint8_t rf_channel_tab[5];

static uint8_t max_channel_attempts_before_discard;

#if defined(DBG_SIG_ENABLE) || defined(DBG_CHANNEL_ENABLE)
uint8_t dbg_sig_rf_channel[] = DBG_SIG_RF_CHANNEL_OUT;
#endif

static uint8_t channel_attempts = 0;

static uint8_t jetstr_channel_cnt = 0;

esb_event_handler jetstr_event_callback;

ISR_DIRECT_DECLARE(JETSTR_IRQHandler)
{
	if (JETSTR_SYS_TIMER->EVENTS_COMPARE[0] == 1) {
		JETSTR_SYS_TIMER->EVENTS_COMPARE[0] = 0; // clear timer compare event
		JETSTR_SYS_TIMER->CC[0] = m_jetstr_cfg_params.jetstr_rx_period;
#ifdef DBG_SIG_ENABLE
		nrf_gpio_pin_set(DBG_SIG_TIM_IRQ);
#endif

		esb_stop_rx();

#ifdef DBG_CHANNEL_ENABLE
		nrf_gpio_pin_clear(dbg_sig_rf_channel[jetstr_channel_cnt]);
#endif
		if ((!first_rnd_sw) || (chan_sw_cnt % 2 == 0)) {
			jetstr_channel_cnt = (jetstr_channel_cnt + 1) % m_jetstr_cfg_params.jetstr_channel_tab_size;
		}

		if (first_rnd_sw) {
			if (chan_sw_cnt >= m_jetstr_cfg_params.jetstr_channel_tab_size * 2) {
				first_rnd_sw = false;
				chan_sw_cnt = 0;
			}

			else {
				chan_sw_cnt++;
			}
		}

#ifdef DBG_CHANNEL_ENABLE
		nrf_gpio_pin_set(dbg_sig_rf_channel[jetstr_channel_cnt]);
#endif
		// LOG_INF("Channel switch to %d", rf_channel_tab[jetstr_channel_cnt]);
		esb_set_rf_channel(rf_channel_tab[jetstr_channel_cnt]);
		esb_start_rx();

#ifdef DBG_SIG_ENABLE
		nrf_gpio_pin_clear(DBG_SIG_TIM_IRQ);
#endif
	}
}

static void esb_ptx_event_handler(struct esb_evt const *p_event)
{
	jetstr_evt_t evt;

	evt.type = jetstr_evt_none;

	switch (p_event->evt_id) {
	case ESB_EVENT_TX_SUCCESS:
		evt.type = jetstr_evt_tx_success;
		esb_set_retransmit_count(m_jetstr_cfg_params.jetstr_retran_cnt_in_sync);
#ifdef DBG_SIG_ENABLE
		nrf_gpio_pin_set(DBG_SIG_TX_SUCCESS);
#endif
		//	 (void) esb_flush_tx();    //JS Modify: 1/3/18,  Remove
		channel_attempts = 0;
#ifdef DBG_SIG_ENABLE
		nrf_gpio_pin_clear(DBG_SIG_TX_SUCCESS);
#endif
		//     if (!nrf_gpio_pin_read(BSP_LED_1))  nrf_gpio_pin_set(BSP_LED_1);

		break;
	case ESB_EVENT_TX_FAILED:
#ifdef DBG_CHANNEL_ENABLE
	nrf_gpio_pin_clear(dbg_sig_rf_channel[channel_cnt]);
#endif
	channel_cnt = (channel_cnt + 1) % m_jetstr_cfg_params.jetstr_channel_tab_size;
		channel_attempts++;
		if (channel_attempts <
		    max_channel_attempts_before_discard) // retransamit at next radio channels
		{
#ifdef DBG_SIG_ENABLE
			nrf_gpio_pin_set(DBG_SIG_RETX);

#endif
			(void)esb_set_retransmit_count(
				m_jetstr_cfg_params.jetstr_retran_cnt_chan_sw);
#ifdef DBG_CHANNEL_ENABLE
			nrf_gpio_pin_set(dbg_sig_rf_channel[channel_cnt]);
#endif

			(void)esb_set_rf_channel(rf_channel_tab[channel_cnt]);
			(void)esb_start_tx();

#ifdef DBG_SIG_ENABLE
			nrf_gpio_pin_clear(DBG_SIG_RETX);
#endif
			return;
		} else // declare fail!!
		{

			evt.type = jetstr_evt_tx_failed;

#ifdef DBG_SIG_ENABLE
			nrf_gpio_pin_set(DBG_SIG_TX_FAIL);
#endif

			// Discard transmission
			(void)esb_set_retransmit_count(
				m_jetstr_cfg_params.jetstr_retran_cnt_out_of_sync);
			(void)esb_flush_tx();

			channel_attempts = 0;  //JS Modify: 1/7/2022
			// nrf_gpio_pin_clear(BSP_LED_1);

#ifdef DBG_SIG_ENABLE
			nrf_gpio_pin_clear(DBG_SIG_TX_FAIL);
#endif
		}
		break;

	case ESB_EVENT_RX_RECEIVED:
		evt.type = jetstr_evt_rx_received;
		break;
	}

	// app_sched_event_put(&evt, sizeof(evt), jetstr_event_callback);
	jetstr_event_callback(&evt);
}

volatile static uint16_t jetstr_tx_period;
volatile static uint16_t jetstr_modify_rx_period;

static void esb_prx_event_handler(struct esb_evt const *p_event)
{
	uint8_t retx_num;

	struct esb_payload rx_buf;
	jetstr_evt_t evt;

	evt.type = jetstr_evt_none;

	switch (p_event->evt_id) {
	case ESB_EVENT_TX_SUCCESS:
		evt.type = jetstr_evt_tx_success;
		break;
	case ESB_EVENT_TX_FAILED:
		evt.type = jetstr_evt_tx_failed;
		break;
	case ESB_EVENT_RX_RECEIVED:

		first_rnd_sw = true;
		chan_sw_cnt = 0; // JS Modify: 10/22/2018 <-- reset channel sw cnt

		evt.type = jetstr_evt_rx_received;
#ifdef DBG_SIG_ENABLE
		nrf_gpio_pin_set(DBG_SIG_RF_RCV);
#endif
		JETSTR_SYS_TIMER->TASKS_STOP = 1;
		JETSTR_SYS_TIMER->TASKS_CLEAR = 1; // clear timer
		if (esb_read_rx_payload(&rx_buf) == 0) {
			jetstr_modify_rx_period = (m_jetstr_cfg_params.jetstr_rx_period -
						m_jetstr_cfg_params.jetstr_rx_delay);
			// evt.rcv_length = rx_buf.length - 1;
			// memcpy(evt.rcv_data, &rx_buf.data[1], evt.rcv_length);
			evt.rcv_length = rx_buf.length;
			memcpy(evt.rcv_data, rx_buf.data, evt.rcv_length);

			// app_sched	_event_put(&evt, sizeof(evt), jetstr_event_callback);
			retx_num = rx_buf.data[0];

			JETSTR_SYS_TIMER->TASKS_STOP = 1;
			JETSTR_SYS_TIMER->TASKS_CLEAR = 1;

			if (retx_num <= JETSTR_RETRAN_CNT_MAX) {
				JETSTR_SYS_TIMER->CC[0] = jetstr_modify_rx_period -
							(retx_num * m_jetstr_cfg_params.jetsr_rx_retran);
			}

			// JETSTR_SYS_TIMER->CC[1] = jetstr_tx_period - 100;

			JETSTR_SYS_TIMER->TASKS_START = 1;

	#ifdef DBG_SIG_ENABLE
			nrf_gpio_pin_clear(DBG_SIG_RF_RCV);
	#endif
		}
	};

	jetstr_event_callback(&evt);
}

static uint32_t jetstr_esb_init(struct esb_config config)
{
	uint32_t err_code;
	uint8_t base_addr_0[4];
	uint8_t addr_prefix[] = {1};

	memcpy(base_addr_0, pipe0_addr, 4);
	channel_cnt = 0;

	//	     esb_config.tx_output_power          = esb_TX_POWER_NEG20DBM;   //<--
	//for testing only

	if (config.mode == ESB_MODE_PTX) {
		config.event_handler = esb_ptx_event_handler;
		config.retransmit_count = m_jetstr_cfg_params.jetstr_retran_cnt_out_of_sync;
	} else if (config.mode == ESB_MODE_PRX) {
		config.event_handler = esb_prx_event_handler;
	}

	err_code = esb_init(&config);
	if (err_code) {
		return err_code;
	}

	err_code = esb_set_rf_channel(rf_channel_tab[channel_cnt]);
	if (err_code) {
		return err_code;
	}

	err_code = esb_set_base_address_0(base_addr_0);
	if (err_code) {
		return err_code;
	}

	err_code = esb_set_prefixes(addr_prefix, sizeof(addr_prefix));
	if (err_code) {
		return err_code;
	}

	if (config.mode == ESB_MODE_PTX) {
#if defined(DBG_SIG_ENABLE) || defined(DBG_CHANNEL_ENABLE)
		nrf_gpio_cfg_output(DBG_SIG_POLL_EXP);
		nrf_gpio_cfg_output(DBG_SIG_SEND_PKT);
		nrf_gpio_cfg_output(DBG_SIG_TX_SUCCESS);
		nrf_gpio_cfg_output(DBG_SIG_RETX);
		nrf_gpio_cfg_output(DBG_SIG_TX_FAIL);
#endif
	} else if (config.mode == ESB_MODE_PRX) {

		NVIC_ClearPendingIRQ(JETSTR_IRQn);
		NVIC_SetPriority(JETSTR_IRQn, 0x00);
		NVIC_EnableIRQ(JETSTR_IRQn);
		JETSTR_SYS_TIMER->INTENSET = TIMER_INTENSET_COMPARE0_Msk;
		// JETSTR_SYS_TIMER->INTENSET = ( TIMER_INTENSET_COMPARE0_Msk |
		// TIMER_INTENSET_COMPARE1_Msk);
		/* connect timer irq handler */

		IRQ_DIRECT_CONNECT(JETSTR_IRQn, 0,
			JETSTR_IRQHandler,
			IRQ_ZERO_LATENCY);
#if defined(DBG_SIG_ENABLE) || defined(DBG_CHANNEL_ENABLE)
		for (uint8_t i = 0; i < 5; i++) {
			nrf_gpio_cfg_output(dbg_sig_rf_channel[i]);
		}
		nrf_gpio_cfg_output(DBG_SIG_RF_RCV);
		nrf_gpio_cfg_output(DBG_SIG_TIM_IRQ);
#endif
	}

	return err_code;
}

void jetstr_init(jetstr_cfg_t *jetstr_cfg, const jetstr_cfg_params_t *jetstr_cfg_params)
{

	memcpy(&m_jetstr_cfg_params, jetstr_cfg_params, sizeof(m_jetstr_cfg_params));

	memcpy(rf_channel_tab, m_jetstr_cfg_params.jetstr_channel_tab, sizeof(rf_channel_tab));

	max_channel_attempts_before_discard = m_jetstr_cfg_params.jetstr_channel_tab_size + 1;

	jetstr_channel_cnt = 0;

	jetstr_event_callback = jetstr_cfg->event_callback;

	jetstr_esb_init(jetstr_cfg->config);
}

void jetstr_rx_start(uint16_t rx_period)
{
	uint32_t err_code;
#ifdef DBG_SIG_ENABLE
	nrf_gpio_pin_set(dbg_sig_rf_channel[0]);
#endif

	// jetstr_hfclk_start();

	// esb_write_payload(&sys_addr_buf);

	err_code = esb_start_rx();

	// Configure the system timer with a 1 MHz base frequency
#if defined(CONFIG_SOC_SERIES_NRF54HX)
	JETSTR_SYS_TIMER->PRESCALER = 5;
#else
	JETSTR_SYS_TIMER->PRESCALER = 4;
#endif
	JETSTR_SYS_TIMER->BITMODE = TIMER_BITMODE_BITMODE_16Bit;
	JETSTR_SYS_TIMER->SHORTS = TIMER_SHORTS_COMPARE0_CLEAR_Msk;
	JETSTR_SYS_TIMER->CC[0] = m_jetstr_cfg_params.jetstr_rx_period;
	JETSTR_SYS_TIMER->TASKS_CLEAR = 1;
	JETSTR_SYS_TIMER->TASKS_START = 1;
}
