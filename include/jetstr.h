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
#include "esb.h"
#include "jetstr_config.h"

#if defined(CONFIG_SOC_SERIES_NRF54LX)
#define JETSTR_SYS_TIMER  NRF_TIMER20 /**< The timer which will be used by the module. */
#define JETSTR_IRQn	  TIMER20_IRQn
#define DBG_SIG_POLL_EXP   0x49 // P2.09 LED1 Debug signal for packet polling timer expire
#define DBG_SIG_SEND_PKT   0x2A // P1.10 LED2 Debug signal for sending packet
#define DBG_SIG_TX_SUCCESS 0x47 // P2.07 LED3 Debug signal for ESB TX success event
#define DBG_SIG_RETX	   0x2E // P1.14 LED4 Debug signal for ESB retranmit packet at next radio channel
#define DBG_SIG_TX_FAIL	   0x46 // P2.06 Debug signal for ESB tranmit fail and discrd packet
#define DBG_SIG_RF_RCV	   0x48 // P2.08 Debug signal for packet received
#define DBG_SIG_TIM_IRQ	   0x4A // P2.10 Debug signal for system timer interrupt
#elif defined(CONFIG_SOC_SERIES_NRF54HX)
#define JETSTR_SYS_TIMER  NRF_TIMER020 /**< The timer which will be used by the module. */
#define JETSTR_IRQn	  TIMER020_IRQn
#define DBG_SIG_POLL_EXP   0x00 // P0.07 Debug signal for packet polling timer expire
#define DBG_SIG_SEND_PKT   0x01 // P0.08 Debug signal for sending packet
#define DBG_SIG_TX_SUCCESS 0x02 // P0.09 Debug signal for ESB TX success event
#define DBG_SIG_RETX	   0x03 // P0.10 Debug signal for ESB retranmit packet at next radio channel
#define DBG_SIG_TX_FAIL	   0x07 // P0.11 Debug signal for ESB tranmit fail and discrd packet
#define DBG_SIG_RF_RCV	   0x08 // P0.00 Debug signal for packet received
#define DBG_SIG_TIM_IRQ	   0x09 // P0.01 Debug signal for system timer interrupt

#elif defined(CONFIG_SOC_SERIES_NRF52X)
#define JETSTR_SYS_TIMER  NRF_TIMER0 /**< The timer which will be used by the module. */
#define JETSTR_IRQn	  TIMER0_IRQn
#define JETSTR_IRQHandler TIMER0_IRQHandler
#define DBG_SIG_POLL_EXP   3  // Debug signal for packet polling timer expire
#define DBG_SIG_SEND_PKT   4  // Debug signal for sending packet
#define DBG_SIG_TX_SUCCESS 28 // Debug signal for ESB TX success event
#define DBG_SIG_RETX	   29 // Debug signal for ESB retranmit packet at next radio channel
#define DBG_SIG_TX_FAIL	   30 // Debug signal for ESB tranmit fail and discrd packet
#define DBG_SIG_RF_RCV	27 // Debug signal for packet received
#define DBG_SIG_TIM_IRQ 26 // Debug signal for system timer interrupt

#endif

// #define DBG_SIG_ENABLE
#define DBG_CHANNEL_ENABLE

#define DBG_SIG_RF_CHANNEL_OUT\
	{\
		DBG_SIG_POLL_EXP,\
		DBG_SIG_SEND_PKT,\
		DBG_SIG_TX_SUCCESS,\
		DBG_SIG_RETX,\
		DBG_SIG_TX_FAIL\
} // Debug signals which asserts when PRX stays on the corresponding channel no.

/**@brief JETSTR config parameters. */
typedef struct {
	uint8_t *jetstr_channel_tab;
	uint8_t jetstr_channel_tab_size;
	uint16_t jetstr_rx_period;
	uint16_t jetstr_rx_delay;
	uint8_t jetstr_retran_cnt_in_sync;
	uint8_t jetstr_retran_cnt_out_of_sync;
	uint16_t jetsr_rx_retran;
	uint16_t jetstr_retran_cnt_chan_sw;

} jetstr_cfg_params_t;

typedef enum {
	JETSTR_PKT_RATE_NULL = 0,
	JETSTR_PKT_RATE_1MS,
	JETSTR_PKT_RATE_1M2S,
	JETSTR_PKT_RATE_2MS,
	JETSTR_PKT_RATE_5MS

} jetstr_pkt_rate_t;

typedef enum {
	jetstr_evt_none = 0,
	jetstr_evt_tx_success,
	jetstr_evt_tx_failed,
	jetstr_evt_rx_received

} jetstr_event_t;

typedef void (*jetstr_event_handler)(void *p_event_data, uint16_t event_size);

typedef struct {
	struct esb_config config;
	jetstr_event_handler event_callback;

} jetstr_cfg_t;

typedef struct {

	jetstr_event_t type;
	uint8_t rcv_data[CONFIG_ESB_MAX_PAYLOAD_LENGTH]; // JS Modify:  for Pixart INPUT_REP_MOVEMENT_LEN = 8
	uint8_t rcv_length;

} jetstr_evt_t;


void jetstr_init(jetstr_cfg_t *jetstr_cfg, const jetstr_cfg_params_t *jetstr_cfg_params);

void jetstr_rx_start(uint16_t rx_period);

void jetstr_hfclk_start(void);

void jetstr_hfclk_stop(void);
