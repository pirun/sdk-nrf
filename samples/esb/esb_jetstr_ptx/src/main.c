/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <zephyr/drivers/clock_control.h>
#include <zephyr/drivers/clock_control/nrf_clock_control.h>

#if defined(NRF54L15_XXAA)
#include <hal/nrf_clock.h>
#endif /* defined(NRF54L15_XXAA) */
#include <zephyr/drivers/timer/nrf_grtc_timer.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/irq.h>
#include <zephyr/logging/log.h>
#include <nrf.h>
#include <esb.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/types.h>
#include <zephyr/sys/byteorder.h>
#if defined(CONFIG_CLOCK_CONTROL_NRF2)
#include <hal/nrf_lrcconf.h>
#endif
#if defined(CONFIG_CLOAK)
#include <cloak.h>
#endif
#include <jetstr.h>
LOG_MODULE_REGISTER(esb_ptx, CONFIG_ESB_PTX_APP_LOG_LEVEL);
struct main_msg {
	uint32_t type;
	uint32_t cnt;
#ifdef CONFIG_CLOAK
	uint32_t cnt_err;
#endif
};

#define MAIN_MSG_TX             0
#define MAIN_MSG_TIMER          1
#define MAIN_MSG_TX_FAIL        2
#define MAIN_MSG_RX             3

struct print_msg {
	uint32_t tx_cnt;
	uint32_t tx_fail_cnt;
	uint32_t rx_cnt;
#ifdef CONFIG_ESB_PTX_DATA_CHECK
	uint32_t rx_error_cnt;
#endif
	int64_t time_cnt;
};

static struct esb_payload rx_payload;
static struct esb_payload tx_payload = ESB_CREATE_PAYLOAD(0, 0x01, 0x02, 0x03, 0x04);
K_MSGQ_DEFINE(main_msgq,
	      sizeof(struct main_msg),
	      64,
	      sizeof(uint32_t));

K_MSGQ_DEFINE(print_msgq,
	      sizeof(struct print_msg),
	      1,
	      sizeof(uint32_t));


static struct k_thread print_thread;

static K_THREAD_STACK_DEFINE(print_stack, 512);

#if CONFIG_ESB_PTX_DELAY > 0
static int32_t timer_chan;
static uint64_t timer_tick;

static int timer_target_set(void);
#endif

static uint8_t nonce[13] = {0};
uint8_t data[CONFIG_APP_DATA_LENGTH];
static uint8_t s_channel_tab[] = JETSTR_CHANNEL_TAB;
static const int8_t hid_xy[][2] = {
	{35,7}, {30,21}, {21,30}, {7,35},
	{-7,35}, {-21,30}, {-30,21}, {-35,7},
	{-35,-7}, {-30,-21}, {-21,-30}, {-7,-35},
	{7,-35}, {21,-30}, {30,-21}, {35,-7}
};

void event_handler(void *p_event_data, uint16_t event_size)
{
	struct main_msg msg;
	int err;
	jetstr_evt_t *evt;

	evt = (jetstr_evt_t *)p_event_data;
	switch (evt->type) {
	case jetstr_evt_tx_success:
		msg.type = MAIN_MSG_TX;
		msg.cnt = 1;
		err = k_msgq_put(&main_msgq, &msg, K_NO_WAIT);
		if (err) {
			LOG_ERR("Cannot put TX done to message queue");
		}
		break;
	case jetstr_evt_tx_failed:
		esb_start_tx();
		msg.type = MAIN_MSG_TX_FAIL;
		msg.cnt = 1;
		err = k_msgq_put(&main_msgq, &msg, K_NO_WAIT);
		if (err) {
			LOG_ERR("Cannot put TX fail to message queue");
		}
		break;
	case jetstr_evt_rx_received:
		msg.type = MAIN_MSG_RX;
		msg.cnt = 0;
#ifdef CONFIG_CLOAK
		msg.cnt_err = 0;
#endif
		while (esb_read_rx_payload(&rx_payload) == 0) {
			msg.cnt++;
		}

		err = k_msgq_put(&main_msgq, &msg, K_NO_WAIT);
		if (err) {
			LOG_ERR("Cannot put RX count to message queue");
		}

		break;
	case jetstr_evt_none:

		break;

	}
}

#if defined(CONFIG_CLOCK_CONTROL_NRF)
int clocks_start(void)
{
	int err;
	int res;
	struct onoff_manager *clk_mgr;
	struct onoff_client clk_cli;

	clk_mgr = z_nrf_clock_control_get_onoff(CLOCK_CONTROL_NRF_SUBSYS_HF);
	if (!clk_mgr) {
		LOG_ERR("Unable to get the Clock manager");
		return -ENXIO;
	}

	sys_notify_init_spinwait(&clk_cli.notify);

	err = onoff_request(clk_mgr, &clk_cli);
	if (err < 0) {
		LOG_ERR("Clock request failed: %d", err);
		return err;
	}

	do {
		err = sys_notify_fetch_result(&clk_cli.notify, &res);
		if (!err && res) {
			LOG_ERR("Clock could not be started: %d", res);
			return res;
		}
	} while (err);

#if defined(NRF54L15_XXAA)
	/* MLTPAN-20 */
	nrf_clock_task_trigger(NRF_CLOCK, NRF_CLOCK_TASK_PLLSTART);
#endif /* defined(NRF54L15_XXAA) */

	LOG_DBG("HF clock started");
	return 0;
}

#elif defined(CONFIG_CLOCK_CONTROL_NRF2)

int clocks_start(void)
{
	int err;
	int res;
	const struct device *radio_clk_dev =
		DEVICE_DT_GET_OR_NULL(DT_CLOCKS_CTLR(DT_NODELABEL(radio)));
	struct onoff_client radio_cli;

	/** Keep radio domain powered all the time to reduce latency. */
	nrf_lrcconf_poweron_force_set(NRF_LRCCONF010, NRF_LRCCONF_POWER_DOMAIN_1, true);

	sys_notify_init_spinwait(&radio_cli.notify);

	err = nrf_clock_control_request(radio_clk_dev, NULL, &radio_cli);

	do {
		err = sys_notify_fetch_result(&radio_cli.notify, &res);
		if (!err && res) {
			LOG_ERR("Clock could not be started: %d", res);
			return res;
		}
	} while (err == -EAGAIN);

	nrf_lrcconf_clock_always_run_force_set(NRF_LRCCONF000, 0, true);
	nrf_lrcconf_task_trigger(NRF_LRCCONF000, NRF_LRCCONF_TASK_CLKSTART_0);

	LOG_DBG("HF clock started");
	return 0;
}

#else
BUILD_ASSERT(false, "No Clock Control driver");
#endif /* defined(CONFIG_CLOCK_CONTROL_NRF2) */

int esb_initialize(void)
{
	int err;
	/* These are arbitrary default addresses. In end user products
	 * different addresses should be used for each set of devices.
	 */
	jetstr_cfg_t jetstr_config;
	jetstr_cfg_params_t jetstr_cfg_params;
	struct esb_config config = ESB_DEFAULT_CONFIG;

	jetstr_cfg_params.jetstr_channel_tab = s_channel_tab;
	jetstr_cfg_params.jetstr_channel_tab_size = JETSTR_CHANNEL_TAB_SIZE;
	jetstr_cfg_params.jetstr_rx_period = JETSTR_RX_PERIOD;
	jetstr_cfg_params.jetstr_rx_delay = JETSTR_RX_DELAY;
	jetstr_cfg_params.jetstr_retran_cnt_in_sync = JETSTR_RETRAN_CNT_IN_SYNC;
	jetstr_cfg_params.jetstr_retran_cnt_out_of_sync = JETSTR_RETRAN_CNT_OUT_OF_SYNC;
	jetstr_cfg_params.jetsr_rx_retran = JETSTR_RX_RETRAN;
	jetstr_cfg_params.jetstr_retran_cnt_chan_sw = JETSTR_RETRAN_CNT_CHAN_SW;

	jetstr_config.event_callback = event_handler;
	jetstr_config.config = config;
	jetstr_config.config.protocol = ESB_PROTOCOL_ESB_DPL;
	jetstr_config.config.bitrate = ESB_BITRATE_4MBPS;
	jetstr_config.config.mode = ESB_MODE_PTX;
	jetstr_config.config.crc = ESB_CRC_16BIT;
	jetstr_config.config.tx_output_power = 8;
	jetstr_config.config.selective_auto_ack = true;
	if (IS_ENABLED(CONFIG_ESB_FAST_SWITCHING)) {
		jetstr_config.config.use_fast_ramp_up = true;
	}

	jetstr_init(&jetstr_config.config, &jetstr_cfg_params);

	return 0;
}

static void fill_tx_payload_data(struct esb_payload *payload)
{
	static uint8_t tx_data_next;

	payload->data[0] = 2;
	payload->data[1] = 0;
	payload->data[2] = hid_xy[tx_data_next][0];
	payload->data[3] = hid_xy[tx_data_next][1];
	payload->data[4] = 0;

	tx_data_next = (tx_data_next + 1 < ARRAY_SIZE(hid_xy)) ? tx_data_next + 1 : 0;

}

static void fill_tx_fifo(void)
{
	int err;
	static bool tx_data_set;
#if defined(CONFIG_CLOAK)
	uint8_t opc = CLOAK_OPC_CCM_DATA_P;
	static uint8_t temp[CLOAK_DATA_MAX_SIZE];
	size_t olen;
	uint32_t temp_nonce = 256;
#endif

	while (1) {
		if (!tx_data_set) {
			fill_tx_payload_data(&tx_payload);
		}
#if defined(CONFIG_CLOAK)

		temp_nonce = sys_get_le32(nonce);
		temp_nonce++;
		// LOG_INF("%d", temp_nonce);
		sys_put_le48(temp_nonce, &nonce[0]);

		err = cloak_ccm_encrypt_data(PSA_KEY_ID_NULL,
				nonce,
				&opc, sizeof(opc),
				data, sizeof(data),
				&tx_payload.data[1], CONFIG_APP_DATA_LENGTH + 4,
				&olen);
		sys_put_le32(temp_nonce, &tx_payload.data[1 + CONFIG_APP_DATA_LENGTH + 4]);
		// LOG_INF("e after tick = %lld", k_uptime_get() - before);
		// };

		// before = k_uptime_get();
		// LOG_HEXDUMP_INF(data, sizeof(data), "plain   data");
		// LOG_HEXDUMP_INF(&tx_payload.data[0], olen + 1, "encrypt data");
		// LOG_INF("encrypt olen = %d", olen);
		// err = cloak_ccm_decrypt_data(PSA_KEY_ID_NULL,
		// 		nonce,
		// 		&opc, sizeof(opc),
		// 		&tx_payload.data[1], olen,
		// 		temp, sizeof(temp),
		// 		&olen);

		// LOG_INF("d after tick = %lld", k_uptime_get() - before);
		// if(err) {
		// 	LOG_ERR("cloak_ccm_decrypt_data Error = %d", err);
		// }

#endif
		err = esb_write_payload(&tx_payload);
		tx_data_set = (!err) ? false : true;
		if (err) {
			break;
		}

#if CONFIG_ESB_PTX_DELAY > 0
		break;
#endif
	}
}

#if CONFIG_ESB_PTX_DELAY > 0
static void timer_compare_handler(int32_t chan_id,
				  uint64_t expire_time,
				  void *user_data)
{
	timer_target_set();

	struct main_msg msg;
	int err;

	msg.type = MAIN_MSG_TIMER;
	err = k_msgq_put(&main_msgq, &msg, K_NO_WAIT);
	if (err) {
		LOG_ERR("Cannot put TIMER count to message queue");
	}
}

static int timer_target_set(void)
{
	int err;

	timer_tick += CONFIG_ESB_PTX_DELAY; // TODO: convert microseconds to timer tick

	err = z_nrf_grtc_timer_set(timer_chan,
				   timer_tick,
				   timer_compare_handler,
				   NULL);

	return err;
}
#endif

static void print_main(void *p1, void *p2, void *p3)
{
	struct print_msg msg;

	/* Process message queue */
	while (!k_msgq_get(&print_msgq, &msg, K_FOREVER)) {
		LOG_INF("Sent %u packets. Failed %u packets. Received %u packets.",
			msg.tx_cnt, msg.tx_fail_cnt, msg.rx_cnt);
		LOG_INF("Elapsed %lld milliseconds.", msg.time_cnt);
	}
}


int main(void)
{
	int err;

	LOG_INF("Enhanced ShockBurst ptx sample");

	err = clocks_start();
	if (err) {
		return 0;
	}

	err = esb_initialize();
	if (err) {
		LOG_ERR("ESB initialization failed, err %d", err);
		return 0;
	}

#if defined(CONFIG_CLOAK)
	cloak_init();
	cloak_set_pairing_key(CLOAK_DEFAULT_PAIR_KEY);
	cloak_import_ccm_sk(CLOAK_DEFAULT_AES_KEY);
#endif

	k_thread_create(&print_thread,
			print_stack,
			K_THREAD_STACK_SIZEOF(print_stack),
			print_main,
			NULL,
			NULL,
			NULL,
			K_LOWEST_APPLICATION_THREAD_PRIO,
			0,
			K_NO_WAIT);

#if CONFIG_ESB_PTX_DELAY > 0
	timer_chan = z_nrf_grtc_timer_chan_alloc();
	if (timer_chan < 0) {
		LOG_ERR("Cannot get a timer channel");
		return 0;
	}
#endif

	LOG_INF("Initialization complete");
	LOG_INF("Sending test packet");

	tx_payload.length = 5;//CONFIG_ESB_PTX_TX_LENGTH;
	fill_tx_payload_data(&tx_payload);
	tx_payload.noack = false;

#if CONFIG_ESB_PTX_DELAY > 0
	timer_tick = z_nrf_grtc_timer_read();
	timer_target_set();
#endif

	uint32_t tx_event_cnt = 0;
	uint32_t tx_fail_cnt = 0;
	uint32_t rx_fifo_cnt = 0;
#ifdef CONFIG_CLOAK
	uint32_t rx_error_cnt = 0;
#endif

	struct main_msg msg;

	while (1) {
		int64_t time_cnt;

		time_cnt = k_uptime_get();

#if !CONFIG_ESB_PTX_DELAY
		fill_tx_fifo();
#endif

		do {
			k_msgq_get(&main_msgq, &msg, K_FOREVER);
			do {
				switch(msg.type) {
				case MAIN_MSG_TX_FAIL:
					tx_fail_cnt += msg.cnt;
				case MAIN_MSG_TX:
					tx_event_cnt += msg.cnt;
#if !CONFIG_ESB_PTX_DELAY
					fill_tx_fifo();
#endif
					break;
#if CONFIG_ESB_PTX_DELAY > 0
				case MAIN_MSG_TIMER:
					fill_tx_fifo();
					break;
#endif
				case MAIN_MSG_RX:
					rx_fifo_cnt += msg.cnt;
					break;
				default:
					break;
				}
			} while (!k_msgq_get(&main_msgq, &msg, K_NO_WAIT));
		} while (tx_event_cnt < CONFIG_ESB_PTX_BATCH_SIZE);

		time_cnt = k_uptime_delta(&time_cnt);

		struct print_msg prt_msg;

		prt_msg.tx_cnt = tx_event_cnt;
		tx_event_cnt = 0;
		prt_msg.tx_fail_cnt = tx_fail_cnt;
		tx_fail_cnt = 0;
		prt_msg.rx_cnt = rx_fifo_cnt;
		rx_fifo_cnt = 0;
		prt_msg.time_cnt = time_cnt;

		err = k_msgq_put(&print_msgq, &prt_msg, K_NO_WAIT);
		if (err) {
			LOG_ERR("Cannot put PTX statistics to message queue");
		}
	}
}
