/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/net/socket.h>
#include <modem/modem_info.h>
#include <modem/modem_key_mgmt.h>
#include "slm_util.h"
#include "slm_native_tls.h"
#include "slm_at_host.h"
#include "slm_at_cmng.h"
#include "slm_native_tls_ps.h"

LOG_MODULE_REGISTER(slm_cmng, CONFIG_SLM_LOG_LEVEL);

/**@brief List of supported opcode */
enum slm_cmng_opcode {
	AT_CMNG_OP_WRITE,
	AT_CMNG_OP_LIST,
	AT_CMNG_OP_READ,
	AT_CMNG_OP_DELETE
};

/**@brief List of supported type */
enum slm_cmng_type {
	AT_CMNG_TYPE_CA_CERT,
	AT_CMNG_TYPE_CERT,
	AT_CMNG_TYPE_PRIV,
	AT_CMNG_TYPE_PSK,
	AT_CMNG_TYPE_PSK_ID,
	AT_CMNG_TYPE_ENDORSEMENT_KEY = 8,
	AT_CMNG_TYPE_NORDIC_ROOT_CA = 10,
	AT_CMNG_TYPE_NORDIC_BASE_PUBKEY = 11,
};

/* global variable defined in different files */
extern struct at_param_list at_param_list;
extern char rsp_buf[SLM_AT_CMD_RESPONSE_MAX_LEN];

/**@brief handle AT#XCMNG commands
 *  AT#XCMNG=<opcode>[,<sec_tag>[,<type>[,<content>]]]
 *  AT#XCMNG? READ command not supported
 *  AT#XCMNG=? READ command not supported
 */
int handle_at_xcmng(enum at_cmd_type cmd_type)
{
	int err = -EINVAL;
	uint16_t op, type;
	nrf_sec_tag_t sec_tag;
	uint8_t *content;
	size_t len = SLM_AT_CMD_RESPONSE_MAX_LEN;

	switch (cmd_type) {
	case AT_CMD_TYPE_SET_COMMAND:
		if (at_params_valid_count_get(&at_param_list) < 2) {
			LOG_ERR("Parameter missed");
			return -EINVAL;
		}
		err = at_params_unsigned_short_get(&at_param_list, 1, &op);
		if (err < 0) {
			LOG_ERR("Fail to get op parameter: %d", err);
			return err;
		}
		if (op > AT_CMNG_OP_DELETE) {
			LOG_ERR("Wrong XCMNG operation: %d", op);
			return -EPERM;
		}
		if (op == AT_CMNG_OP_LIST) {
		#if defined(CONFIG_SLM_NATIVE_TLS_PS)
			slm_tls_tbl_dump();
			return 0;
		#else
			/* Currently not support list command */
			LOG_ERR("XCMNG List is not supported");
			return -EPERM;
		#endif
		}
		if (at_params_valid_count_get(&at_param_list) < 4) {
			/* READ, WRITE, DELETE requires sec_tag and type */
			LOG_ERR("Parameter missed");
			return -EINVAL;
		}
		err = at_params_unsigned_int_get(&at_param_list, 2, &sec_tag);
		if (err < 0) {
			LOG_ERR("Fail to get sec_tag parameter: %d", err);
			return err;
		};
		if (sec_tag > MAX_SLM_SEC_TAG) {
			LOG_ERR("Invalid security tag: %d", sec_tag);
			return -EINVAL;
		}
		err = at_params_unsigned_short_get(&at_param_list, 3, &type);
		if (err < 0) {
			LOG_ERR("Fail to get type parameter: %d", err);
			return err;
		};
		if (op == AT_CMNG_OP_WRITE) {
			if (at_params_valid_count_get(&at_param_list) < 5) {
				/* WRITE requires sec_tag, type and content */
				LOG_ERR("Parameter missed");
				return -EINVAL;
			}
			content = k_malloc(SLM_AT_CMD_RESPONSE_MAX_LEN);
			err = util_string_get(&at_param_list, 4, content,
						   &len);
			if (err != 0) {
				LOG_ERR("Failed to get content");
				k_free(content);
				return err;
			}
			err = slm_tls_storage_set(sec_tag, type, content, len);
			if (err != 0) {
#if defined(CONFIG_SLM_NATIVE_TLS_PS)
				LOG_ERR("FAILED! slm_tls_ps_set() = %d", err);
#else
				LOG_ERR("FAILED! modem_key_mgmt_write() = %d", err);
#endif
			}
			k_free(content);
		} else if (op == AT_CMNG_OP_READ) {
			if (type == AT_CMNG_TYPE_CERT ||
			   type == AT_CMNG_TYPE_PRIV ||
			   type == AT_CMNG_TYPE_PSK ||
			   type == AT_CMNG_TYPE_NORDIC_ROOT_CA) {
				/* Not supported */
				LOG_ERR("Not support READ for type: %d", type);
				return -EPERM;
			}
			content = k_malloc(SLM_AT_CMD_RESPONSE_MAX_LEN);
			err = slm_tls_storage_get(sec_tag, type, content,
					SLM_AT_CMD_RESPONSE_MAX_LEN,
					&len);
			if (err != 0) {
#if defined(CONFIG_SLM_NATIVE_TLS_PS)
				LOG_ERR("FAILED! slm_tls_ps_get() = %d", err);
#else
				LOG_ERR("FAILED! modem_key_mgmt_read() = %d", err);
#endif
			} else {
				*(content + len) = '\0';
				sprintf(rsp_buf, "%%CMNG: %d,%d,\"\","
					"\"%s\"\r\n", sec_tag, type, content);
				rsp_send(rsp_buf, strlen(rsp_buf));
			}
			k_free(content);
		} else if (op == AT_CMNG_OP_DELETE) {
			err = slm_tls_storage_remove(sec_tag, type);
#if defined(CONFIG_SLM_NATIVE_TLS_PS)
				LOG_ERR("FAILED! slm_tls_ps_remove() = %d", err);
#else
				LOG_ERR("FAILED! modem_key_mgmt_delete() = %d",	err);
#endif
		}
		break;
	default:
		break;
	}

	return err;
}
int handle_at_tfm_attest(enum at_cmd_type cmd_type)
{
	uint16_t op, type;
	nrf_sec_tag_t sec_tag;

	switch (cmd_type) {
	case AT_CMD_TYPE_SET_COMMAND:
		/* Get the entity attestation token (requires ~1kB stack memory!). */
		att_test();
		break;
	case AT_CMD_TYPE_TEST_COMMAND:
		break;
	case AT_CMD_TYPE_READ_COMMAND:
		break;
	default:
		break;
	}
}
int handle_at_tfm_private(enum at_cmd_type cmd_type)
{
	uint16_t op, type;
	nrf_sec_tag_t sec_tag;

	switch (cmd_type) {
	case AT_CMD_TYPE_SET_COMMAND:
		break;
	case AT_CMD_TYPE_TEST_COMMAND:
		break;
	case AT_CMD_TYPE_READ_COMMAND:
		break;
	default:
		break;
	}
}

/**@brief API to initialize CMNG AT commands handler
 */
int slm_at_cmng_init(void)
{
#if defined(CONFIG_SLM_NATIVE_TLS_PSA)
	psa_status_t status;

	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		LOG_ERR("Crypto init failed.");
		goto err;
	}
	LOG_INF("PSA crypto init completed");
#endif
err:
	return 0;
}

/**@brief API to uninitialize CMNG AT commands handler
 */
int slm_at_cmng_uninit(void)
{
	return 0;
}
