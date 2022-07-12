/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include "slm_defines.h"
#include "slm_native_tls_ps.h"
#include "slm_native_tls.h"
#include <logging/log.h>
#include <psa/protected_storage.h>
#include <stdio.h>
#include <zephyr/zephyr.h>

LOG_MODULE_REGISTER(slm_tls_ps, CONFIG_SLM_LOG_LEVEL);

/* global functions defined in different files */
void rsp_send(const uint8_t *str, size_t len);

/* global variable defined in different files */
extern struct at_param_list at_param_list;
extern char rsp_buf[SLM_AT_CMD_RESPONSE_MAX_LEN];

/* Most significant 32 bits of UID for TLS credentials with type 0 (arbitrary)*/
#define SLM_TLS_PS_BASE 0x140DCAF0ULL
#define SLM_TLS_TBL_UUID	0xD98A7DBBB4DCBF2CULL

/* Conversion from type and sec_tag to 64-bit UID */
#define SLM_TLS_PS_UID(type, sec_tag) \
	(((SLM_TLS_PS_BASE + type) << 32) + sec_tag)

#define SLM_TLS_TYPE_LENGTH (2)
#define SLM_TLS_TBL_MAX_SIZE (NATIVE_TLS_SEC_TAG_COUNT * SLM_TLS_TYPE_LENGTH)
#define SLM_SEC_TAG_TO_SLOT(sec_tag, type) \
	((sec_tag - MIN_NATIVE_TLS_SEC_TAG) * SLM_TLS_TYPE_LENGTH + ((type > UINT8_MAX) ? 1:0))
#define SLM_SLOT_TO_SEC_TAG(slot) \
	((slot/SLM_TLS_TYPE_LENGTH) + MIN_NATIVE_TLS_SEC_TAG)
#define SLM_TLS_PSA_CREDENTIAL_TYPE_MAX (16)
/* pointer to credential table buffer */
static uint8_t *crdl_tbl;

/* Return corresponding error code for PSA Protected Storage statuses */
static int translate_status(psa_status_t status)
{
	switch (status) {
	case PSA_SUCCESS:
		return 0;
	case PSA_ERROR_NOT_PERMITTED:
		return -EPERM;
	case PSA_ERROR_INVALID_ARGUMENT:
		return -EINVAL;
	case PSA_ERROR_NOT_SUPPORTED:
		return -ENOTSUP;
	case PSA_ERROR_INSUFFICIENT_STORAGE:
		return -ENOSPC;
	case PSA_ERROR_DOES_NOT_EXIST:
		return -ENOENT;
	case PSA_ERROR_STORAGE_FAILURE:
	case PSA_ERROR_DATA_CORRUPT:
	case PSA_ERROR_INVALID_SIGNATURE:
	case PSA_ERROR_GENERIC_ERROR:
	default:
		return -EIO;
	}

	/* Unreachable */
	return status;
}
/* Conversion from type and sec_tag to SLM_TLS_TBL_MAX_SIZE bytes bitmask */
static inline void SLM_TLS_TBL_MAP(char *buf, sec_tag_t sec_tag, uint16_t type, bool set)
{
	int16_t slot = SLM_SEC_TAG_TO_SLOT(sec_tag, type);

	if (type >= 8) {
		WRITE_BIT(buf[slot + 1], (type % 8), set);
	} else {
		WRITE_BIT(buf[slot], type, set);
	}
}
void slm_tls_tbl_dump(void)
{
	size_t len;
	psa_status_t status;
	sec_tag_t sec_tag;
	uint16_t type;
	char xrsp_buf[32];

	crdl_tbl = k_malloc(SLM_TLS_TBL_MAX_SIZE);
	status = slm_tls_tbl_get(crdl_tbl, &len);
	if (status != PSA_SUCCESS) {
		LOG_ERR("get psa tbl failed %d", status);
	} else {
		LOG_DBG("slm_tls_tbl_get %d", len);
		for (int i = 0; i < SLM_TLS_TBL_MAX_SIZE;) {
			if (crdl_tbl[i] != 0 || crdl_tbl[i+1] != 0) {
				sec_tag = SLM_SLOT_TO_SEC_TAG(i);
				type = (crdl_tbl[i+1] << 8) | (crdl_tbl[i]);
				for (uint8_t j = 0; j < UINT8_MAX; j++) {
					if (type & BIT(j)) {
						sprintf(xrsp_buf, "#XCMNG: %u,%u\r\n", sec_tag, j);
						rsp_send(xrsp_buf, strlen(xrsp_buf));
					}
				}
			}
			i += SLM_TLS_TYPE_LENGTH;
		}
	}

	k_free(crdl_tbl);
}
int slm_tls_tbl_get(void *buf, size_t *len)
{
	psa_status_t status;

	status = psa_ps_get(SLM_TLS_TBL_UUID, 0, SLM_TLS_TBL_MAX_SIZE, buf, len);

	if (status != PSA_SUCCESS) {
		LOG_ERR("Could not get credential table. Error %d", status);
	}
	return translate_status(status);
}
static int slm_tls_tbl_set(sec_tag_t sec_tag, uint16_t type, bool set)
{
	psa_status_t status;
	struct psa_storage_info_t info;
	psa_storage_create_flags_t flags = 0;
	size_t len = SLM_TLS_TBL_MAX_SIZE;

	if (type >= SLM_TLS_PSA_CREDENTIAL_TYPE_MAX) {
		return -ENOTSUP;
	}
	crdl_tbl = k_malloc(SLM_TLS_TBL_MAX_SIZE);
	if (crdl_tbl == NULL) {
		LOG_ERR("Fail to allocate slm cred table memory");
		return -ENOMEM;
	}
	memset(crdl_tbl, 0, SLM_TLS_TBL_MAX_SIZE);

	status = psa_ps_get_info(SLM_TLS_TBL_UUID, &info);

	if (status == PSA_SUCCESS) {
		status = slm_tls_tbl_get(crdl_tbl, &len);
	}
	status = psa_ps_remove(SLM_TLS_TBL_UUID);
	SLM_TLS_TBL_MAP(crdl_tbl, sec_tag, type, set);
	status = psa_ps_set(SLM_TLS_TBL_UUID, SLM_TLS_TBL_MAX_SIZE, crdl_tbl, flags);
	k_free(crdl_tbl);
	if (status != PSA_SUCCESS) {
		LOG_ERR("final set cred table status %d\n", status);
	}
	return translate_status(status);
}

int slm_tls_ps_set(sec_tag_t sec_tag, uint16_t type, const void *buf,
		   size_t len)
{
	psa_status_t status;
	psa_storage_uid_t uid;
	psa_storage_create_flags_t flags = 0;

	uid = SLM_TLS_PS_UID(type, sec_tag);

	if (IS_ENABLED(CONFIG_SLM_NATIVE_TLS_PS_WRITE_ONCE)) {
		flags |= PSA_STORAGE_FLAG_WRITE_ONCE;
	} else {
		status = psa_ps_remove(uid);
	}
	status = psa_ps_set(uid, len, buf, flags);

	if (status != PSA_SUCCESS) {
		LOG_ERR("Could not set credential. Error %d", status);
		(void)slm_tls_tbl_set(sec_tag, type, false);
	} else {
		status = slm_tls_tbl_set(sec_tag, type, true);
		if (status != PSA_SUCCESS) {
			status = psa_ps_remove(uid);
		}
	}

	return translate_status(status);
}

int slm_tls_ps_get(sec_tag_t sec_tag, uint16_t type, void *buf, size_t buf_len,
		   size_t *len)
{
	psa_status_t status;
	psa_storage_uid_t uid;

	uid = SLM_TLS_PS_UID(type, sec_tag);
	status = psa_ps_get(uid, 0, buf_len, buf, len);

	if (status != PSA_SUCCESS) {
		LOG_ERR("Could not get credential. Error %d", status);
	}

	return translate_status(status);
}

int slm_tls_ps_remove(sec_tag_t sec_tag, uint16_t type)
{
	psa_status_t status;
	psa_storage_uid_t uid;

	uid = SLM_TLS_PS_UID(type, sec_tag);
	status = psa_ps_remove(uid);

	if (status != PSA_SUCCESS) {
		LOG_ERR("Could not remove credential. Error %d", status);
	}
	slm_tls_tbl_set(sec_tag, type, false);

	return translate_status(status);
}
psa_status_t att_get_pub_key(void)
{
	psa_status_t err = PSA_SUCCESS;

	/* TODO: How to retrieve this?!? */

	/* Log any eventual errors via app_log */
	return err;
}

psa_status_t att_get_iat(uint8_t *ch_buffer, uint32_t ch_sz,
			 uint8_t *token_buffer, uint32_t *token_sz)
{
	psa_status_t err = PSA_SUCCESS;
	uint32_t sys_token_sz;
	size_t token_buf_size = ATT_MAX_TOKEN_SIZE;


	/* Call with bigger challenge object than allowed */

	/*
	 * First determine how large the token is on this system.
	 * We don't need to compare with the size of ATT_MAX_TOKEN_SIZE here
	 * since a check will be made in 'psa_initial_attest_get_token' and the
	 * error return code will indicate a mismatch.
	 */
	switch (ch_sz) {
	case 32:
		err = psa_initial_attest_get_token(
			ch_buffer,
			PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32,
			token_buffer,
			token_buf_size,
			&sys_token_sz);
		break;
	case 48:
		err = psa_initial_attest_get_token(
			ch_buffer,
			PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48,
			token_buffer,
			token_buf_size,
			&sys_token_sz);
		break;
	case 64:
		err = psa_initial_attest_get_token(
			ch_buffer,
			PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64,
			token_buffer,
			token_buf_size,
			&sys_token_sz);
		break;
	default:
		err = -EINVAL;
		break;
	}
	if (err) {
		goto err;
	}

	LOG_INF("att: System IAT size is: %u bytes.", sys_token_sz);

	/* Request the initial attestation token w/the challenge data. */
	LOG_INF("att: Requesting IAT with %u byte challenge.", ch_sz);
	err = psa_initial_attest_get_token(
		ch_buffer,      /* Challenge/nonce input buffer. */
		ch_sz,          /* Challenge size (32, 48 or 64). */
		token_buffer,   /* Token output buffer. */
		token_buf_size,
		token_sz        /* Post exec output token size. */
		);
	LOG_INF("att: IAT data received: %u bytes.", *token_sz);

err:
	/* Log any eventual errors via app_log */
	return err;
}

psa_status_t att_test(void)
{
	psa_status_t err = PSA_SUCCESS;

	/* 64-byte nonce/challenge, encrypted using the default public key;
	 *
	 * 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
	 * 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
	 * 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
	 * 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
	 */
	uint32_t nonce_sz = 64;
	uint8_t nonce_buf[ATT_MAX_TOKEN_SIZE] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0
	};

	/* IAT response buffer. */
	uint32_t iat_sz = ATT_MAX_TOKEN_SIZE;
	uint8_t iat_buf[ATT_MAX_TOKEN_SIZE] = { 0 };

	// /* String format output config. */
	//	struct sf_hex_tbl_fmt fmt = {
	//	.ascii = true,
	//	.addr_label = true,
	//	.addr = 0
	//	};

	/* Request the IAT from the initial attestation service. */
	err = att_get_iat(nonce_buf, nonce_sz, iat_buf, &iat_sz);
	if (err) {
		goto err;
	}

	/* Display queued log messages before dumping the IAT. */
	//al_dump_log();

	/* Dump the IAT for debug purposes. */
	//sf_hex_tabulate_16(&fmt, iat_buf, (size_t)iat_sz);

err:
	return err;
}
