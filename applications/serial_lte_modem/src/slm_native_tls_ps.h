/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SLM_NATIVE_TLS_PS
#define SLM_NATIVE_TLS_PS

#include <zephyr/types.h>
#include <net/tls_credentials.h>
#if IS_ENABLED(CONFIG_SLM_NATIVE_TLS_PSA)
#include "psa/crypto.h"
#include "psa/error.h"
#endif

/**@file slm_native_tls.h
 *
 * @brief Storage of TLS credentials using PSA Protected Storage API
 * @{
 */

/**
 * @brief Store a TLS credential in Protected Storage
 *
 * @param[in]  sec_tag security tag of the credential
 * @param[in]  type TLS credential type, as used in AT%CMNG
 * @param[in]  buf Buffer containing the credential
 * @param[in]  len Size of the credential
 *
 * @return 0 if successful, negative error code if failure.
 */
int slm_tls_ps_set(sec_tag_t sec_tag, uint16_t type, const void *buf,
		   size_t len);
/**
 * @brief Get a TLS credential from Protected Storage
 *
 * @param[in]  sec_tag security tag of the credential
 * @param[in]  type TLS credential type, as used in AT%CMNG
 * @param[out] buf Buffer in which to write the credential
 * @param[in]  buf_len Size of the buffer
 * @param[out] len Size of the credential
 *
 * @return 0 if successful, negative error code if failure.
 */
int slm_tls_ps_get(sec_tag_t sec_tag, uint16_t type, void *buf, size_t buf_len,
		   size_t *len);
/**
 * @brief Remove a TLS credential from Protected Storage
 *
 * @param[in]  sec_tag security tag of the credential
 * @param[in]  type TLS credential type, as used in AT%CMNG
 *
 * @return 0 if successful, negative error code if failure.
 */
int slm_tls_ps_remove(sec_tag_t sec_tag, uint16_t type);
/**
 * @brief Get a TLS credential table from Protected Storage
 *
 * @param[out] buf Buffer in which to write the credential table
 * @param[out] len Size of the credential table
 *
 * @return 0 if successful, negative error code if failure.
 */
int slm_tls_tbl_get(void *buf, size_t *len);

/**
 * @brief Print TLS credential table from Protected Storage to AT response.
 * *
 */
void slm_tls_tbl_dump(void);
#if IS_ENABLED(CONFIG_SLM_NATIVE_TLS_PSA)
#include "psa/initial_attestation.h"

/** For develop function **/
/** Maximum buffer size for an initial attestation token instance. */
#define ATT_MAX_TOKEN_SIZE (0x240)

/**
 * @brief Gets the public key portion of the attestation service's securely
 *        stored key pair. This public key can be provided to external
 *        verification services for device verification purposes.
 *
 * @return Returns error code as specified in \ref psa_status_t
 */
psa_status_t att_get_pub_key(void);

/**
 * @brief Gets an initial attestation token (IAT) from the TF-M secure
 *        processing environment (SPE). This data will be provided in CBOR
 *        format and is encrypted using the private key held on the SPE.
 *
 * The initial attestation token (IAT) is composed of a series of 'claims' or
 * data points used to uniquely identify this device to an external
 * verification entity (the IAT consumer).
 *
 * The generated IAT should be cryptographically verifiable by the IAT consumer.
 *
 * For details on IAT see https://tools.ietf.org/html/draft-mandyam-eat-01
 *
 * @param ch_buffer     Pointer to the buffer containing the nonce or
 *                      challenge data to be validated with the private key.
 * @param ch_sz         The number of bytes in the challenge. 32, 48 or 64.
 * @param token_buffer  Pointer to the buffer where the IAT will be written.
 *                      Must be equal in size to the system IAT output, which
 *                      can be determined via a call to
 *                      'psa_initial_attest_get_token_size'.
 * @param token_sz      Pointer to the size of token_buffer, this value will be
 *                      updated in this function to contain the number of bytes
 *                      actually retrieved during the IAT request.
 *
 * @return Returns error code as specified in \ref psa_status_t
 */
psa_status_t att_get_iat(uint8_t *ch_buffer, uint32_t ch_sz,
			 uint8_t *token_buffer, uint32_t *token_sz);

/**
 * @brief TODO!
 *
 * @return Returns error code as specified in \ref psa_status_t
 */
psa_status_t att_test(void);
#endif

/** @} */

#endif /* SLM_NATIVE_TLS_PS */
