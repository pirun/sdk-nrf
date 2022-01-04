/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "psa/client.h"
#include "tfm_ns_interface.h"
#include "tfm_api.h"
#include "tfm_psa_call_param.h"
#include "tfm_veneers.h"
#ifdef TFM_PSA_API
#include "psa_manifest/sid.h"
#endif
#include "tfm_example_api.h"
/**** API functions ****/
psa_status_t rot_a_input_output(const uint8_t **in_data,
                        size_t *in_data_len,
                        const uint8_t **out_data,
                        size_t *out_data_len,
                        size_t data_count)
{
    psa_status_t status;
#ifdef TFM_PSA_API
    psa_handle_t handle;
#endif
    int16_t idx;
    psa_invec in_vecs[data_count];
    psa_outvec out_vecs[data_count];

    for(idx = 0 ; idx < data_count; idx++ ) {
        in_vecs[idx].base = in_data[idx];
        in_vecs[idx].len = in_data_len[idx];
        out_vecs[idx].base = out_data[idx];
        out_vecs[idx].len = out_data_len[idx];            
    }
#ifdef TFM_PSA_API
    handle = psa_connect(ROT_A_INPUT_OUTPUT_SID, ROT_A_INPUT_OUTPUT_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    status = psa_call(handle, PSA_IPC_CALL, in_vecs, IOVEC_LEN(in_vecs),
                      out_vecs, IOVEC_LEN(out_vecs));

    psa_close(handle);

#else
     status = tfm_ns_interface_dispatch(
	 			(veneer_fn)tfm_rot_a_input_output_req_veneer,
	 			(uint32_t)in_vecs,  IOVEC_LEN(in_vecs),
	 			(uint32_t)out_vecs, IOVEC_LEN(out_vecs));
    /* A parameter with a buffer pointer pointer that has data length longer
     * than maximum permitted is treated as a secure violation.
     * TF-M framework rejects the request with TFM_ERROR_INVALID_PARAMETER.
     */
    if (status == (psa_status_t)TFM_ERROR_INVALID_PARAMETER) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif

    return status;
}

/**** API functions ****/
psa_status_t rot_b_crypto_hash(const void *in_data,
                        size_t in_data_len,
                        const void *out_data)
{
    psa_status_t status;
#ifdef TFM_PSA_API
    psa_handle_t handle;
#endif
    psa_invec in_vecs[] = {
        { .base = in_data, .len = in_data_len}
    };
    psa_outvec out_vecs[] = {
        { .base = out_data, .len = DIGEST_SIZE}
    };
#ifdef TFM_PSA_API
    handle = psa_connect(ROT_B_CRYPTO_HASH_SID, ROT_B_CRYPTO_HASH_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    status = psa_call(handle, PSA_IPC_CALL, in_vecs, IOVEC_LEN(in_vecs),
                      out_vecs, IOVEC_LEN(out_vecs));

    psa_close(handle);

#else
    status = tfm_ns_interface_dispatch(
				(veneer_fn)tfm_rot_b_crypto_hash_req_veneer,
				(uint32_t)in_vecs,  IOVEC_LEN(in_vecs),
				(uint32_t)out_vecs, IOVEC_LEN(out_vecs));
	return status;

    /* A parameter with a buffer pointer pointer that has data length longer
     * than maximum permitted is treated as a secure violation.
     * TF-M framework rejects the request with TFM_ERROR_INVALID_PARAMETER.
     */
    if (status == (psa_status_t)TFM_ERROR_INVALID_PARAMETER) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif

    return status;
}
/**** API functions ****/
psa_status_t rot_c_crypto_rand(const void *out_data)
{
    psa_status_t status;
#ifdef TFM_PSA_API
    psa_handle_t handle;
#endif
    psa_outvec out_vecs[] = {
        { .base = out_data, .len = DIGEST_SIZE}
    };
#ifdef TFM_PSA_API
    handle = psa_connect(ROT_C_CRYPTO_RAND_SID, ROT_C_CRYPTO_RAND_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    status = psa_call(handle, PSA_IPC_CALL, NULL, 0,
                      out_vecs, IOVEC_LEN(out_vecs));

    psa_close(handle);

#else
    status = tfm_ns_interface_dispatch(
				(veneer_fn)tfm_rot_c_crypto_rand_req_veneer,
				NULL,  0,
				(uint32_t)out_vecs, IOVEC_LEN(out_vecs));
	return status;

    /* A parameter with a buffer pointer pointer that has data length longer
     * than maximum permitted is treated as a secure violation.
     * TF-M framework rejects the request with TFM_ERROR_INVALID_PARAMETER.
     */
    if (status == (psa_status_t)TFM_ERROR_INVALID_PARAMETER) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif

    return status;
}