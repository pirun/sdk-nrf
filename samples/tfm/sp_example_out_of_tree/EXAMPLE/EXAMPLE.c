/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <assert.h>
#include <stdio.h>

#include "tfm_sp_log.h"
#include "psa_manifest/tfm_example.h"
#include "psa/crypto.h"
#include "tfm_crypto_defs.h"
#include "tfm_memory_utils.h"
#ifdef TFM_PSA_API
#include "tfm_spm_log.h"
#include "psa/service.h"
#endif

#define DIGEST_SIZE 32
#define BUFFER_LEN 100

#define ROT_A_SEND_TEMPLATE " Hello World outvec"
psa_status_t rot_a_operation(void *in_data, size_t data_len , void *out_data)
{
    psa_status_t r = PSA_SUCCESS;

    LOG_DBGFMT("%s\r\n",__func__);
    (void)tfm_memcpy(out_data, in_data, data_len);
    (void)tfm_memcpy((out_data + data_len - 1), ROT_A_SEND_TEMPLATE, sizeof(ROT_A_SEND_TEMPLATE));
    return r;
}

psa_status_t rot_b_operation(void *in_data, size_t in_data_size, void *out_data)
{
    size_t hash_length;
    psa_status_t r;
    //try hash something here
    LOG_DBGFMT("%s\r\n",__func__);

    r = psa_hash_compute(PSA_ALG_SHA_256,
                        in_data,
                        in_data_size,
                        out_data,
                        DIGEST_SIZE,
                        &hash_length);
    if(r != PSA_SUCCESS) {
        LOG_DBGFMT("psa_hash_compute failed %d\r\n", r);
    }
    return r ;
}

psa_status_t rot_c_operation(void *out_data, size_t out_size)
{
    psa_status_t r;

    LOG_DBGFMT("%s\r\n",__func__);    
    r = psa_generate_random(out_data, out_size);
    if(r != PSA_SUCCESS) {
        LOG_DBGFMT("rot_c_operation\r\npsa_generate_random failed %d\r\n", r);
    }
}
#if !defined(TFM_PSA_API)
//secure library mode
psa_status_t rot_a_input_output_req(psa_invec *in_vec, size_t in_len,
                            psa_outvec *out_vec, size_t out_len)
{
    psa_status_t status = PSA_SUCCESS;
    int16_t idx;

    LOG_DBGFMT("%s\r\n", __func__);
    for(idx = 0; idx < in_len ;idx++) {
	    status = rot_a_operation((void *)in_vec[idx].base, in_vec[idx].len, (void *)out_vec[idx].base);
        if(status != PSA_SUCCESS) {
            LOG_ERRFMT("rot_a_operation failed @%d\r\n", idx);
            break;
        }
    }
    return status;
}
psa_status_t rot_b_crypto_hash_req(psa_invec *in_vec, size_t in_len,
                            psa_outvec *out_vec, size_t out_len)
{
    psa_status_t status = PSA_SUCCESS;
	size_t in_data_len;

    LOG_DBGFMT("%s\r\n", __func__);

	if ((in_len != 1) || (out_len != 1)) {
		/* The number of arguments are incorrect */
		return PSA_ERROR_PROGRAMMER_ERROR;
	}
	in_data_len = in_vec[0].len;

    LOG_DBGFMT("in_data_len %d", in_data_len);
	status = rot_b_operation((void *)in_vec[0].base, in_data_len,
				    (void *)out_vec[0].base);
    return status;    
}
psa_status_t rot_c_crypto_rand_req(psa_invec *in_vec, size_t in_len,
                            psa_outvec *out_vec, size_t out_len)
{
    psa_status_t status = PSA_SUCCESS;
    LOG_DBGFMT("%s\r\n", __func__);

    status = rot_c_operation((void *)out_vec[0].base, out_vec[0].len);

    return status;
}
#else
/* Define the whether the service is inuse flag. */
static uint32_t service_in_use = 0;
typedef psa_status_t (*example_func_t)(void);
static psa_msg_t msg;

static void example_signal_handle(psa_signal_t signal, example_func_t pfn)
{
    psa_status_t status;

    status = psa_get(signal, &msg);
    switch (msg.type) {
    case PSA_IPC_CONNECT:
        LOG_INFFMT("example_signal_handle PSA_IPC_CONNECT\r\n");
        if (service_in_use & signal) {
            status = PSA_ERROR_CONNECTION_REFUSED;
        } else {
            service_in_use |= signal;
            status = PSA_SUCCESS;
        }        
        psa_reply(msg.handle, PSA_SUCCESS);
        LOG_INFFMT("example_signal_handle replay after PSA_IPC_CONNECT\r\n");
        break;
    case PSA_IPC_CALL:
        LOG_INFFMT("example_signal_handle PSA_IPC_CALL\r\n");
        status = pfn();
        LOG_INFFMT("example_signal_handle psa_reply\r\n");
        psa_reply(msg.handle, status);
        break;
    case PSA_IPC_DISCONNECT:
        LOG_INFFMT("example_signal_handle PSA_IPC_DISCONNECT\r\n");
        assert((service_in_use & signal) != 0);
        service_in_use &= ~signal;
        psa_reply(msg.handle, PSA_SUCCESS);
        break;
    default:
        psa_panic();
    }
}

//This is a simple input/output communication between non-secure and secure world.
//This function only handle PSA_IPC_CALL.
//The other signals are handled by example_signal_handle.
static psa_status_t rot_A_by_handle_ipc(void)
{
    uint8_t idx;
    uint8_t rec_buf[BUFFER_LEN];
    char send_buf[BUFFER_LEN];
    size_t rec_len;

    LOG_DBGFMT("rot_A call by signal handle\r\n");
    for (idx = 0; idx < PSA_MAX_IOVEC; idx++) {
        if (msg.in_size[idx] != 0) {
            rec_len = psa_read(msg.handle, idx, rec_buf, BUFFER_LEN);
            LOG_DBGFMT("rot_A read from non-secure world:\r\n%s count %d\r\n", rec_buf, rec_len);
        }
        if (msg.out_size[idx] != 0) {
            rot_a_operation(rec_buf, rec_len , send_buf);
            psa_write(msg.handle, idx, send_buf, BUFFER_LEN);
        }
    }
    return PSA_SUCCESS;
}

static psa_status_t rot_B_by_handle_ipc(void)
{
    uint8_t idx;
    uint8_t rec_buf[BUFFER_LEN];
    char send_buf[DIGEST_SIZE];
    size_t rec_len;

    LOG_DBGFMT("rot_B call by signal handle\r\n");
    for (idx = 0; idx < PSA_MAX_IOVEC; idx++) {
        if (msg.in_size[idx] != 0) {
            rec_len = psa_read(msg.handle, idx, rec_buf, BUFFER_LEN);
            LOG_DBGFMT("rot_B read from non-secure world:\r\n%s count %d\r\n", rec_buf, rec_len);
            rot_b_operation(rec_buf, rec_len, send_buf);
            LOG_DBGFMT("rot_B hash %x\r\n",send_buf);
        }
        if (msg.out_size[idx] != 0) {                
            psa_write(msg.handle, idx, send_buf, DIGEST_SIZE);
        }
    }

    return PSA_SUCCESS;
}
static psa_status_t rot_C_by_handle_ipc(void)
{    
    uint8_t idx;
	uint8_t random_bytes[DIGEST_SIZE];

    LOG_DBGFMT("rot_C call by signal handle\r\n");
    for (idx = 0; idx < PSA_MAX_IOVEC; idx++) {
        if (msg.out_size[idx] != 0) {
            rot_c_operation(random_bytes, DIGEST_SIZE);
            psa_write(msg.handle, idx, random_bytes, DIGEST_SIZE);
        }
    }
    return PSA_SUCCESS;
}

#endif //TFM_PSA_API

psa_status_t example_main()
{
    LOG_DBGFMT("Custom service this_hello entry main\r\n");
#ifdef TFM_PSA_API
    psa_signal_t signals = 0;
    SPMLOG_INFMSG("Custom service this_hello entry main\r\n");
    SPMLOG_INFMSG("Custom service IPC MODE\r\n");
    //In IPC mode , we need a infinite loop to handle incoming signal
    while (1) {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
        if (signals & ROT_A_INPUT_OUTPUT_SIGNAL) {
            //pass to handle
            example_signal_handle(ROT_A_INPUT_OUTPUT_SIGNAL, rot_A_by_handle_ipc);
        } else if (signals & ROT_B_CRYPTO_HASH_SIGNAL) {
            //pass to handle
            example_signal_handle(ROT_B_CRYPTO_HASH_SIGNAL, rot_B_by_handle_ipc);
        } else if (signals & ROT_C_CRYPTO_RAND_SIGNAL) {
            example_signal_handle(ROT_C_CRYPTO_RAND_SIGNAL, rot_C_by_handle_ipc);
        } else {
            /* Should not come here */
            psa_panic();
        }
    }    
#else
    LOG_DBGFMT("Custom service secure library MODE\r\n");
    return PSA_SUCCESS;
#endif
}
