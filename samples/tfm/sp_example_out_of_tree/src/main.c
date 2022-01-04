/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr.h>
#include <sys/printk.h>
#include <power/reboot.h>

#include "tfm_api.h"
#include "tfm_ns_interface.h"
#include "tfm_example_api.h"
#include "psa/crypto.h"
#include <string.h>

#ifdef TFM_PSA_API
    #include "psa_manifest/sid.h"
#endif

#define I_LIKE_REBOOT
#define ROT_A_TEST_DATA_COUNT 2
const uint8_t GREETING_A_1[] = "str1";
const uint8_t GREETING_A_2[] = "this call is from non-secure happy world to secure world RoT_A";
//this call is from non-secure happy world to secure world RoT_B
const uint8_t GREETING_B[] = {0x74,0x68,0x69,0x73,0x20,0x63,0x61,0x6c,0x6c,0x20,0x69,0x73,0x20,0x66,0x72,0x6f,\
                0x6d,0x20,0x6e,0x6f,0x6e,0x2d,0x73,0x65,0x63,0x75,0x72,0x65,0x20,0x68,0x61,0x70,0x70,\
                0x79,0x20,0x77,0x6f,0x72,0x6c,0x64,0x20,0x74,0x6f,0x20,0x73,0x65,0x63,0x75,0x72,0x65,\
                0x20,0x77,0x6f,0x72,0x6c,0x64,0x20,0x52,0x6f,0x54,0x5f,0x42};
size_t GREETING_B_SIZE = sizeof(GREETING_B)/sizeof(GREETING_B[0]);
const uint8_t GREETING_C[] = "this call is from non-secure happy world to secure world RoT_C";

static void print_hex_number(uint8_t *num, size_t len)
{
	printk("0x");
	for (int i = 0; i < len; i++) {
		printk("%02x", num[i]);
	}
	printk("\n");
}
//IPC MODEL
#if defined(TFM_PSA_API)
static void tfm_example_ipc_test_rot_a(void)
{
    char str3[128], str4[128];
    struct psa_invec invecs[ROT_A_TEST_DATA_COUNT] = {{GREETING_A_1, sizeof(GREETING_A_1)},
                                  {GREETING_A_2, sizeof(GREETING_A_2)}};
    struct psa_outvec outvecs[ROT_A_TEST_DATA_COUNT] = {{str3, sizeof(str3)},
                                    {str4, sizeof(str4)}};
    psa_handle_t handle;
    psa_status_t status;
    uint32_t version;

    version = psa_version(ROT_A_INPUT_OUTPUT_SID);
    printk("TFM service ROT_A_INPUT_OUTPUT 0x%x support version is %d.\r\n", ROT_A_INPUT_OUTPUT_SID, version);
    handle = psa_connect(ROT_A_INPUT_OUTPUT_SID, ROT_A_INPUT_OUTPUT_VERSION);
    if (handle > 0) {
        printk("connected\r\n");
    } else {
		printk("The RoT Service has refused the connection!\n");
		return;
	}
    status = psa_call(handle, PSA_IPC_CALL, invecs, ROT_A_TEST_DATA_COUNT, outvecs, ROT_A_TEST_DATA_COUNT);
    if (status >= 0) {
        printk("psa_call ROT_A is successful!\r\n");
    } else {
        printk("psa_call ROT_A is failed!\r\n");
        return;
    }
    for(uint8_t idx = 0; idx < ROT_A_TEST_DATA_COUNT; idx++) {
        printk("outvec%d is: %s\r\n", idx+1, (char *)outvecs[idx].base);        
    }
        
    psa_close(handle);
    printk("TEST_PASSED tfm_example_ipc_test_rot_a\n");
}
static void tfm_example_ipc_test_rot_b(void)
{
	char str2[DIGEST_SIZE], computed_hash[DIGEST_SIZE];
	struct psa_invec invecs[1] = {
        {.base = GREETING_B, .len = GREETING_B_SIZE}
    };
	struct psa_outvec outvecs[1] = {
        {.base = str2, .len = DIGEST_SIZE}
    };
    psa_handle_t handle;
    psa_status_t status;
    uint32_t version;
    size_t hash_length;

    version = psa_version(ROT_B_CRYPTO_HASH_SID);
    printk("TFM service ROT_B_CRYPTO_RAND_SID 0x%x support version is %d.\r\n", ROT_B_CRYPTO_HASH_SID, version);
    handle = psa_connect(ROT_B_CRYPTO_HASH_SID, ROT_B_CRYPTO_HASH_VERSION);
    if (handle > 0) {
        printk("connected\r\n");
    } else {
		printk("The RoT Service has refused the connection!\n");
		return;
	}    
    status = psa_call(handle, PSA_IPC_CALL, invecs, 1, outvecs, 1);
    if (status >= 0) {
        printk("psa_call ROT_B is successful!\r\n");
    } else {
        printk("psa_call ROT_B is failed!\r\n");
        return;
    }
    printk("rot_b output hash is:\n");
	print_hex_number(outvecs[0].base, outvecs[0].len);
    psa_close(handle);
    status = psa_hash_compute(PSA_ALG_SHA_256,
                        GREETING_B,
                        sizeof(GREETING_B),
                        computed_hash,
                        DIGEST_SIZE,
                        &hash_length);
    printk("psa_hash_compute hash is:\n");
	print_hex_number(computed_hash, DIGEST_SIZE);
    if(memcmp(outvecs[0].base, computed_hash, DIGEST_SIZE) == 0) {
        printk("TEST_PASSED tfm_example_ipc_test_rot_b\n");
    } else {
        printk("TEST_FAILED tfm_example_ipc_test_rot_b\n");
    }    
}

static void tfm_example_ipc_test_rot_c(void)
{
	char str2[DIGEST_SIZE];
	struct psa_outvec outvecs[1] = {
        {.base = str2, .len = DIGEST_SIZE}
    };
    psa_handle_t handle;
    psa_status_t status;
    uint32_t version;

    version = psa_version(ROT_C_CRYPTO_RAND_SID);
    printk("TFM service ROT_C_CRYPTO_RAND_SID 0x%x support version is %d.\r\n", ROT_C_CRYPTO_RAND_SID, version);
    handle = psa_connect(ROT_C_CRYPTO_RAND_SID, ROT_C_CRYPTO_RAND_VERSION);
    if (handle > 0) {
        printk("connected\r\n");
    } else {
		printk("The RoT Service has refused the connection!\n");
		return;
	}    
    status = psa_call(handle, PSA_IPC_CALL, NULL, 0, outvecs, 1);
    if (status >= 0) {
        printk("psa_call ROT_C is successful!\r\n");
    } else {
        printk("psa_call ROT_C is failed!\r\n");
        return;
    }

    printk("rot_c output random number is:\n");
	print_hex_number(outvecs[0].base, outvecs[0].len);
    psa_close(handle);
    printk("TEST_PASSED tfm_example_ipc_test_rot_c\n");
}
#else
static psa_status_t tfm_example_lib_test_rot_a(void)
{
    psa_status_t status ;    
    uint8_t str3[128], str4[128];
    const uint8_t *in_data[ROT_A_TEST_DATA_COUNT] = {GREETING_A_1, GREETING_A_2};
    uint8_t *out_data[ROT_A_TEST_DATA_COUNT] = {str3, str4};
    size_t in_data_len[ROT_A_TEST_DATA_COUNT] = {sizeof(GREETING_A_1), sizeof(GREETING_A_2)};
    size_t out_data_len[ROT_A_TEST_DATA_COUNT] = {sizeof(str3), sizeof(str4)};

    printk("%s\n",__func__);
    status = rot_a_input_output(in_data, in_data_len,
                        out_data, out_data_len,
                        ROT_A_TEST_DATA_COUNT);
    
    for(uint8_t idx = 0; idx < ROT_A_TEST_DATA_COUNT; idx++) {
        printk("outvec%d is: %s\r\n", idx+1, out_data[idx]);        
    }
    if(status == PSA_SUCCESS){
        printk("TEST_PASSED tfm_example_lib_test_rot_a\n");
    }
    return status;
}

static psa_status_t tfm_example_lib_test_rot_b(void)
{
    psa_status_t status ;
	uint8_t str2[DIGEST_SIZE],	computed_hash[DIGEST_SIZE];
    size_t hash_length;

    printk("%s\n",__func__);
    status = rot_b_crypto_hash(GREETING_B, GREETING_B_SIZE, str2);
    if(status == PSA_SUCCESS) {
        print_hex_number(str2, DIGEST_SIZE);
    }
    status = psa_hash_compute(PSA_ALG_SHA_256,
                        GREETING_B,
                        sizeof(GREETING_B),
                        computed_hash,
                        DIGEST_SIZE,
                        &hash_length);
    printk("psa_hash_compute hash is:\n");
	print_hex_number(computed_hash, DIGEST_SIZE);
    if(memcmp(str2, computed_hash, DIGEST_SIZE) == 0) {
        printk("TEST_PASSED tfm_example_ipc_test_rot_b\n");
    } else {
        printk("TEST_FAILED tfm_example_ipc_test_rot_b\n");
    }    

    return status;
}
static psa_status_t tfm_example_lib_test_rot_c(void)
{
    psa_status_t status ;
	char str2[DIGEST_SIZE];    

    printk("%s\n",__func__);
    status = rot_c_crypto_rand(str2);
    if(status == PSA_SUCCESS) {
        print_hex_number(str2, DIGEST_SIZE);
    }
    if(status == PSA_SUCCESS) {
        printk("TEST_PASSED tfm_example_lib_test_rot_c\n");
    }
    return status;
}

#endif
void main(void)
{
	psa_crypto_init();
#ifdef TFM_PSA_API
	printk("TF-M IPC on %s\n", CONFIG_BOARD);
	tfm_example_ipc_test_rot_a();
	tfm_example_ipc_test_rot_b();
	tfm_example_ipc_test_rot_c();
#else
	printk("TF-M LIB on %s\n", CONFIG_BOARD);
    tfm_example_lib_test_rot_a();
    tfm_example_lib_test_rot_b();
    tfm_example_lib_test_rot_c();
#endif

#if defined(I_LIKE_REBOOT)
    uint8_t count = 5;
	printk("Wait 5 seconds before reset\n");
    while(count) {
        printk("%d\n", count--);
        k_sleep(K_MSEC(1000));
    }	
	sys_reboot(0);
#endif	
}
