/*
 * Copyright (c) 2019,2020, 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <sys/printk.h>
#include <power/reboot.h>

#include "tfm_api.h"
#include "tfm_ns_interface.h"
#ifdef TFM_PSA_API
    #include "psa_manifest/sid.h"
#else
    #include "psa/tfm_example.h"
#endif
//#define I_LIKE_REBOOT

static void print_hex_number(uint8_t *num, size_t len)
{
	printk("0x");
	for (int i = 0; i < len; i++) {
		printk("%02x", num[i]);
	}
	printk("\n");
}
#if !defined(TFM_PSA_API)
static psa_status_t tfm_example_lib_test_rot_a(void)
{
    psa_status_t status ;
    // psa_status_t rot_a_input_output(const void **in_data,
    //                     size_t in_data_count,
    //                     const void **out_data,
    //                     size_t out_data_count)
    
    char str1[] = "str1";
    char str2[] = "this call is from non-secure happy world to secure world RoT_A";
    char str3[128], str4[128];
    char *in_data = {str1, str2};
    char *out_data = {str3, str4};

    printk("%s\n",__func__);
    status = rot_a_input_output(in_data, 2, out_data, 2);
    printk("status %d\n", status);
    return status;
}
#else
static void tfm_example_ipc_test_rot_a()
{
    char str1[] = "str1";
    char str2[] = "this call is from non-secure happy world to secure world RoT_A";
    char str3[128], str4[128];
    struct psa_invec invecs[2] = {{str1, sizeof(str1)},
                                  {str2, sizeof(str2)}};
    struct psa_outvec outvecs[2] = {{str3, sizeof(str3)},
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
    status = psa_call(handle, PSA_IPC_CALL, invecs, 2, outvecs, 2);
    if (status >= 0) {
        printk("psa_call ROT_A is successful!\r\n");
    } else {
        printk("psa_call ROT_A is failed!\r\n");
        return;
    }

    printk("outvec1 is: %s\r\n", outvecs[0].base);
    printk("outvec2 is: %s\r\n", outvecs[1].base);
    psa_close(handle);
    printk("TEST_PASSED tfm_example_ipc_test_rot_a\n");
}
static void tfm_example_ipc_test_rot_b()
{
	char str1[] = "this call is from non-secure happy world to secure world RoT_B";
	char str2[32];
	struct psa_invec invecs[1] = {str1, sizeof(str1)};
	struct psa_outvec outvecs[1] = {str2, sizeof(str2)};

    psa_handle_t handle;
    psa_status_t status;
    uint32_t version;

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
    printk("TEST_PASSED tfm_example_ipc_test_rot_b\n");
}

static void tfm_example_ipc_test_rot_c()
{
	char str1[] = "this call is from non-secure happy world to secure world RoT_C";
	char str2[32];
	struct psa_invec invecs[1] = {str1, sizeof(str1)};
	struct psa_outvec outvecs[1] = {str2, sizeof(str2)};

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
#endif
void main(void)
{
	psa_crypto_init();
#ifdef TFM_PSA_API
	tfm_example_ipc_test_rot_a();
	tfm_example_ipc_test_rot_b();
	tfm_example_ipc_test_rot_c();
#else
    tfm_example_lib_test_rot_a();
#endif

	printk("TF-M IPC on %s\n", CONFIG_BOARD);
#if defined(I_LIKE_REBOOT)
	printk("Wait 5 seconds before reset\n");
	k_sleep(K_MSEC(5000));
	sys_reboot(0);
#endif	
}
