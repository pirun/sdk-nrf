#
# Copyright (c) 2019 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(serial_lte_modem)

# NORDIC SDK APP START
target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/slm_util.c)
target_sources(app PRIVATE src/slm_settings.c)
target_sources(app PRIVATE src/slm_at_host.c)
target_sources(app PRIVATE src/slm_at_commands.c)
target_sources(app PRIVATE src/slm_at_socket.c)
target_sources(app PRIVATE src/slm_at_tcp_proxy.c)
target_sources(app PRIVATE src/slm_at_udp_proxy.c)
target_sources(app PRIVATE src/slm_at_icmp.c)
target_sources(app PRIVATE src/slm_at_fota.c)
# NORDIC SDK APP END
target_sources_ifdef(CONFIG_SLM_SMS app PRIVATE src/slm_at_sms.c)
target_sources_ifdef(CONFIG_SLM_NATIVE_TLS app PRIVATE src/slm_native_tls.c)
target_sources_ifdef(CONFIG_SLM_NATIVE_TLS app PRIVATE src/slm_at_cmng.c)
target_sources_ifdef(CONFIG_SLM_NATIVE_TLS_PS app PRIVATE src/slm_native_tls_ps.c)
target_sources_ifdef(CONFIG_SLM_NATIVE_TLS_PSA app PRIVATE src/slm_native_tls_ps.c)

add_subdirectory_ifdef(CONFIG_SLM_GNSS src/gnss)
add_subdirectory_ifdef(CONFIG_SLM_FTPC src/ftp_c)
add_subdirectory_ifdef(CONFIG_SLM_MQTTC src/mqtt_c)
add_subdirectory_ifdef(CONFIG_SLM_HTTPC src/http_c)
add_subdirectory_ifdef(CONFIG_SLM_TWI src/twi)
add_subdirectory_ifdef(CONFIG_SLM_GPIO src/gpio)
add_subdirectory_ifdef(CONFIG_SLM_NRF52_DFU src/dfu)
target_include_directories(app PRIVATE
  $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/install/interface/include
)

zephyr_include_directories(src)
#set_property(TARGET zephyr_property_target
#             APPEND PROPERTY TFM_CMAKE_OPTIONS
#            -DPLATFORM_DEFAULT_ATTEST_HAL=OFF
#            -DPLATFORM_DEFAULT_CRYPTO_KEYS=OFF
#            -DPLATFORM_DEFAULT_ROTPK=OFF
#            -DPLATFORM_DEFAULT_IAK=OFF
#            -DPLATFORM_DEFAULT_NV_SEED=OFF
#            -DPLATFORM_DEFAULT_OTP=OFF
#            -DPLATFORM_DEFAULT_OTP_WRITEABLE=OFF
#            -DPLATFORM_DEFAULT_PROVISIONING=OFF
#            -DTFM_DUMMY_PROVISIONING=OFF
#            -DCRYPTO_NV_SEED=OFF
#            -DPLATFORM_NV_COUNTER_MODULE_DISABLED=TRUE
#            -DPLATFORM_DEFAULT_NV_COUNTERS=OFF
#)

#if (CONFIG_SLM_NATIVE_TLS_PSA)
#      add_overlay_config(
#        app
#        ${NRF_DIR}/samples/spm/spm_ns_handler_from_spm_fault.conf
#        )
#
#      add_overlay_dts(
#        mcuboot
#        ${NRF_DIR}/samples/spm/spm_uart.overlay
#      )
# endif()
