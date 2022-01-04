#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

get_target_property(TFM_BINARY_DIR tfm TFM_BINARY_DIR)
configure_file(
  ${CMAKE_CURRENT_LIST_DIR}/EXAMPLE/tfm_manifest_list.yaml.in
  ${CMAKE_CURRENT_BINARY_DIR}/EXAMPLE/tfm_manifest_list.yaml
)

set_property(TARGET zephyr_property_target
  APPEND PROPERTY TFM_CMAKE_OPTIONS
  -DTFM_EXTRA_MANIFEST_LIST_FILES=${CMAKE_CURRENT_BINARY_DIR}/EXAMPLE/tfm_manifest_list.yaml
  -DTFM_EXTRA_PARTITION_PATHS=${CMAKE_CURRENT_LIST_DIR}/EXAMPLE
  -DTFM_PARTITION_EXAMPLE_OOT=ON
)
set_property(TARGET zephyr_property_target
  APPEND PROPERTY TFM_CMAKE_OPTIONS
  -DCMAKE_BUILD_TYPE=debug
  -DTFM_SPM_LOG_LEVEL=TFM_SPM_LOG_LEVEL_DEBUG
  -DTFM_PARTITION_LOG_LEVEL=TFM_PARTITION_LOG_LEVEL_DEBUG
  )

project(tfm_secure_partition_example_out_of_tree)

target_sources(app PRIVATE 
  src/main.c
  ns_api/tfm_example_api.c)

target_include_directories(app PRIVATE
  ${ZEPHYR_TRUSTED_FIRMWARE_M_MODULE_DIR}/trusted-firmware-m/interface/include
  ns_api

)
zephyr_link_libraries(
 -Wl,--undefined=psa_framework_version
 -Wl,--undefined=example_main
 -Wl,--undefined=rot_A_by_handle
 -Wl,--undefined=rot_A
 -Wl,--undefined=example_signal_handle
 -Wl,--undefined=rot_B_by_handle_ipc
 -Wl,--undefined=rot_a_input_output_req
 -Wl,--undefined=rot_a_operation
 -Wl,--undefined=LOG_DBGFMT
 -Wl,--undefined=LOG_ERRFMT
 -Wl,--undefined=LOG_INFFMT

 )
 

 target_include_directories(app PRIVATE
  ${ZEPHYR_TRUSTED_FIRMWARE_M_MODULE_DIR}/interface/include
)

target_compile_definitions(app
    PRIVATE TFM_PARTITION_EXAMPLE
)
