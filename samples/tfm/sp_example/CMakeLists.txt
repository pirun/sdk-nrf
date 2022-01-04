# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(tfm_ipc)

target_sources(app PRIVATE src/main.c)

target_include_directories(app PRIVATE
  ${ZEPHYR_TRUSTED_FIRMWARE_M_MODULE_DIR}/trusted-firmware-m/interface/include
)
set_property(TARGET zephyr_property_target
  APPEND PROPERTY TFM_CMAKE_OPTIONS
  -DCMAKE_BUILD_TYPE=debug
  -DTFM_SPM_LOG_LEVEL=TFM_SPM_LOG_LEVEL_DEBUG
  -DTFM_PARTITION_LOG_LEVEL=TFM_PARTITION_LOG_LEVEL_DEBUG
  -DTFM_PARTITION_EXAMPLE=ON
  )
  zephyr_link_libraries(
 -Wl,--undefined=psa_framework_version
 -Wl,--undefined=example_main
 -Wl,--undefined=rot_A_by_handle
 -Wl,--undefined=rot_A
 -Wl,--undefined=example_signal_handle
 -Wl,--undefined=rot_B_by_handle_ipc
 )

  