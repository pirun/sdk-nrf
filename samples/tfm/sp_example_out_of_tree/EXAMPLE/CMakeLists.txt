#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT TFM_PARTITION_EXAMPLE_OOT)
    return() 
endif()

add_library(tfm_app_rot_partition_example_oot STATIC)

target_sources(tfm_app_rot_partition_example_oot
    PRIVATE    
        EXAMPLE.c
)
target_include_directories(tfm_app_rot_partition_example_oot
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/EXAMPLE
)

# Set include directory
target_include_directories(tfm_app_rot_partition_example_oot
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/EXAMPLE
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/EXAMPLE
)
# The generated sources
target_sources(tfm_app_rot_partition_example_oot
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/EXAMPLE/auto_generated/intermedia_tfm_example.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/EXAMPLE/auto_generated/load_info_tfm_example.c
)


target_link_libraries(tfm_app_rot_partition_example_oot
    PRIVATE
        tfm_secure_api
        psa_interface
        platform_s
        secure_fw        
        tfm_sprt
        tfm_psa_rot_partition_crypto        
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_example_oot
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_EXAMPLE
)
