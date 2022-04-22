#! /bin/sh
rm -rf build
west build -b nrf5340dk_nrf5340_cpuapp -- '-DCONFIG_MCUBOOT_IMAGE_VERSION="1.0.0+0"' -Dhci_rpmsg_CONFIG_FW_INFO_FIRMWARE_VERSION=1

