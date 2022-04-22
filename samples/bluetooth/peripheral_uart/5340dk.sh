#! /bin/sh
#west build -b nrf5340dk_nrf5340_cpuapp -- -DOVERLAY_CONFIG=prj_dfu.conf -Dmcuboot_OVERLAY_CONFIG=${PWD}/mcuboot.conf
west build -b nrf5340dk_nrf5340_cpuapp -- -DOVERLAY_CONFIG=prj_dfu.conf
west flash --erase