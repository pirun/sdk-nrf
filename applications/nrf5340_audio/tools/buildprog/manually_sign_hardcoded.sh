#!/bin/bash
#REM Hack to generate nRF5340 network core packet craft controller with b0n
PCFT_HEX=$1
BUILD_DIR=$2
FINAL_PCFT_HEX="pcft_CPUNET.hex"
FINAL_PCFT_UPDATE_BIN="pcft_net_core_update.bin"
#RETEIVE setting value from .config
#"${ZEPHYR_BASE}/../bootloader/mcuboot/root-rsa-2048.pem"
MCUBOOT_RSA_KEY="$(awk -F 'CONFIG_BOOT_SIGNATURE_KEY_FILE=' '/CONFIG_BOOT_SIGNATURE_KEY_FILE=/{print $2}' $BUILD_DIR/mcuboot/zephyr/.config | sed 's/"//g')"
if [[ "$MCUBOOT_RSA_KEY" == *\/* ]]
then
    echo "absolute path"
else
    echo "relative path"
    MCUBOOT_RSA_KEY=${ZEPHYR_BASE}/../bootloader/mcuboot/$MCUBOOT_RSA_KEY
fi
#IMAGE_VERSION="0.0.0+1"
IMAGE_VERSION="$(awk -F 'CONFIG_MCUBOOT_IMAGE_VERSION=' '/CONFIG_MCUBOOT_IMAGE_VERSION=/{print $2}' $BUILD_DIR/zephyr/.config | sed 's/"//g')"
#VALIDATION_MAGIC_VALUE="0x281ee6de,0x86518483,79106"
MAGIC_VALUE1="$(awk -F 'CONFIG_FW_INFO_MAGIC_COMMON=' '/CONFIG_FW_INFO_MAGIC_COMMON=/{print $2}' $BUILD_DIR/hci_rpmsg/zephyr/.config)"
MAGIC_VALUE2="$(awk -F 'CONFIG_SB_VALIDATION_INFO_MAGIC=' '/CONFIG_SB_VALIDATION_INFO_MAGIC=/{print $2}' $BUILD_DIR/hci_rpmsg/zephyr/.config)"
TEMP_VER="$(awk -F 'CONFIG_SB_VALIDATION_INFO_VERSION=' '/CONFIG_SB_VALIDATION_INFO_VERSION=/{print $2}' $BUILD_DIR/hci_rpmsg/zephyr/.config)"
TEMP_HWID="$(awk -F 'CONFIG_FW_INFO_HARDWARE_ID=' '/CONFIG_FW_INFO_HARDWARE_ID=/{print $2}' $BUILD_DIR/hci_rpmsg/zephyr/.config)"
TEMP_CRYPTO_ID="$(awk -F 'CONFIG_SB_VALIDATION_INFO_CRYPTO_ID=' '/CONFIG_SB_VALIDATION_INFO_CRYPTO_ID=/{print $2}' $BUILD_DIR/hci_rpmsg/zephyr/.config)"
TEMP_COMPAT_ID="$(awk -F 'CONFIG_FW_INFO_MAGIC_COMPATIBILITY_ID=' '/CONFIG_FW_INFO_MAGIC_COMPATIBILITY_ID=/{print $2}' $BUILD_DIR/hci_rpmsg/zephyr/.config)"
MAGIC_VALUE3=$((TEMP_VER+$((TEMP_HWID<<8))+$((TEMP_CRYPTO_ID <<16))+$((TEMP_COMPAT_ID << 24))))
VALIDATION_MAGIC_VALUE="$MAGIC_VALUE1,$MAGIC_VALUE2,$MAGIC_VALUE3"
#240
NUM_VER_COUNTER_SLOTS="$(awk -F 'CONFIG_SB_NUM_VER_COUNTER_SLOTS=' '/CONFIG_SB_NUM_VER_COUNTER_SLOTS=/{print $2}' $BUILD_DIR/hci_rpmsg/zephyr/.config)"
#0x200
FW_INFO_OFFSET="$(awk -F 'CONFIG_FW_INFO_OFFSET=' '/CONFIG_FW_INFO_OFFSET=/{print $2}' $BUILD_DIR/hci_rpmsg/zephyr/.config)"
PM_PARTITION_SIZE_PROVISION="$(awk -F 'CONFIG_PM_PARTITION_SIZE_PROVISION=' '/CONFIG_PM_PARTITION_SIZE_PROVISION=/{print $2}' $BUILD_DIR/hci_rpmsg/zephyr/.config)"
PM_APP_ADDRESS="$(awk -F 'PM_APP_ADDRESS=' '/PM_APP_ADDRESS=/{print $2}' $BUILD_DIR/hci_rpmsg/pm_CPUNET.config)"
PM_PROVISION_ADDRESS="$(awk -F 'PM_PROVISION_ADDRESS=' '/PM_PROVISION_ADDRESS=/{print $2}' $BUILD_DIR/hci_rpmsg/pm_CPUNET.config)"
PM_MCUBOOT_SECONDARY_SIZE="$(awk -F 'PM_MCUBOOT_SECONDARY_SIZE=' '/PM_MCUBOOT_SECONDARY_SIZE=/{print $2}' $BUILD_DIR/pm.config)"
python ${ZEPHYR_BASE}/../nrf/scripts/bootloader/hash.py --in ${PCFT_HEX} > $BUILD_DIR/app_firmware.sha256
python ${ZEPHYR_BASE}/../nrf/scripts/bootloader/do_sign.py --private-key $BUILD_DIR/hci_rpmsg/zephyr/GENERATED_NON_SECURE_SIGN_KEY_PRIVATE.pem --in  $BUILD_DIR/app_firmware.sha256 > $BUILD_DIR/app_firmware.signature
python ${ZEPHYR_BASE}/../nrf/scripts/bootloader/validation_data.py  --input ${PCFT_HEX} --output-hex $BUILD_DIR/signed_by_b0_pcft.hex  --output-bin $BUILD_DIR/signed_by_b0_pcft.bin --offset 0 --signature $BUILD_DIR/app_firmware.signature --public-key $BUILD_DIR/hci_rpmsg/zephyr/nrf/subsys/bootloader/generated/public.pem --magic-value ${VALIDATION_MAGIC_VALUE}
#Generate net_core_app_update.bin
python ${ZEPHYR_BASE}/../bootloader/mcuboot/scripts/imgtool.py sign --key ${MCUBOOT_RSA_KEY} --header-size ${FW_INFO_OFFSET} --align 4 --version ${IMAGE_VERSION} --pad-header --slot-size ${PM_MCUBOOT_SECONDARY_SIZE}  $BUILD_DIR/signed_by_b0_pcft.bin $BUILD_DIR/${FINAL_PCFT_UPDATE_BIN}
python ${ZEPHYR_BASE}/../nrf/scripts/bootloader/provision.py --s0-addr ${PM_APP_ADDRESS} --provision-addr ${PM_PROVISION_ADDRESS} --public-key-files  $BUILD_DIR/hci_rpmsg/zephyr/nrf/subsys/bootloader/generated/public.pem,$BUILD_DIR/hci_rpmsg/zephyr/GENERATED_NON_SECURE_PUBLIC_0.pem,$BUILD_DIR/hci_rpmsg/zephyr/GENERATED_NON_SECURE_PUBLIC_1.pem --output $BUILD_DIR/provision.hex  --num-counter-slots-version ${NUM_VER_COUNTER_SLOTS} --max-size ${PM_PARTITION_SIZE_PROVISION}

python $ZEPHYR_BASE/scripts/mergehex.py -o $BUILD_DIR/b0n_container.hex ${PCFT_HEX} $BUILD_DIR/provision.hex
python $ZEPHYR_BASE/scripts/mergehex.py -o $BUILD_DIR/${FINAL_PCFT_HEX} --overlap=replace $BUILD_DIR/hci_rpmsg/b0n/zephyr/zephyr.hex  $BUILD_DIR/b0n_container.hex $BUILD_DIR/provision.hex ${PCFT_HEX} $BUILD_DIR/signed_by_b0_pcft.hex

BASEDIR=$(dirname "$0")
#replace built net_core
cp $BUILD_DIR/${FINAL_PCFT_UPDATE_BIN} $BUILD_DIR/zephyr/net_core_app_update.bin
cp $BUILD_DIR/${FINAL_PCFT_HEX} $BUILD_DIR/zephyr/net_core_app_signed.hex

cp $BUILD_DIR/${FINAL_PCFT_UPDATE_BIN} ${BASEDIR}/../..//bin
cp $BUILD_DIR/${FINAL_PCFT_HEX} ${BASEDIR}/../../bin

#generate merged_domains.hex
python $ZEPHYR_BASE/scripts/mergehex.py -o $BUILD_DIR/zephyr/merged_domains.hex $BUILD_DIR/${FINAL_PCFT_HEX} $BUILD_DIR/zephyr/merged.hex
#generate dfu_application.zip
python ${ZEPHYR_BASE}/../nrf/scripts/bootloader/generate_zip.py --bin-files $BUILD_DIR/zephyr/app_update.bin $BUILD_DIR/zephyr/net_core_app_update.bin --output $BUILD_DIR/zephyr/dfu_application.zip --name nrf5340_audio --meta-info-file $BUILD_DIR/zephyr/zephyr.meta app_update.binload_address=0xc200 app_update.binimage_index=0 app_update.binslot_index_primary=1 app_update.binslot_index_secondary=2 app_update.binversion_MCUBOOT=${IMAGE_VERSION} net_core_app_update.binimage_index=1 net_core_app_update.binslot_index_primary=3 net_core_app_update.binslot_index_secondary=4 net_core_app_update.binload_address=0x1008800 net_core_app_update.binboard=nrf5340dk_nrf5340_cpunet net_core_app_update.binversion=1 net_core_app_update.binsoc=nRF5340_CPUNET_QKAA type=application board=nrf5340dk_nrf5340_cpuapp soc=nRF5340_CPUAPP_QKAA
