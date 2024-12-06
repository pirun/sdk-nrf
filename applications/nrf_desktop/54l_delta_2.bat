@REM This script is used to build the update application and create delta patch binary. The delta patch is generated and copied to the delta_dfu/binaries/patches folder for update.

@REM Build the application
west build -p -b nrf54l15dk/nrf54l15/cpuapp -d build_54l -- -DFILE_SUFFIX=delta_gazell_ble -DCONFIG_MCUBOOT_IMGTOOL_SIGN_VERSION=\"2.0.0+0\"
@REM Backup original hex file
copy build_54l\merged.hex delta_200.hex
@REM Generate signed binary image from hex for later delta patch generation
arm-zephyr-eabi-objcopy --input-target=ihex --output-target=binary --gap-fill=0xff build_54l\nrf_desktop\zephyr\zephyr.signed.hex %ZEPHYR_BASE%\..\delta_dfu\binaries\signed_images\target_200.bin

@REM Check if patches directory exists, if not create it
setlocal
:: Define the directory want to create
set "dir=%ZEPHYR_BASE%\..\delta_dfu\binaries\patches"
:: Check if the directory exists
if not exist "%dir%" (
    :: Create the directory and its parent directories
    mkdir "%dir%"
)
endlocal
@REM Generate delta patch binary with patch_with_arg.py script
python  %ZEPHYR_BASE%\..\delta_dfu\scripts\patch_with_arg.py -d build_54l
