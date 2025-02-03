@REM @REM This script is used to build the origin application and program it to the board. The signed image is generated and copied to the delta_dfu/binaries/signed_images folder for delta image source generation

@REM @REM Build the application
west build -p -b nrf54l15dk/nrf54l05/cpuapp -d build_l05_delta -- -DFILE_SUFFIX=delta -DCONFIG_MCUBOOT_IMGTOOL_SIGN_VERSION=\"1.0.0+0\"
@REM @REM Backup original hex file
copy build_l05_delta\merged.hex delta_100.hex
@REM Program the application to the board
west flash -d build_l05_delta


:: Check if the %ZEPHYR% environment variable is defined

if not defined ZEPHYR_BASE (
    echo %ZEPHYR_BASE% is not set, setting it to a relative path...
    set "ZEPHYR_BASE_REL=%CD%\..\..\..\zephyr"
)
:: Use for to get the absolute path
for %%I in ("%ZEPHYR_BASE_REL%") do (
    set "ZEPHYR_BASE=%%~fI"
)

echo "%ZEPHYR_BASE%" current value: %ZEPHYR_BASE%

@REM Check if signed_images directory exists, if not create it
setlocal

:: Define the directory want to create
set "dir=%ZEPHYR_BASE%\..\delta_dfu\binaries\signed_images"

:: Check if the directory exists
if not exist "%dir%" (
    :: Create the directory and its parent directories
    mkdir "%dir%"
)
endlocal
@REM Generate signed binary image from hex for later delta patch generation
@REM arm-none-eabi-objcopy --input-target=ihex --output-target=binary --gap-fill=0xff build_54l\nrf_desktop\zephyr\zephyr.signed.hex %ZEPHYR_BASE%\..\delta_dfu\binaries\signed_images\source_100.bin
arm-zephyr-eabi-objcopy --input-target=ihex --output-target=binary --gap-fill=0xff build_l05_delta\nrf_desktop\zephyr\zephyr.signed.hex %ZEPHYR_BASE%\..\delta_dfu\binaries\signed_images\source_100.bin
