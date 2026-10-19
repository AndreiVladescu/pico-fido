#!/bin/bash
#
# ESP32-S3 build for the fingerprint fork. The Pico (RP2040/RP2350) targets are
# kept in the tree but are not built by this fork.
#
# Usage:
#   ./build_esp32.sh                 # build + merged release image
#   ./build_esp32.sh flash [PORT]    # build and flash
#   ./build_esp32.sh menuconfig
#
# Extra CMake options can be passed through IDF_CMAKE_ARGS, e.g.
#   IDF_CMAKE_ARGS="-DENABLE_BIO=OFF" ./build_esp32.sh

set -e

VERSION_MAJOR="8"
VERSION_MINOR="2"
SUFFIX="${VERSION_MAJOR}.${VERSION_MINOR}"
TARGET="${TARGET:-esp32s3}"
BUILD_DIR="${BUILD_DIR:-build_esp32}"
IDF_VERSION="${IDF_VERSION:-v5.5.3}"

if ! command -v idf.py >/dev/null 2>&1; then
    # ESP-IDF installed by the EIM installer
    if [ -f "$HOME/.espressif/tools/activate_idf_${IDF_VERSION}.sh" ]; then
        # The activate script refuses to be sourced from another script, so
        # ask it for the environment instead (-e prints KEY=VALUE lines).
        while IFS='=' read -r key value; do
            [ -n "$key" ] && export "$key=$value"
        done < <(sh "$HOME/.espressif/tools/activate_idf_${IDF_VERSION}.sh" -e)
        export PATH="$PATH:$SYSTEM_PATH"
        idf.py() { "$IDF_PYTHON_ENV_PATH/bin/python3" "$IDF_PATH/tools/idf.py" "$@"; }
        esptool.py() { "$IDF_PYTHON_ENV_PATH/bin/python3" "$IDF_PATH/components/esptool_py/esptool/esptool.py" "$@"; }
    # classic install.sh / export.sh layout
    elif [ -n "$IDF_PATH" ] && [ -f "$IDF_PATH/export.sh" ]; then
        . "$IDF_PATH/export.sh" >/dev/null
    else
        echo "ESP-IDF not found. Set IDF_PATH or install it with EIM." >&2
        exit 1
    fi
fi

cd "$(dirname "$0")"
# Only initialise: an unconditional "submodule update" would reset pico-keys-sdk
# to the recorded commit and drop work in progress on the SDK branch.
if [ ! -f pico-keys-sdk/CMakeLists.txt ]; then
    git submodule update --init --recursive
fi

CMAKE_ARGS=()
if [ -n "${IDF_CMAKE_ARGS}" ]; then
    read -r -a CMAKE_ARGS <<< "${IDF_CMAKE_ARGS}"
fi

if [ ! -f "${BUILD_DIR}/CMakeCache.txt" ] || ! grep -q "IDF_TARGET:STRING=${TARGET}" "${BUILD_DIR}/CMakeCache.txt"; then
    idf.py -B "${BUILD_DIR}" "${CMAKE_ARGS[@]}" set-target "${TARGET}"
fi

case "$1" in
    flash)
        PORT_ARGS=()
        if [ -n "$2" ]; then
            PORT_ARGS=(-p "$2")
        fi
        idf.py -B "${BUILD_DIR}" "${CMAKE_ARGS[@]}" "${PORT_ARGS[@]}" build flash
        ;;
    menuconfig)
        idf.py -B "${BUILD_DIR}" "${CMAKE_ARGS[@]}" menuconfig
        ;;
    *)
        idf.py -B "${BUILD_DIR}" "${CMAKE_ARGS[@]}" build
        mkdir -p release
        (cd "${BUILD_DIR}" && esptool.py --chip "${TARGET}" merge_bin -o "../release/pico_fido_bio_${TARGET}-${SUFFIX}.bin" @flash_args)
        echo "Release image: release/pico_fido_bio_${TARGET}-${SUFFIX}.bin"
        ;;
esac
