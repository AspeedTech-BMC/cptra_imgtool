#! /bin/bash

YELLOW='\033[0;33m'
END='\033[0m'

DIR="$(dirname "$(realpath "$0")")"
CPTRA_TOOLS_DIR="$DIR/.."
CPTRA_SW_DIR="$CPTRA_TOOLS_DIR/../caliptra-sw"
CPTRA_MCU_SW_DIR="$CPTRA_TOOLS_DIR/../caliptra-mcu-sw"

function cptra_printf() {
    echo -e "${YELLOW}[CPTRA]${END} $1"
}

pushd .

# Get caliptra-sw repository
if [ ! -d $CPTRA_SW_DIR ]; then
    cptra_printf "Cloning caliptra-sw repository..."
    git clone ssh://gerrit.aspeed.com:29418/caliptra-sw $CPTRA_SW_DIR
    cd $CPTRA_SW_DIR
    git checkout aspeed-rt-1.2.0
    git submodule init
    git submodule update dpe
else
    cptra_printf "Caliptra-sw repository already exists."
fi

# Get caliptra-mcu-sw repository
if [ ! -d $CPTRA_MCU_SW_DIR ]; then
    cptra_printf "Cloning caliptra-mcu-sw repository..."
    git clone ssh://gerrit.aspeed.com:29418/caliptra-mcu-sw $CPTRA_MCU_SW_DIR
    cd $CPTRA_MCU_SW_DIR && git checkout develop
    sed -i 's/^const MCU_RT_IDENTIFIER: u32 = 0x00000002;/const MCU_RT_IDENTIFIER: u32 = 0x00000003;/' $CPTRA_MCU_SW_DIR/builder/src/flash_image.rs
else
    cptra_printf "Caliptra-mcu-sw repository already exists."
fi

popd

