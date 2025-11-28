#! /bin/bash

YELLOW='\033[0;33m'
END='\033[0m'

DIR="$(dirname "$(realpath "$0")")"
CPTRA_TOOLS_DIR="$DIR/.."
CPTRA_SW_DIR="$CPTRA_TOOLS_DIR/caliptra-sw"
CPTRA_MCU_SW_DIR="$CPTRA_TOOLS_DIR/caliptra-mcu-sw"
CPTRA_TARGET_DIR=$CPTRA_TOOLS_DIR/target

function cptra_printf() {
    echo -e "${YELLOW}[CPTRA]${END} $1"
}

pushd .

# Get caliptra-sw repository
if [ ! -d $CPTRA_SW_DIR ]; then
    cptra_printf "Cloning caliptra-sw repository..."
    git clone https://github.com/chipsalliance/caliptra-sw.git $CPTRA_SW_DIR
    cd $CPTRA_SW_DIR
    git checkout caliptra-2.1-dev
    git am ../patch/0001-fix-svn-not-found-mldsa-priv-key-not-read-issue.patch
    git submodule init
    git submodule update dpe
else
    cptra_printf "Caliptra-sw repository already exists."
    # cptra_printf "Update to lastest version on caliptra-2.1-dev branch."
    # cd $CPTRA_SW_DIR
    # git pull --rebase
fi

# Get caliptra-mcu-sw repository
if [ ! -d $CPTRA_MCU_SW_DIR ]; then
    cptra_printf "Cloning caliptra-mcu-sw repository..."
    git clone https://github.com/chipsalliance/caliptra-mcu-sw.git $CPTRA_MCU_SW_DIR
    cd $CPTRA_MCU_SW_DIR && git checkout main-2.1
else
    cptra_printf "Caliptra-mcu-sw repository already exists."
fi

# Build the caliptra-sw tool
cptra_printf "Building caliptra-sw tool..."
cd $CPTRA_SW_DIR
cargo build -p caliptra-auth-manifest-app --target-dir $CPTRA_TARGET_DIR

# Build caliptra-mcu-sw tool
cptra_printf "Building caliptra-mcu-sw tool..."
cd $CPTRA_MCU_SW_DIR
cargo build -p xtask --target-dir $CPTRA_TARGET_DIR

popd
