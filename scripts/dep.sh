#! /bin/bash

YELLOW='\033[0;33m'
END='\033[0m'

DIR="$(dirname "$(realpath "$0")")"
CPTRA_IMGTOOL_DIR="$DIR/.."
AUTH_FLASH_TOOLS_DIR="$CPTRA_IMGTOOL_DIR/tools/cptra_1x"
AUTH_TOOL_DIR="$AUTH_FLASH_TOOLS_DIR/caliptra-sw"
FLASH_TOOL_DIR="$AUTH_FLASH_TOOLS_DIR/caliptra-mcu-sw"
CPTRA_TARGET_DIR=$CPTRA_IMGTOOL_DIR/target
CPTRA_AUTH_FLASH_TOOL_TARGET_DIR=$CPTRA_IMGTOOL_DIR/target/tools/cptra_1x

function cptra_printf() {
    echo -e "${YELLOW}[CPTRA]${END} $1"
}

pushd .

# echo $DIR
# echo $CPTRA_IMGTOOL_DIR
# echo $AUTH_FLASH_TOOLS_DIR
# echo $AUTH_TOOL_DIR
# echo $FLASH_TOOL_DIR
# echo $CPTRA_TARGET_DIR
# echo $CPTRA_AUTH_FLASH_TOOL_TARGET_DIR

# Get caliptra-mcu-sw repository
if [ ! -d $FLASH_TOOL_DIR ]; then
    cptra_printf "Cloning caliptra-mcu-sw repository..."
    git clone ssh://gerrit.aspeed.com:29418/caliptra-mcu-sw $FLASH_TOOL_DIR
    cd $FLASH_TOOL_DIR && git checkout aspeed-dev-ast2700a2
else
    cptra_printf "Caliptra-mcu-sw repository already exists."
fi

if [ ! -d "$CPTRA_TARGET_DIR/debug" ]; then
    mkdir -p "$CPTRA_TARGET_DIR/debug"
fi

# Build the caliptra-sw tool
cptra_printf "Building auth-manifest tool..."
cd $CPTRA_IMGTOOL_DIR
cargo build -p caliptra-auth-manifest-app-1x --target-dir $CPTRA_AUTH_FLASH_TOOL_TARGET_DIR
cp $CPTRA_AUTH_FLASH_TOOL_TARGET_DIR/debug/caliptra-auth-manifest-app-1x $CPTRA_TARGET_DIR/debug/

# Build caliptra-mcu-sw tool
cptra_printf "Building caliptra-mcu-sw tool..."
cd $FLASH_TOOL_DIR
cargo build -p xtask --target-dir $CPTRA_AUTH_FLASH_TOOL_TARGET_DIR
cp $CPTRA_AUTH_FLASH_TOOL_TARGET_DIR/debug/xtask $CPTRA_TARGET_DIR/debug/xtask

popd
