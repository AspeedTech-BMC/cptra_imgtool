#! /bin/bash

function create_ecdsa_key
{
    prefix=$1
    suffix=$2

    # Generate ECDSA key pair
    openssl ecparam -name secp384r1 -genkey -noout -out $KEY/keypair.pem

    # Extract private key from ECDSA key pair and translate to ec key format
    openssl ec -in $KEY/keypair.pem -out $KEY/$prefix-ecc-prvk-$suffix.pem > /dev/null 2>&1

    # Extract public key from ECDSA key pair
    openssl pkey -pubout -in $KEY/keypair.pem -out $KEY/$prefix-ecc-pubk-$suffix.pem > /dev/null 2>&1

    rm $KEY/keypair.pem
}

function create_env
{
    prj=$1

    # Remove workspace
    rm -rf $WORKSPACE

    # Create workspace directory
    mkdir -p $KEY
    mkdir -p $CONFIG
    mkdir -p $OUT

    # Create cptra image tool directory
    rm -rf $CPTRA_IMGTOOL/key/$prj-test
    rm -rf $CPTRA_IMGTOOL/prebuilt/$prj-test
    mkdir -p $CPTRA_IMGTOOL/key/$prj-test
    cp -rf $CPTRA_IMGTOOL/prebuilt/$prj $CPTRA_IMGTOOL/prebuilt/$prj-test

    # Generate real key
    cp $CPTRA_IMGTOOL/key/$prj/own-fw-lms-prvk.pem $KEY/lms-prvk.pem
    cp $CPTRA_IMGTOOL/key/$prj/own-fw-lms-pubk.pem $KEY/lms-pubk.pem
    cp $CPTRA_IMGTOOL/key/$prj/*-ecc-* $KEY
    ecc_key_list=$(ls "$KEY"/*-ecc-*)
    echo $ecc_key_list
    for file in ${ecc_key_list[@]}; do
        prefix_file=$(basename "$file" .pem)
        mv $file $KEY/$prefix_file-0.pem
    done

    # Generate key pair by openssl
    create_ecdsa_key "vnd-fw" "1"
    create_ecdsa_key "own-fw" "1"
    create_ecdsa_key "vnd-man" "1"
    create_ecdsa_key "own-man" "1"

    # Apply the test key pairs
    cp $KEY/* $CPTRA_IMGTOOL/key/$prj-test
}

function config_license
{
    cfg_file=$1

    echo '# Licensed under the Apache-2.0 license' > $cfg_file

    echo '' >> $cfg_file
}

function config_authtool
{
    cfg_file=$1

    echo '[authtool]' >> $cfg_file
    echo 'caliptra_sw_auth = "../caliptra-sw/auth-manifest/app/"' >> $cfg_file
    echo 'caliptra_mcu_sw = "../caliptra-mcu-sw/"' >> $cfg_file
    echo '' >> $cfg_file
}

function config_manifest_config
{
    version=$1
    flags=$2
    sec_version=$3
    key_pair=$4
    cfg_file=$5

    echo '[manifest_config]' >> $cfg_file
    echo "version = ${version}" >> $cfg_file
    echo "flags = ${flags}" >> $cfg_file
    echo "security_version = ${sec_version}" >> $cfg_file

    # Use prebuilt vendor firmware key signature
    vnd_fw_prvk=$(echo ${ECC_KEY_PAIR[${key_pair}_vnd_fw]} | awk '{print $1}')
    if [ $vnd_fw_prvk == 'vnd-fw-ecc-prvk-0' ]; then
        echo 'vnd_prebuilt_sig = "vnd_ecc_sig.der"' >> $cfg_file
    else
        echo 'vnd_prebuilt_sig = ""' >> $cfg_file
    fi

    echo '' >> $cfg_file
}

function config_vendor_fw_key_config
{
    key_pair=$1
    cfg_file=$2

    vnd_fw_key_pair=$(echo ${ECC_KEY_PAIR[${key_pair}_vnd_fw]})
    vnd_fw_prvk=$(echo $vnd_fw_key_pair | awk '{print $1}')
    vnd_fw_pubk=$(echo $vnd_fw_key_pair | awk '{print $2}')

    echo '[vendor_fw_key_config]' >> $cfg_file
    echo "ecc_pub_key = \"${vnd_fw_pubk}.pem\"" >> $cfg_file
    echo "ecc_priv_key = \"${vnd_fw_prvk}.pem\"" >> $cfg_file
    echo 'lms_pub_key = "lms-pubk.pem"' >> $cfg_file
    echo 'lms_priv_key = "lms-prvk.pem"' >> $cfg_file

    echo '' >> $cfg_file
}

function config_vendor_man_key_config
{
    key_pair=$1
    cfg_file=$2

    vnd_man_key_pair=$(echo ${ECC_KEY_PAIR[${key_pair}_vnd_man]})
    vnd_man_prvk=$(echo $vnd_man_key_pair | awk '{print $1}')
    vnd_man_pubk=$(echo $vnd_man_key_pair | awk '{print $2}')

    echo '[vendor_man_key_config]' >> $cfg_file
    echo "ecc_pub_key = \"${vnd_man_pubk}.pem\"" >> $cfg_file
    echo "ecc_priv_key = \"${vnd_man_prvk}.pem\"" >> $cfg_file
    echo 'lms_pub_key = "lms-pubk.pem"' >> $cfg_file
    echo 'lms_priv_key = "lms-prvk.pem"' >> $cfg_file

    echo '' >> $cfg_file
}

function config_owner_fw_key_config
{
    key_pair=$1
    cfg_file=$2

    own_fw_key_pair=$(echo ${ECC_KEY_PAIR[${key_pair}_own_fw]})
    own_fw_prvk=$(echo $own_fw_key_pair | awk '{print $1}')
    own_fw_pubk=$(echo $own_fw_key_pair | awk '{print $2}')

    echo '[owner_fw_key_config]' >> $cfg_file
    echo "ecc_pub_key = \"${own_fw_pubk}.pem\"" >> $cfg_file
    echo "ecc_priv_key = \"${own_fw_prvk}.pem\"" >> $cfg_file
    echo 'lms_pub_key = "lms-pubk.pem"' >> $cfg_file
    echo 'lms_priv_key = "lms-prvk.pem"' >> $cfg_file

    echo '' >> $cfg_file
}

function config_owner_man_key_config
{
    key_pair=$1
    cfg_file=$2

    own_man_key_pair=$(echo ${ECC_KEY_PAIR[${key_pair}_own_man]})
    own_man_prvk=$(echo $own_man_key_pair | awk '{print $1}')
    own_man_pubk=$(echo $own_man_key_pair | awk '{print $2}')

    echo '[owner_man_key_config]' >> $cfg_file
    echo "ecc_pub_key = \"${own_man_pubk}.pem\"" >> $cfg_file
    echo "ecc_priv_key = \"${own_man_prvk}.pem\"" >> $cfg_file
    echo 'lms_pub_key = "lms-pubk.pem"' >> $cfg_file
    echo 'lms_priv_key = "lms-prvk.pem"' >> $cfg_file

    echo '' >> $cfg_file
}

function config_image_runtime_list
{
    cptra_rt=$1
    mcu_rt=$2
    cfg_file=$3

    echo '[image_runtime_list]' >> $cfg_file
    echo "caliptra_file = \"${cptra_rt}\"" >> $cfg_file
    echo "mcu_file = \"${mcu_rt}\"" >> $cfg_file

    echo '' >> $cfg_file
}

function config_image_metadata_list
{
    img_list=( "u-boot-spl" "atf" "optee" "u-boot" "ssp" "tsp" )

    for img in ${img_list[@]}; do
        img_info=$(echo ${SOC_BOOTLOADER_IMAGE[$img]})
        file=$(echo $img_info | awk '{print $1}')
        source=$(echo $img_info | awk '{print $2}')
        fw_id=$(echo $img_info | awk '{print $3}')

        echo '[[image_metadata_list]]' >> $cfg_file
        echo "file = \"${file}\"" >> $cfg_file
        echo "source = ${source}" >> $cfg_file
        echo "fw_id = ${fw_id}" >> $cfg_file
        echo 'ignore_auth_check = false' >> $cfg_file

        echo '' >> $cfg_file
    done
}

function create_config
{
    version=$1
    flags=$2
    sec_version=$3
    key_pair=$4

    file_name=$CONFIG/${version}_${flags}_${sec_version}_${key_pair}.toml

    config_license $file_name
    config_authtool $file_name
    config_manifest_config $version $flags $sec_version $key_pair $file_name
    config_vendor_fw_key_config $key_pair $file_name
    config_vendor_man_key_config $key_pair $file_name
    config_owner_fw_key_config $key_pair $file_name
    config_owner_man_key_config $key_pair $file_name
    config_image_runtime_list 'caliptra-fw.bin' 'u-boot-spl.bin' $file_name
    config_image_metadata_list
}

function generate_img
{
    version=$1
    flags=$2
    sec_version=$3
    key_pair=$4
    prj=$5
    pre=$6

    cfg_path=$CONFIG/${version}_${flags}_${sec_version}_${key_pair}.toml
    img_path=$OUT/${pre}-${version}-${flags}-${sec_version}-${key_pair}-flash-image.bin
    cp $cfg_path $CPTRA_IMGTOOL/config/$prj-test-manifest.toml

    pushd .
    cd $CPTRA_IMGTOOL
    cargo run create-auth-flash --prj $prj-test
    popd

    cp $CPTRA_IMGTOOL/out/$prj-test-flash-image.bin $img_path
}

function modify_img
{
    version=$1
    flags=$2
    sec_version=$3
    key_pair=$4
    ofset=$5
    pre=$6

    img_path=$OUT/${pre}-${version}-${flags}-${sec_version}-${key_pair}-flash-image.bin
    printf '\x88' | dd of=${img_path} bs=1 seek=${ofset} conv=notrunc
}

function build_zephyr
{
    ver=$1
    ver_file=$ZEPHYR_SRC/aspeed-zephyr-project/apps/mcu-runtime/src/manifest_image_sig.c

    if [ -d $ver_file ]; then
        echo "Error: Zephyr manifest version file does not exist."
        exit 1
    fi

    sed -i "s/^#define CPTRA_SOC_MANIFEST_VER *(.*)/#define CPTRA_SOC_MANIFEST_VER (${ver})/" $ver_file

    pushd .
    cd $ZEPHYR_SRC/zephyr/ && source zephyr-env.sh
    cd ../aspeed-zephyr-project
    west build -p always -b ast2700_evb/ast2700/bootmcu apps/mcu-runtime
    cp build/zephyr/zephyr.bin ../../fmc_imgtool/fmc_imgtool
    cd ../../fmc_imgtool/fmc_imgtool
    python3 main.py --version 2 --input zephyr.bin --output $OUT/zephyr_v$ver.bin
    popd
}

##########################################################
# Global variable
##########################################################
CURRENT_DIR=$(realpath $(dirname "$0"))
PRJ=$1
ZEPHYR_SRC=$CURRENT_DIR/../../../zephyr
WORKSPACE="$CURRENT_DIR/genimg"
CPTRA_IMGTOOL="$CURRENT_DIR/.."
KEY=$WORKSPACE/key
CONFIG=$WORKSPACE/config
OUT=$WORKSPACE/out

# This is test key pair name array used for IT testing
# xxxx_0 key is real key pair, xxxx_1 is key random generated by openssl
declare -A ECC_KEY_PAIR=(
    # Case 0: | Correct | Correct | Correct | Correct |
    ['ts0_oooo_vnd_fw']="vnd-fw-ecc-prvk-0 vnd-fw-ecc-pubk-0"
    ['ts0_oooo_own_fw']="own-fw-ecc-prvk-0 own-fw-ecc-pubk-0"
    ['ts0_oooo_vnd_man']="vnd-man-ecc-prvk-0 vnd-man-ecc-pubk-0"
    ['ts0_oooo_own_man']="own-man-ecc-prvk-0 own-man-ecc-pubk-0"
    # Case 1: | Correct | Correct | Correct | Correct |
    ['ts1_oooo_vnd_fw']="vnd-fw-ecc-prvk-0 vnd-fw-ecc-pubk-0"
    ['ts1_oooo_own_fw']="own-fw-ecc-prvk-0 own-fw-ecc-pubk-0"
    ['ts1_oooo_vnd_man']="vnd-man-ecc-prvk-1 vnd-man-ecc-pubk-1"
    ['ts1_oooo_own_man']="own-man-ecc-prvk-1 own-man-ecc-pubk-1"
    # Case 2: | Incorrect | Correct | Correct | Correct |
    ['ts2_xooo_vnd_fw']="vnd-fw-ecc-prvk-1 vnd-fw-ecc-pubk-1"
    ['ts2_xooo_own_fw']="own-fw-ecc-prvk-0 own-fw-ecc-pubk-0"
    ['ts2_xooo_vnd_man']="vnd-man-ecc-prvk-0 vnd-man-ecc-pubk-0"
    ['ts2_xooo_own_man']="own-man-ecc-prvk-0 own-man-ecc-pubk-0"
    # Case 3: | Correct | Incorrect | Correct | Correct |
    ['ts3_oxoo_vnd_fw']="vnd-fw-ecc-prvk-0 vnd-fw-ecc-pubk-0"
    ['ts3_oxoo_own_fw']="own-fw-ecc-prvk-1 own-fw-ecc-pubk-1"
    ['ts3_oxoo_vnd_man']="vnd-man-ecc-prvk-0 vnd-man-ecc-pubk-0"
    ['ts3_oxoo_own_man']="own-man-ecc-prvk-0 own-man-ecc-pubk-0"
    # Case 4: | Correct | Correct | Incorrect | Correct |
    ['ts4_ooxo_vnd_fw']="vnd-fw-ecc-prvk-0 vnd-fw-ecc-pubk-0"
    ['ts4_ooxo_own_fw']="own-fw-ecc-prvk-0 own-fw-ecc-pubk-0"
    ['ts4_ooxo_vnd_man']="vnd-man-ecc-prvk-0 vnd-man-ecc-pubk-1"
    ['ts4_ooxo_own_man']="own-man-ecc-prvk-0 own-man-ecc-pubk-0"
    # Case 5: | Correct | Correct | Correct | Incorrect |
    ['ts5_ooox_vnd_fw']="vnd-fw-ecc-prvk-0 vnd-fw-ecc-pubk-0"
    ['ts5_ooox_own_fw']="own-fw-ecc-prvk-0 own-fw-ecc-pubk-0"
    ['ts5_ooox_vnd_man']="vnd-man-ecc-prvk-0 vnd-man-ecc-pubk-0"
    ['ts5_ooox_own_man']="own-man-ecc-prvk-0 own-man-ecc-pubk-1"
)

declare -A SOC_BOOTLOADER_IMAGE=(
    # | file name | source | firmware id |
    ['u-boot-spl']="u-boot-spl.bin 1 1"
    ['atf']="atf.bin 1 10"
    ['optee']="optee.bin 1 11"
    ['u-boot']="u-boot.bin 1 12"
    ['ssp']="ssp.bin 1 13"
    ['tsp']="tsp.bin 1 14"
)

##########################################################
# Main flow
##########################################################
if [[ -z $PRJ ]]; then
    echo "Usage: $0 <project_name>"
    echo "Example: $0 ast2700-default"
    exit 1
fi

if [[ ! -d $CPTRA_IMGTOOL/key/$PRJ || ! -d $CPTRA_IMGTOOL/prebuilt/$PRJ ]]; then
    echo "Error: project does not exists."
    exit 1
fi

create_env $PRJ

# Test pass case
create_config 1 0 0 'ts0_oooo'
generate_img 1 0 0 'ts0_oooo' $PRJ 'pass'

create_config 1 0 0 'ts1_oooo'
generate_img 1 0 0 'ts1_oooo' $PRJ 'pass'

create_config 1 0 0 'ts4_ooxo'
generate_img 1 0 0 'ts4_ooxo' $PRJ 'pass'

create_config 1 0 1 'ts0_oooo'
generate_img 1 0 1 'ts0_oooo' $PRJ 'pass'

# Test fail case
create_config 1 0 0 'ts0_oooo'
generate_img 1 0 0 'ts0_oooo' $PRJ 'fail-mdy-magic'
modify_img 1 0 0 'ts0_oooo' 0 'fail-mdy-magic'

create_config 1 0 0 'ts0_oooo'
generate_img 1 0 0 'ts0_oooo' $PRJ 'fail-mdy-checksum'
modify_img 1 0 0 'ts0_oooo' 4 'fail-mdy-checksum'

create_config 1 0 0 'ts2_xooo'
generate_img 1 0 0 'ts2_xooo' $PRJ 'fail'

create_config 1 0 0 'ts3_oxoo'
generate_img 1 0 0 'ts3_oxoo' $PRJ 'fail'

create_config 1 0 0 'ts5_ooox'
generate_img 1 0 0 'ts5_ooox' $PRJ 'fail'

create_config 1 0 0 'ts0_oooo'
generate_img 1 0 0 'ts0_oooo' $PRJ 'fail_m0_z1'
build_zephyr 1

create_config 1 0 1 'ts0_oooo'
generate_img 1 0 1 'ts0_oooo' $PRJ 'fail_m1_z2'
build_zephyr 2
