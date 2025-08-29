#! /bin/bash

function usage
{
    echo "./newprj.sh <prj> [ref_prj]"
}

function dup_prj
{
    new_prj=$1
    ref_prj=$2

    # Copy configuratione
    cp -rf $CPTRA_TOOLS_DIR/config/$ref_prj-manifest.toml $CPTRA_TOOLS_DIR/config/$new_prj-manifest.toml

    # Copy prebuilt directory and file
    cp -rf $CPTRA_TOOLS_DIR/prebuilt/$ref_prj $CPTRA_TOOLS_DIR/prebuilt/$new_prj

    # Copy key directory and file
    cp -rf $CPTRA_TOOLS_DIR/key/$ref_prj $CPTRA_TOOLS_DIR/key/$new_prj
}

function empty_prj
{
    # TODO: Generate default configuration automatically

    new_prj=$1

    # Create configuration
    touch $CPTRA_TOOLS_DIR/config/$new_prj-manifest.toml

    # Create prebuilt directory
    mkdir $CPTRA_TOOLS_DIR/prebuilt/$new_prj

    # Create key directory
    mkdir $CPTRA_TOOLS_DIR/key/$new_prj
}

function create_prj
{
    new_prj=$1
    ref_prj=$2

    if [ -z "$ref_prj" ]; then
        empty_prj $new_prj
    else
        dup_prj $new_prj $ref_prj
    fi
}

##########################################################
# Input parameters check
##########################################################
DIR="$(dirname "$(realpath "$0")")"
CPTRA_TOOLS_DIR="$DIR/.."
NEW_PRJ=""
REF_PRJ=""

if [ "$#" -eq 1 ]; then
    NEW_PRJ=$1
elif [ "$#" -eq 2 ]; then
    NEW_PRJ=$1
    REF_PRJ=$2
else
    usage
    exit 1
fi

##########################################################
# Main flow
##########################################################

create_prj $NEW_PRJ $REF_PRJ