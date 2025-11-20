#! /bin/bash

function create_ecdsa_key
{
    prefix=$1

    # Generate ECDSA key pair
    openssl ecparam -name secp384r1 -genkey -noout -out keypair.pem

    # Extract private key from ECDSA key pair and translate to ec key format
    openssl ec -in keypair.pem -out $prefix-ecc-prvk.pem > /dev/null 2>&1

    # Extract public key from ECDSA key pair
    openssl pkey -pubout -in keypair.pem -out $prefix-ecc-pubk.pem > /dev/null 2>&1

    rm keypair.pem
}

# Generate key pair by openssl
create_ecdsa_key "vnd-fw" "1"
create_ecdsa_key "own-fw" "1"
create_ecdsa_key "vnd-man" "1"
create_ecdsa_key "own-man" "1"