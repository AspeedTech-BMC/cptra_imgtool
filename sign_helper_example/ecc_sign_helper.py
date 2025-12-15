#!/usr/bin/env python3
import sys
import os
import binascii
import argparse
import tempfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


def sign_digest(digest: bytes, key_path: str) -> bytes:
    """Signs a pre-hashed digest using ECDSA-P384."""
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA384())))
    return signature


def sign_from_stdin(key_path: str):
    """STDIN/STDOUT mode: read digest from stdin, write signature to stdout."""
    digest_hex = sys.stdin.readline().strip()
    if not digest_hex:
        sys.stderr.write("Error: No digest provided via stdin\n")
        sys.exit(1)

    digest = binascii.unhexlify(digest_hex)
    sys.stderr.write(f"[STDIN MODE] Signing digest:\n {digest_hex}\n")

    signature = sign_digest(digest, key_path)
    sig_hex = binascii.hexlify(signature).decode()

    sys.stderr.write(f"Signature generated (DER hex): {sig_hex}\n")
    sys.stdout.write(sig_hex + "\n")


def sign_by_file(key_path: str, input_path: str):
    """File mode: read digest from file, overwrite file with signature."""
    if not os.path.exists(input_path):
        sys.stderr.write(f"Error: input file '{input_path}' does not exist\n")
        sys.exit(1)

    # Read digest bytes from file
    with open(input_path, "rb") as f:
        digest = f.read()

    sys.stderr.write(f"[FILE MODE] Signing digest from file: {input_path}\n")

    signature = sign_digest(digest, key_path)

    # Overwrite the same file with the signature
    with open(input_path, "wb") as f:
        f.write(signature)

    sys.stderr.write(f"Signature written back to file: {input_path}\n")


def main():
    parser = argparse.ArgumentParser(description="ECDSA-P384 signing helper (supports stdin/stdout or file mode)")
    parser.add_argument("--key", required=True, help="Key type (fw | man)")
    parser.add_argument("--by-file", action="store_true", help="Use file-based mode (digest in file, signature written back)")
    parser.add_argument("--input", help="Path to input file (used in file mode)")
    args = parser.parse_args()

    # ------------------------------------------------------------
    # Select private key based on --key argument
    # ------------------------------------------------------------
    if args.key == "fw":
        key_path = "key/ast2700a1-default/own-fw-ecc-prvk.pem"
    elif args.key == "man":
        key_path = "key/ast2700a1-default/own-man-ecc-prvk.pem"
    else:
        sys.stderr.write(f"Unknown key type: {args.key}\n")
        sys.exit(1)

    # ------------------------------------------------------------
    # Choose flow based on --by-file flag
    # ------------------------------------------------------------
    if args.by_file:
        if not args.input:
            sys.stderr.write("Error: --input <path> is required when using --by-file\n")
            sys.exit(1)
        sys.stderr.write(f"Using input file: {args.input}\n")
        sign_by_file(key_path, args.input)
    else:
        sign_from_stdin(key_path)


if __name__ == "__main__":
    main()
