use anyhow::Result;
use hex;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::mem;

// ECDSA imports
use p384::ecdsa::signature::hazmat::PrehashSigner;
use p384::ecdsa::{Signature, SigningKey};
use sec1::DecodeEcPrivateKey;

// LMS imports
// use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_crypto::OsslCrypto;
use caliptra_image_gen::ImageGeneratorCrypto;

use caliptra_image_types::{
    ImageDigest, ImageLmsPrivKey, ImageLmsSignature, SHA384_DIGEST_WORD_SIZE,
};

/// ECDSA: sign a SHA384 digest using an ECDSA-P384 private key.
fn ecc_sign_digest(digest: &[u8], key_path: &str) -> Result<Signature> {
    let pem = fs::read(key_path)?;
    let signing_key = SigningKey::from_sec1_pem(std::str::from_utf8(&pem)?)?;
    let sig = signing_key
        .sign_prehash(digest)
        .map_err(|_| anyhow::anyhow!("Failed to sign digest"))?;
    Ok(sig)
}

fn read_lms_privkey_from_file(path: &str) -> anyhow::Result<ImageLmsPrivKey> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;

    // check size
    let expected_size = mem::size_of::<ImageLmsPrivKey>();
    if buf.len() != expected_size {
        anyhow::bail!(
            "Invalid LMS private key size: expected {} bytes, got {}",
            expected_size,
            buf.len()
        );
    }

    // use unsafe directly reinterpret bytes to struct
    let priv_key: ImageLmsPrivKey =
        unsafe { std::ptr::read(buf.as_ptr() as *const ImageLmsPrivKey) };

    Ok(priv_key)
}

/// LMS: sign a digest using LMS private key
fn lms_sign_digest(digest: &[u8], key_path: &str) -> Result<ImageLmsSignature> {
    // load LMS private key (binary format)
    // eprintln!("Loading LMS private key from: {}", key_path);

    let priv_key = read_lms_privkey_from_file(key_path)?;

    // convert digest bytes to [u32; 12] (corresponding to SHA384 digest)
    if digest.len() != SHA384_DIGEST_WORD_SIZE * 4 {
        anyhow::bail!("Invalid digest length: expected 48 bytes");
    }

    let mut digest_arr: ImageDigest = [0u32; SHA384_DIGEST_WORD_SIZE];
    for (i, chunk) in digest.chunks_exact(4).enumerate() {
        digest_arr[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    // establish OpenSSL Crypto backend
    let crypto = OsslCrypto {};

    // use OsslCrypto trait method to perform LMS signing
    let sig = crypto.lms_sign(&digest_arr, &priv_key)?;

    // return signature structure
    Ok(sig)
}

/// Sign by file (overwrite digest file with signature)
fn sign_by_file(algo: &str, key_path: &str, input_path: &str) -> Result<()> {
    let mut digest = Vec::new();
    {
        let mut f = File::open(input_path)?;
        f.read_to_end(&mut digest)?;
    }

    eprintln!("[FILE MODE] Signing digest from file: {}", input_path);

    match algo {
        "ecc" => {
            let sig = ecc_sign_digest(&digest, key_path)?;
            let der_bytes = sig.to_der();
            let mut f = File::create(input_path)?;
            f.write_all(der_bytes.as_bytes())?;
            eprintln!("ECC signature written to file: {}", input_path);
        }
        "lms" => {
            let sig = lms_sign_digest(&digest, key_path)?;
            let sig_ptr = &sig as *const _ as *const u8;
            let sig_bytes =
                unsafe { std::slice::from_raw_parts(sig_ptr, std::mem::size_of_val(&sig)) };

            let mut f = File::create(input_path)?;
            f.write_all(sig_bytes)?;
            eprintln!("LMS signature written to file: {}", input_path);
        }
        _ => anyhow::bail!("Unsupported algorithm: {}", algo),
    }

    Ok(())
}

/// STDIN/STDOUT mode
fn sign_by_stdin(algo: &str, key_path: &str) -> Result<()> {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let digest_hex = line.trim();
    let digest = hex::decode(digest_hex)?;

    // Show only the first 16 bytes of the digest for preview
    let preview_len = digest.len().min(16);
    let preview_hex = hex::encode(&digest[..preview_len]);
    eprintln!(
        "[STDIN MODE] Signing digest (first 16 bytes): {}",
        preview_hex
    );

    match algo {
        "ecc" => {
            let sig = ecc_sign_digest(&digest, key_path)?;
            let der_bytes = sig.to_der();
            eprintln!(
                // "ECC signature generated (DER hex): {}",
                // hex::encode(&der_bytes)
                "ECC signature generated",
            );
            println!("{}", hex::encode(&der_bytes));
        }
        "lms" => {
            let sig = lms_sign_digest(&digest, key_path)?;
            let sig_ptr = &sig as *const _ as *const u8;
            let sig_bytes =
                unsafe { std::slice::from_raw_parts(sig_ptr, std::mem::size_of_val(&sig)) };

            eprintln!(
                "LMS signature generated (binary len={} bytes)",
                sig_bytes.len()
            );
            println!("{}", hex::encode(&sig_bytes));
        }
        _ => anyhow::bail!("Unsupported algorithm: {}", algo),
    }

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Example:
    // ./rust_sign_helper --algo ecc --key fw
    // ./rust_sign_helper --algo lms --key man --by-file --input digest.bin
    let mut algo = "";
    let mut key_type = "";
    let mut by_file = false;
    let mut input_path = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--algo" => {
                algo = args.get(i + 1).map(|s| s.as_str()).unwrap_or("");
                i += 1;
            }
            "--key" => {
                key_type = args.get(i + 1).map(|s| s.as_str()).unwrap_or("");
                i += 1;
            }
            "--by-file" => {
                by_file = true;
            }
            "--input" => {
                input_path = args.get(i + 1).cloned().unwrap_or_default();
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    if algo.is_empty() || key_type.is_empty() {
        eprintln!(
            "Usage: rust_sign_helper --algo <ecc|lms> --key <fw|man> [--by-file --input <path>]"
        );
        std::process::exit(1);
    }

    // Select key path
    let key_path = match (algo, key_type) {
        ("ecc", "fw") => "key/ast2700a1-default/own-fw-ecc-prvk.pem",
        ("ecc", "man") => "key/ast2700a1-default/own-man-ecc-prvk.pem",
        ("lms", "fw") => "key/ast2700a1-default/own-fw-lms-prvk.pem",
        ("lms", "man") => "key/ast2700a1-default/own-man-lms-prvk.pem",
        _ => {
            eprintln!("Unknown key type or algorithm: {algo}:{key_type}");
            std::process::exit(1);
        }
    };

    if by_file {
        if input_path.is_empty() {
            eprintln!("Error: --input <path> required for --by-file mode");
            std::process::exit(1);
        }
        sign_by_file(algo, key_path, &input_path)?;
    } else {
        sign_by_stdin(algo, key_path)?;
    }

    Ok(())
}
