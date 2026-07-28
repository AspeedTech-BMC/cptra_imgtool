/*++

Licensed under the Apache-2.0 license.

Modified by ASPEED Technology Inc., 2026-07-28: Support both Caliptra zero-leaf
and full RFC 8554 LMS trees when signing authorization manifests, with parallel
no-cache full-tree generation using only the Rust standard library.

--*/

use anyhow::{anyhow, bail, Context, Result};
use caliptra_image_gen_1x::ImageGeneratorCrypto;
use caliptra_image_types_1x::{
    ImageDigest, ImageLmsPrivKey, ImageLmsPublicKey, ImageLmsSignature, IMAGE_LMS_KEY_HEIGHT,
    IMAGE_LMS_OTS_TYPE, IMAGE_LMS_TREE_TYPE, SHA192_DIGEST_BYTE_SIZE,
};
use sha2::{Digest, Sha256};
use std::{thread, time::Instant};
use zerocopy::IntoBytes;

const D_PBLC: u16 = 0x8080;
const D_LEAF: u16 = 0x8282;
const D_INTR: u16 = 0x8383;
const LMOTS_P: usize = 51;
const LMOTS_W: u8 = 4;
const CALIPTRA_FIXED_Q: u32 = 5;

type Hash24 = [u8; SHA192_DIGEST_BYTE_SIZE];
type TreePath = [Hash24; IMAGE_LMS_KEY_HEIGHT];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LmsTreeMode {
    CaliptraZeroLeaf,
    FullRfc8554,
}

/// Sign an LMS digest and select the authentication-tree construction that
/// matches the supplied public key.
///
/// The caliptra-sw 1.x image signer always creates the LM-OTS signature at q=5
/// and, for H=15, creates an authentication path from the Caliptra "zero-leaf"
/// tree. Some existing keys were generated from a full RFC 8554 tree instead.
/// The LM-OTS signature is identical for both modes; only the authentication
/// path differs. This helper retains the existing backend for LM-OTS signing,
/// then replaces the tree path with the path whose root matches `pub_key`.
pub(crate) fn sign_lms_matching_public_key<Crypto: ImageGeneratorCrypto>(
    crypto: &Crypto,
    digest: &ImageDigest,
    priv_key: &ImageLmsPrivKey,
    pub_key: &ImageLmsPublicKey,
) -> Result<ImageLmsSignature> {
    validate_key_headers(priv_key, pub_key)?;

    // Keep the existing OpenSSL/RustCrypto implementation for the LM-OTS
    // signature and nonce generation. The dependency revision used by this
    // tool signs H=15 keys at q=5.
    let mut signature = crypto.lms_sign(digest, priv_key)?;
    let q = signature.q.get();

    if q != CALIPTRA_FIXED_Q {
        bail!("Unsupported LMS q={q}; this cptra_imgtool revision expects q={CALIPTRA_FIXED_Q}");
    }

    let expected_root: Hash24 = pub_key
        .digest
        .as_bytes()
        .try_into()
        .context("Invalid LMS public-key digest length")?;

    // Zero-leaf mode is inexpensive, so test it first to retain the behavior
    // and performance of the original Caliptra signing flow.
    let (zero_root, zero_path) = build_tree(priv_key, q, LmsTreeMode::CaliptraZeroLeaf)?;
    if zero_root == expected_root {
        install_tree_path(&mut signature, &zero_path);
        eprintln!("LMS tree mode: Caliptra zero-leaf (q={q})");
        return Ok(signature);
    }

    // A full H=15/W=4 tree needs about 26.7 million SHA-256 operations.
    // Generate it in parallel using scoped standard-library threads. The
    // result is intentionally not cached, so this works in read-only,
    // sandboxed, containerized, and temporary build environments.
    eprintln!(
        "LMS zero-leaf root does not match the configured public key; generating full RFC 8554 tree without cache"
    );
    let started = Instant::now();
    let (full_root, full_path) = build_tree(priv_key, q, LmsTreeMode::FullRfc8554)?;
    eprintln!(
        "Full RFC 8554 LMS tree generated in {:?}",
        started.elapsed()
    );

    if full_root == expected_root {
        install_tree_path(&mut signature, &full_path);
        eprintln!("LMS tree mode: full RFC 8554 (q={q}, no cache)");
        return Ok(signature);
    }

    Err(anyhow!(
        "LMS private/public key mismatch: configured root={}, zero-leaf root={}, full-tree root={}",
        hex::encode_upper(expected_root),
        hex::encode_upper(zero_root),
        hex::encode_upper(full_root),
    ))
}

fn validate_key_headers(priv_key: &ImageLmsPrivKey, pub_key: &ImageLmsPublicKey) -> Result<()> {
    if priv_key.tree_type != IMAGE_LMS_TREE_TYPE || pub_key.tree_type != IMAGE_LMS_TREE_TYPE {
        bail!("Unsupported LMS tree type; expected LMS_SHA256_N24_H15 (type 12)");
    }
    if priv_key.otstype != IMAGE_LMS_OTS_TYPE || pub_key.otstype != IMAGE_LMS_OTS_TYPE {
        bail!("Unsupported LM-OTS type; expected LMOTS_SHA256_N24_W4 (type 7)");
    }
    if priv_key.tree_type != pub_key.tree_type {
        bail!("LMS private/public tree-type mismatch");
    }
    if priv_key.otstype != pub_key.otstype {
        bail!("LMS private/public LM-OTS-type mismatch");
    }
    if priv_key.id != pub_key.id {
        bail!("LMS private/public identifier I mismatch");
    }
    Ok(())
}

fn install_tree_path(signature: &mut ImageLmsSignature, path: &TreePath) {
    for (dst, src) in signature.tree_path.iter_mut().zip(path.iter()) {
        dst.as_mut_bytes().copy_from_slice(src);
    }
}

fn build_tree(priv_key: &ImageLmsPrivKey, q: u32, mode: LmsTreeMode) -> Result<(Hash24, TreePath)> {
    if q >= (1u32 << IMAGE_LMS_KEY_HEIGHT) {
        bail!("Invalid LMS q={q}");
    }

    let id = priv_key.id;
    let seed: Hash24 = priv_key
        .seed
        .as_bytes()
        .try_into()
        .context("Invalid LMS private seed length")?;
    let leaf_count = 1usize << IMAGE_LMS_KEY_HEIGHT;
    let zero_k = [0u8; SHA192_DIGEST_BYTE_SIZE];
    let mut nodes = vec![[0u8; SHA192_DIGEST_BYTE_SIZE]; leaf_count];

    match mode {
        LmsTreeMode::CaliptraZeroLeaf => {
            for (i, node) in nodes.iter_mut().enumerate() {
                let ots_public_key = if i as u32 == q {
                    generate_lmots_public_key(&id, &seed, i as u32)
                } else {
                    zero_k
                };
                let r = (leaf_count + i) as u32;
                *node = hash_leaf(&id, r, &ots_public_key);
            }
        }
        LmsTreeMode::FullRfc8554 => {
            generate_full_tree_leaves_parallel(&id, &seed, &mut nodes);
        }
    }

    let mut path = [[0u8; SHA192_DIGEST_BYTE_SIZE]; IMAGE_LMS_KEY_HEIGHT];
    let mut target = q as usize;

    for (level, path_node) in path.iter_mut().enumerate() {
        *path_node = nodes[target ^ 1];

        let parent_count = nodes.len() / 2;
        let parent_base = 1usize << (IMAGE_LMS_KEY_HEIGHT - level - 1);
        let mut parents = Vec::with_capacity(parent_count);
        for pair_index in 0..parent_count {
            let r = (parent_base + pair_index) as u32;
            parents.push(hash_internal(
                &id,
                r,
                &nodes[pair_index * 2],
                &nodes[pair_index * 2 + 1],
            ));
        }

        nodes = parents;
        target >>= 1;
    }

    Ok((nodes[0], path))
}

fn generate_full_tree_leaves_parallel(id: &[u8; 16], seed: &Hash24, nodes: &mut [Hash24]) {
    let worker_count = configured_worker_count(nodes.len());
    let chunk_size = (nodes.len() + worker_count - 1) / worker_count;
    let leaf_count = nodes.len();

    eprintln!("Generating {leaf_count} full RFC LMS leaves with {worker_count} worker thread(s)");

    if worker_count == 1 {
        for (i, node) in nodes.iter_mut().enumerate() {
            let k = generate_lmots_public_key(id, seed, i as u32);
            *node = hash_leaf(id, (leaf_count + i) as u32, &k);
        }
        return;
    }

    let id_value = *id;
    let seed_value = *seed;
    thread::scope(|scope| {
        for (chunk_index, chunk) in nodes.chunks_mut(chunk_size).enumerate() {
            let start = chunk_index * chunk_size;
            let id = id_value;
            let seed = seed_value;
            scope.spawn(move || {
                for (offset, node) in chunk.iter_mut().enumerate() {
                    let i = start + offset;
                    let k = generate_lmots_public_key(&id, &seed, i as u32);
                    *node = hash_leaf(&id, (leaf_count + i) as u32, &k);
                }
            });
        }
    });
}

fn configured_worker_count(max_workers: usize) -> usize {
    let configured = std::env::var("CPTRA_LMS_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0);

    configured
        .or_else(|| {
            thread::available_parallelism()
                .ok()
                .map(|value| value.get())
        })
        .unwrap_or(1)
        .min(max_workers)
        .max(1)
}

fn generate_lmots_public_key(id: &[u8; 16], seed: &Hash24, q: u32) -> Hash24 {
    let q_bytes = q.to_be_bytes();
    let mut public_hasher = Sha256::new();
    public_hasher.update(id);
    public_hasher.update(q_bytes);
    public_hasher.update(D_PBLC.to_be_bytes());

    for i in 0..LMOTS_P {
        let i_bytes = (i as u16).to_be_bytes();
        let mut value = hash24(&[id, &q_bytes, &i_bytes, &[0xff], seed]);

        for j in 0..((1u16 << LMOTS_W) - 1) {
            value = hash24(&[id, &q_bytes, &i_bytes, &[j as u8], &value]);
        }
        public_hasher.update(value);
    }

    truncate_sha256(public_hasher.finalize())
}

fn hash_leaf(id: &[u8; 16], r: u32, ots_public_key: &Hash24) -> Hash24 {
    hash24(&[id, &r.to_be_bytes(), &D_LEAF.to_be_bytes(), ots_public_key])
}

fn hash_internal(id: &[u8; 16], r: u32, left: &Hash24, right: &Hash24) -> Hash24 {
    hash24(&[id, &r.to_be_bytes(), &D_INTR.to_be_bytes(), left, right])
}

fn hash24(parts: &[&[u8]]) -> Hash24 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    truncate_sha256(hasher.finalize())
}

fn truncate_sha256(digest: impl AsRef<[u8]>) -> Hash24 {
    let mut result = [0u8; SHA192_DIGEST_BYTE_SIZE];
    result.copy_from_slice(&digest.as_ref()[..SHA192_DIGEST_BYTE_SIZE]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::FromBytes;

    const FULL_PRIVATE: [u8; 48] = [
        0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x07, 0x93, 0x72, 0x3a, 0xd8, 0xf9, 0x70, 0x70,
        0x8a, 0x6d, 0xb5, 0xfa, 0x88, 0xc2, 0x24, 0x3e, 0x70, 0x38, 0xb4, 0x77, 0x58, 0x4a, 0x13,
        0x65, 0x74, 0x2b, 0xd5, 0x44, 0x49, 0xbc, 0x94, 0x1e, 0x9b, 0x8a, 0x16, 0x0e, 0xbc, 0xe9,
        0xbd, 0x8a, 0xa1,
    ];

    const ZERO_PRIVATE: [u8; 48] = [
        0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x07, 0xe5, 0x6d, 0x3e, 0x53, 0xa5, 0xc2, 0x5b,
        0xea, 0xf3, 0x3a, 0x90, 0x15, 0x5b, 0x27, 0x3a, 0xe3, 0x65, 0xc4, 0xfb, 0xac, 0xd3, 0xab,
        0xa2, 0x8f, 0x77, 0xe7, 0xc5, 0x1c, 0x7f, 0x39, 0xba, 0x4d, 0x59, 0xd0, 0xb0, 0x83, 0x79,
        0xa9, 0xf7, 0x5d,
    ];

    #[test]
    fn zero_leaf_root_matches_known_key() {
        let key = ImageLmsPrivKey::read_from_bytes(&ZERO_PRIVATE).unwrap();
        let (root, _) = build_tree(&key, CALIPTRA_FIXED_Q, LmsTreeMode::CaliptraZeroLeaf).unwrap();
        assert_eq!(
            hex::encode_upper(root),
            "47B2156CA3641CC402C0FD957972BA56086F8F8CFA05B5BB"
        );
    }

    // Full H=15/W=4 generation performs roughly 26.7 million SHA-256
    // operations, so keep this as an explicit regression test rather than
    // running it in every default unit-test invocation.
    #[test]
    #[ignore]
    fn full_tree_root_matches_known_key() {
        let key = ImageLmsPrivKey::read_from_bytes(&FULL_PRIVATE).unwrap();
        let (root, _) = build_tree(&key, CALIPTRA_FIXED_Q, LmsTreeMode::FullRfc8554).unwrap();
        assert_eq!(
            hex::encode_upper(root),
            "9E5C4E82ABF00291EB53D652266C23E1250CAFAC0117FED4"
        );
    }
}
