/*++

Licensed under the Apache-2.0 license.

File Name:

   soc_man.rs

Abstract:

    SoC manifest overlay for aspeed authorization manifest application

--*/

use crate::config;
use p384::ecdsa::Signature;
use std::mem::size_of;
use std::path::{Path, PathBuf};

const IMAGE_METADATA_MAX_COUNT: usize = 127;

#[derive(Clone, Copy)]
#[repr(C)]
struct AspeedAuthManifestPreamble {
    magic: u32,
    size: u32,
    ver: u32,
    flags: u32,
    vnd_manifest_ecc_pubk: [u8; 96],
    vnd_manifest_lms_pubk: [u8; 48],
    vnd_manifest_ecc_sig: [u8; 96],
    vnd_manifest_lms_sig: [u8; 1620],
    owner_manifest_ecc_pubk: [u8; 96],
    owner_manifest_lms_pubk: [u8; 48],
    owner_manifest_ecc_sig: [u8; 96],
    owner_manifest_lms_sig: [u8; 1620],
    vnd_matadata_ecc_sig: [u8; 96],
    vnd_matadata_lms_sig: [u8; 1620],
    owner_matadata_ecc_sig: [u8; 96],
    owner_matadata_lms_sig: [u8; 1620],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AspeedAuthManifestImageMetadata {
    id: u32,
    flags: u32,
    digest: [u8; 48],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AspeedAuthManifestImageMetadataCollection {
    pub(crate) count: u32,
    pub(crate) metadata_list: [AspeedAuthManifestImageMetadata; IMAGE_METADATA_MAX_COUNT],
}

pub(crate) struct AspeedAuthorizationManifest {
    path: PathBuf,
    preamble: AspeedAuthManifestPreamble,
    metadata_col: AspeedAuthManifestImageMetadataCollection,
}

fn from_img<T: Copy>(buf: &[u8], offset: usize) -> T {
    assert!(offset + size_of::<T>() <= buf.len(), "Out of bounds");
    unsafe {
        let ptr = buf.as_ptr().add(offset) as *const T;
        ptr.read_unaligned()
    }
}

fn to_img<T: Copy>(val: &T) -> Vec<u8> {
    let size = std::mem::size_of::<T>();
    let ptr = val as *const T as *const u8;
    unsafe { std::slice::from_raw_parts(ptr, size).to_vec() }
}

impl AspeedAuthorizationManifest {
    pub(crate) fn new(path: &PathBuf) -> Self {
        let img = std::fs::read(path).expect("Failed to read SoC manifest file");

        let preamble = from_img::<AspeedAuthManifestPreamble>(&img, 0);
        let metadata_col = from_img::<AspeedAuthManifestImageMetadataCollection>(
            &img,
            size_of::<AspeedAuthManifestPreamble>(),
        );

        Self {
            path: path.clone(),
            preamble,
            metadata_col,
        }
    }

    pub(crate) fn close(&self) {
        let preamble = to_img(&self.preamble);
        let metadata_col = to_img(&self.metadata_col);
        let mut image = Vec::new();

        image.extend_from_slice(&preamble);
        image.extend_from_slice(&metadata_col);

        std::fs::write(self.path.clone(), image).expect("Failed to write SoC manifest file");
    }

    pub(crate) fn mdy_vnd_ecc_sig(&mut self, cfg: &config::AspeedAuthManifestConfigFromFile) {
        if cfg.manifest_config.vnd_prebuilt_sig.is_empty() {
            return;
        }

        let prebuilt_sig = Path::new(&cfg.manifest_config.vnd_prebuilt_sig);
        if !prebuilt_sig.exists() || !prebuilt_sig.is_file() {
            return;
        }

        /* Read signature from der and convery it to hardware endian */
        let sig_der = std::fs::read(prebuilt_sig).expect("Failed to read the prebuilt signature");
        let sig_raw = Signature::from_der(&sig_der)
            .expect("Failed to parse DER signature")
            .to_vec()
            .chunks_exact(4)
            .flat_map(|chunk| {
                u32::from_le_bytes(chunk.try_into().expect("Chunk size mismatch")).to_be_bytes()
            })
            .collect::<Vec<u8>>();

        self.preamble.vnd_manifest_ecc_pubk = [0; 96];
        self.preamble.vnd_manifest_lms_pubk = [0; 48];
        self.preamble.vnd_manifest_ecc_sig = sig_raw.try_into().expect("Signature size mismatch");
    }
}
