/*++

Licensed under the Apache-2.0 license.

File Name:

   soc_man.rs

Abstract:

    SoC manifest overlay for aspeed authorization manifest application

--*/

use crate::config;
use crate::utility::PathBufExt;
use anyhow::{anyhow, Result};
use log::{debug, info};
use p384::ecdsa::Signature;
use std::mem::size_of;
use std::path::PathBuf;

const IMAGE_METADATA_MAX_COUNT: usize = 127;
const ECC384_SIG_SIZE: usize = 96;
const ECC384_PUBK_SIZE: usize = 96;
const SHA384_DIGEST_SIZE: usize = 48;
const LMS_SIG_SIZE: usize = 1620;
const LMS_PUBK_SIZE: usize = 48;

#[derive(Clone, Copy)]
#[repr(C)]
struct AuthManifestPreamble {
    magic: u32,
    size: u32,
    ver: u32,
    flags: u32,
    vnd_manifest_ecc_pubk: [u8; ECC384_PUBK_SIZE],
    vnd_manifest_lms_pubk: [u8; LMS_PUBK_SIZE],
    vnd_manifest_ecc_sig: [u8; ECC384_SIG_SIZE],
    vnd_manifest_lms_sig: [u8; LMS_SIG_SIZE],
    owner_manifest_ecc_pubk: [u8; ECC384_PUBK_SIZE],
    owner_manifest_lms_pubk: [u8; LMS_PUBK_SIZE],
    owner_manifest_ecc_sig: [u8; ECC384_SIG_SIZE],
    owner_manifest_lms_sig: [u8; LMS_SIG_SIZE],
    vnd_matadata_ecc_sig: [u8; ECC384_SIG_SIZE],
    vnd_matadata_lms_sig: [u8; LMS_SIG_SIZE],
    owner_matadata_ecc_sig: [u8; ECC384_SIG_SIZE],
    owner_matadata_lms_sig: [u8; LMS_SIG_SIZE],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AspeedAuthManifestPreamble {
    magic: u32,
    size: u32,
    ver: u32,
    sec_ver: u32,
    flags: u32,
    vnd_manifest_ecc_pubk: [u8; ECC384_PUBK_SIZE],
    vnd_manifest_lms_pubk: [u8; LMS_PUBK_SIZE],
    vnd_manifest_ecc_sig: [u8; ECC384_SIG_SIZE],
    vnd_manifest_lms_sig: [u8; LMS_SIG_SIZE],
    owner_manifest_ecc_pubk: [u8; ECC384_PUBK_SIZE],
    owner_manifest_lms_pubk: [u8; LMS_PUBK_SIZE],
    owner_manifest_ecc_sig: [u8; ECC384_SIG_SIZE],
    owner_manifest_lms_sig: [u8; LMS_SIG_SIZE],
    owner_manifest_svn_ecc_sig: [u8; ECC384_SIG_SIZE],
    owner_manifest_svn_lms_sig: [u8; LMS_SIG_SIZE],
    vnd_matadata_ecc_sig: [u8; ECC384_SIG_SIZE],
    vnd_matadata_lms_sig: [u8; LMS_SIG_SIZE],
    owner_matadata_ecc_sig: [u8; ECC384_SIG_SIZE],
    owner_matadata_lms_sig: [u8; LMS_SIG_SIZE],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AspeedAuthManifestImageMetadata {
    id: u32,
    flags: u32,
    digest: [u8; SHA384_DIGEST_SIZE],
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

const VND_ECC_SIG_BIN: &[u8] = include_bytes!("vnd_sig/vnd_ecc_sig.der");
const VND_LMS_SIG_BIN: &[u8] = include_bytes!("vnd_sig/vnd_lms_sig.der");
const _: () = assert!(VND_ECC_SIG_BIN.len() == 103, "VND_ECC_SIG_BIN size error!");
const _: () = assert!(VND_LMS_SIG_BIN.len() == 1620, "VND_LMS_SIG_BIN size error!");

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

        let ori_preamble = from_img::<AuthManifestPreamble>(&img, 0);
        let metadata_col = from_img::<AspeedAuthManifestImageMetadataCollection>(
            &img,
            size_of::<AuthManifestPreamble>(),
        );

        let preamble = AspeedAuthManifestPreamble {
            magic: ori_preamble.magic,
            size: ori_preamble.size,
            ver: ori_preamble.ver,
            sec_ver: 0, // Security version is not used in the official manifest
            flags: ori_preamble.flags,
            vnd_manifest_ecc_pubk: ori_preamble.vnd_manifest_ecc_pubk,
            vnd_manifest_lms_pubk: ori_preamble.vnd_manifest_lms_pubk,
            vnd_manifest_ecc_sig: ori_preamble.vnd_manifest_ecc_sig,
            vnd_manifest_lms_sig: ori_preamble.vnd_manifest_lms_sig,
            owner_manifest_ecc_pubk: ori_preamble.owner_manifest_ecc_pubk,
            owner_manifest_lms_pubk: ori_preamble.owner_manifest_lms_pubk,
            owner_manifest_ecc_sig: ori_preamble.owner_manifest_ecc_sig,
            owner_manifest_lms_sig: ori_preamble.owner_manifest_lms_sig,
            owner_manifest_svn_ecc_sig: [0; ECC384_SIG_SIZE], // Placeholder for SVN ECC signature
            owner_manifest_svn_lms_sig: [0; LMS_SIG_SIZE],    // Placeholder for SVN LMS signature
            vnd_matadata_ecc_sig: ori_preamble.vnd_matadata_ecc_sig,
            vnd_matadata_lms_sig: ori_preamble.vnd_matadata_lms_sig,
            owner_matadata_ecc_sig: ori_preamble.owner_matadata_ecc_sig,
            owner_matadata_lms_sig: ori_preamble.owner_matadata_lms_sig,
        };

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

    pub(crate) fn modify_vnd_ecc_sig(
        &mut self,
    ) -> Result<()> {
        // Skip modification if not configured
        if self.preamble.vnd_manifest_ecc_sig == [0u8; ECC384_SIG_SIZE] {
            info!("No need to modify vendor ECC signature.");
            return Ok(());
        }

        let sig_der = VND_ECC_SIG_BIN.to_vec();

        // Parse DER and convert to raw little-endian hardware format
        let sig_raw = Signature::from_der(&sig_der)
            .map_err(|_| anyhow!("Failed to parse DER signature"))?
            .to_vec()
            .chunks_exact(4)
            .flat_map(|chunk| {
                u32::from_le_bytes(chunk.try_into().expect("Chunk size mismatch")).to_be_bytes()
            })
            .collect::<Vec<u8>>();

        debug!("Prebuilt signature ECC: {:02x?}", sig_raw);

        // Apply to preamble
        self.preamble.vnd_manifest_ecc_pubk = [0; ECC384_PUBK_SIZE];
        self.preamble.vnd_manifest_ecc_sig = sig_raw
            .try_into()
            .map_err(|_| anyhow!("Signature size mismatch"))?;

        Ok(())
    }

    pub(crate) fn modify_vnd_lms_sig(
        &mut self,
    ) -> Result<()> {
        // Skip modification if not configured
        if self.preamble.vnd_manifest_lms_sig == [0u8; LMS_SIG_SIZE] {
            info!("No need to modify vendor LMS signature.");
            return Ok(());
        }

        let sig_raw = VND_LMS_SIG_BIN.to_vec();

        debug!("Prebuilt signature LMS: {:02x?}", sig_raw);

        // Apply to preamble
        self.preamble.vnd_manifest_lms_pubk = [0; LMS_PUBK_SIZE];
        self.preamble.vnd_manifest_lms_sig = sig_raw
            .try_into()
            .map_err(|_| anyhow!("Signature size mismatch"))?;

        Ok(())
    }

    pub(crate) fn insert_security_version(
        &mut self,
        path: &config::AspeedManifestCreationPath,
        cfg: &config::AspeedAuthManifestConfigFromFile,
        key_dir: &PathBuf,
    ) {
        let cmd = path.tool_dir.join("caliptra-auth-manifest-app");
        let mut child = std::process::Command::new(cmd)
            .args([
                "create-sig-svn",
                "--version",
                &cfg.manifest_config.version.to_string(),
                "--sec-version",
                &cfg.manifest_config.security_version.to_string(),
                "--flags",
                &cfg.manifest_config.flags.to_string(),
                "--key-dir",
                &key_dir.to_string(),
                "--config",
                &path.caliptra_cfg.to_string(),
                "--out",
                &path.svn_sig.to_string(),
            ])
            .spawn()
            .expect("Failed to execute command");

        /* Wait for the process to exit */
        let _ = child.wait().expect("Failed to wait on child");

        let sig =
            std::fs::read(path.svn_sig.unwrap_or_err()).expect("Failed to read svn signature file");
        let ecc_sig: [u8; ECC384_SIG_SIZE] = from_img(&sig, 0);
        let mut lms_sig: [u8; LMS_SIG_SIZE] = from_img(&sig, ECC384_SIG_SIZE);

        // Convert lms q endianness to match rom verification.
        lms_sig[0..4].reverse();

        debug!("Security Version ECC Signature: {:02x?}", ecc_sig);
        debug!("Security Version LMS Signature: {:02x?}", lms_sig);
        self.preamble.sec_ver = cfg.manifest_config.security_version;
        self.preamble.owner_manifest_svn_ecc_sig = ecc_sig;
        self.preamble.owner_manifest_svn_lms_sig = lms_sig;
    }
}
