/*++

Licensed under the Apache-2.0 license.

File Name:

   config.rs

Abstract:

    File contains utilities for parsing image authorization configuration files

--*/

use anyhow::Context;
use hex;
use sha2::{Sha384, Digest};
use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub(crate) struct AuthManifestKeyConfigFromFile {
    pub ecc_pub_key: String,

    pub ecc_priv_key: Option<String>,

    pub lms_pub_key: String,

    pub lms_priv_key: Option<String>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct ImageMetadataConfigFromFile {
    pub digest: String,

    pub source: u32,

    pub fw_id: u32,

    pub ignore_auth_check: bool,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct AuthManifestConfigFromFile {
    pub vendor_fw_key_config: AuthManifestKeyConfigFromFile,

    pub vendor_man_key_config: AuthManifestKeyConfigFromFile,

    pub owner_fw_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub owner_man_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub image_metadata_list: Vec<ImageMetadataConfigFromFile>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct AspeedImageMetadataConfigFromFile {
    pub file: String,

    pub source: u32,

    pub fw_id: u32,

    pub ignore_auth_check: bool,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct AspeedAuthManifestConfigFromFile {
    pub version: u32,

    pub flags: u32,

    pub vendor_fw_key_config: AuthManifestKeyConfigFromFile,

    pub vendor_man_key_config: AuthManifestKeyConfigFromFile,

    pub owner_fw_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub owner_man_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub image_metadata_list: Vec<AspeedImageMetadataConfigFromFile>,
}

pub(crate) struct ManifestCreationPath {
    pub aspeed_cfg: PathBuf,

    pub caliptra_cfg: PathBuf,

    pub key_dir: PathBuf,

    pub prebuilt_dir: PathBuf,

    pub manifest: PathBuf,
}

pub(crate) fn new_manifest_path_mgnt(args: &ArgMatches) -> anyhow::Result<ManifestCreationPath> {
    let prj: &String = args
        .get_one::<String>("prj")
        .with_context(|| "prj arg not specified")?;

    let root = env!("CARGO_MANIFEST_DIR");

    let manifest = args
        .get_one::<PathBuf>("out")
        .cloned()
        .unwrap_or_else(|| PathBuf::from(format!("{}/out/{}-auth-manifest.bin", root, prj)));

    let aspeed_cfg = PathBuf::from(format!("{}/config/{}-manifest.toml", root, prj));
    let caliptra_cfg: PathBuf = PathBuf::from(format!("{}/out/{}-manifest.toml", root, prj));
    let key_dir: PathBuf = PathBuf::from(format!("{}/key/{}/", root, prj));
    let prebuilt_dir: PathBuf = PathBuf::from(format!("{}/prebuilt/{}/", root, prj));

    if !aspeed_cfg.exists() || !key_dir.exists() || !prebuilt_dir.exists() {
        return Err(anyhow::anyhow!("Invalid config file path"));
    }

    Ok(ManifestCreationPath {
        aspeed_cfg: aspeed_cfg,
        caliptra_cfg: caliptra_cfg,
        key_dir: key_dir,
        prebuilt_dir: prebuilt_dir,
        manifest: manifest,
    })
}

pub(crate) fn load_auth_man_config_from_aspeed_file(
    path_mngt: &ManifestCreationPath,
) -> anyhow::Result<AspeedAuthManifestConfigFromFile> {
    let config_str = std::fs::read_to_string(&path_mngt.aspeed_cfg).with_context(|| {
        format!(
            "Failed to read the config file {}",
            path_mngt.aspeed_cfg.display()
        )
    })?;

    let config: AspeedAuthManifestConfigFromFile =
        toml::from_str(&config_str).with_context(|| {
            format!(
                "Failed to parse the config file {}",
                path_mngt.aspeed_cfg.display()
            )
        })?;

    Ok(config)
}

pub(crate) fn store_auth_man_config_to_file(
    config: &AspeedAuthManifestConfigFromFile,
    path_mngt: &ManifestCreationPath,
) -> anyhow::Result<()> {
    let mut cfg_file: AuthManifestConfigFromFile = AuthManifestConfigFromFile::default();

    /* Read the configuration from aspeed manifest configuration */
    cfg_file.vendor_fw_key_config = config.vendor_fw_key_config.clone();
    cfg_file.vendor_man_key_config = config.vendor_man_key_config.clone();
    cfg_file.owner_fw_key_config = config.owner_fw_key_config.clone();
    cfg_file.owner_man_key_config = config.owner_man_key_config.clone();
    cfg_file.image_metadata_list = config
        .image_metadata_list
        .iter()
        .map(|img| {
            let data = std::fs::read(path_mngt.prebuilt_dir.join(&img.file)).unwrap();
            // let digest = Crypto {}.sha384_digest(&data).unwrap();
            let digest = hex::encode(Sha384::digest(&data));
            ImageMetadataConfigFromFile {
                digest: digest,
                source: img.source,
                fw_id: img.fw_id,
                ignore_auth_check: img.ignore_auth_check,
            }
        })
        .collect();

    /* Create the caliptra manifest read from aspeed manifest config */
    let mut out_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path_mngt.caliptra_cfg)
        .with_context(|| format!("Failed to create file {}", path_mngt.caliptra_cfg.display()))?;

    out_file.write_all(toml::to_string(&cfg_file).unwrap().as_bytes())?;

    Ok(())
}
