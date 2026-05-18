/*++

Licensed under the Apache-2.0 license.

Modified by ASPEED Technology Inc., 2026-04-16: Support load stage filed in manifest flags
Modified by ASPEED Technology Inc., 2026-04-16: Make the auth manifest tool more flexible to support different signature combinations
Modified by ASPEED Technology Inc., 2026-04-16: Support sign helper config input
Modified by ASPEED Technology Inc., 2026-04-16: Ime flag support svn
Modified by ASPEED Technology Inc., 2026-05-18: Rename the Rust dependency crate import for compatibility with two versions of the auth manifest
                                                generation tool, and remove unused dependencies: caliptra-drivers and caliptra-image-elf.

File Name:

   config.rs

Abstract:

    File contains utilities for parsing image authorization configuration files

--*/

use anyhow::Context;
use caliptra_auth_man_gen_1x::{
    AspeedAuthManifestSignHelper, AuthManifestECCKeyPair, AuthManifestGeneratorEccKeyConfig,
    AuthManifestGeneratorEccKeyOptionalConfig, AuthManifestGeneratorKeyConfig,
    AuthManifestGeneratorLmsKeyConfig, AuthManifestGeneratorLmsKeyOptionalConfig,
    AuthManifestLmsKeyPair,
};
use caliptra_auth_man_types_1x::{AuthManifestImageMetadata, AuthManifestPrivKeys};
use caliptra_auth_man_types_1x::{AuthManifestPubKeys, ImageMetadataFlags};
#[cfg(feature = "openssl")]
use caliptra_image_crypto_1x::OsslCrypto as Crypto;
#[cfg(feature = "rustcrypto")]
use caliptra_image_crypto_1x::RustCrypto as Crypto;
use caliptra_image_crypto_1x::{lms_priv_key_from_pem, lms_pub_key_from_pem};
use caliptra_image_gen_1x::*;
use serde_derive::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Authorization Manifest Key configuration from config file.
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct AuthManifestKeyConfigFromFile {
    pub ecc_pub_key: String,

    pub ecc_priv_key: Option<String>,

    pub lms_pub_key: String,

    pub lms_priv_key: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct AspeedAuthManifestKeyConfigFromFile {
    pub ecc_pub_key: Option<String>,

    pub ecc_priv_key: Option<String>,

    pub lms_pub_key: Option<String>,

    pub lms_priv_key: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ImageMetadataConfigFromFile {
    digest: String,
    source: u32,
    fw_id: u32,
    ignore_auth_check: bool,
    svn: Option<u8>,
    load_stage: u32,
}

// Authorization Manifest configuration from TOML file
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct AuthManifestConfigFromFile {
    pub vendor_fw_key_config: AuthManifestKeyConfigFromFile,

    pub vendor_man_key_config: AuthManifestKeyConfigFromFile,

    pub owner_fw_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub owner_man_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub image_metadata_list: Vec<ImageMetadataConfigFromFile>,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct AspeedAuthManifestConfigFromFile {
    pub vendor_fw_key_config: Option<AspeedAuthManifestKeyConfigFromFile>,

    pub vendor_man_key_config: Option<AspeedAuthManifestKeyConfigFromFile>,

    pub owner_fw_key_config: Option<AspeedAuthManifestKeyConfigFromFile>,

    pub owner_man_key_config: Option<AspeedAuthManifestKeyConfigFromFile>,

    pub image_metadata_list: Vec<ImageMetadataConfigFromFile>,

    pub sign_helper: Option<AspeedAuthManifestSignHelper>,
}

/// Load Authorization Manifest Key Configuration from file
pub(crate) fn load_auth_man_config_from_file(
    path: &PathBuf,
) -> anyhow::Result<AuthManifestConfigFromFile> {
    let config_str = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read the config file {}", path.display()))?;

    let config: AuthManifestConfigFromFile = toml::from_str(&config_str)
        .with_context(|| format!("Failed to parse the config file {}", path.display()))?;

    Ok(config)
}

pub(crate) fn load_aspeed_auth_man_config_from_file(
    path: &PathBuf,
) -> anyhow::Result<AspeedAuthManifestConfigFromFile> {
    let config_str = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read the config file {}", path.display()))?;

    let config: AspeedAuthManifestConfigFromFile = toml::from_str(&config_str)
        .with_context(|| format!("Failed to parse the config file {}", path.display()))?;

    Ok(config)
}

fn key_config_from_file(
    path: &Path,
    config: &AuthManifestKeyConfigFromFile,
) -> anyhow::Result<AuthManifestGeneratorKeyConfig> {
    // Get the Private Keys.
    let mut priv_keys = AuthManifestPrivKeys::default();
    if let Some(pem_file) = &config.ecc_priv_key {
        let priv_key_path = path.join(pem_file);
        priv_keys.ecc_priv_key = Crypto::ecc_priv_key_from_pem(&priv_key_path)?;
    }

    if let Some(pem_file) = &config.lms_priv_key {
        let priv_key_path = path.join(pem_file);
        priv_keys.lms_priv_key = lms_priv_key_from_pem(&priv_key_path)?;
    }

    Ok(AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeys {
            ecc_pub_key: Crypto::ecc_pub_key_from_pem(&path.join(&config.ecc_pub_key))?,
            lms_pub_key: lms_pub_key_from_pem(&path.join(&config.lms_pub_key))?,
        },

        priv_keys: Some(priv_keys),
    })
}

pub(crate) fn vendor_config_from_file(
    path: &Path,
    config: &AuthManifestKeyConfigFromFile,
) -> anyhow::Result<AuthManifestGeneratorKeyConfig> {
    key_config_from_file(path, config)
}

pub(crate) fn owner_config_from_file(
    path: &Path,
    config: &Option<AuthManifestKeyConfigFromFile>,
) -> anyhow::Result<Option<AuthManifestGeneratorKeyConfig>> {
    if let Some(config) = config {
        let gen_config = key_config_from_file(path, config)?;
        Ok(Some(gen_config))
    } else {
        Ok(None)
    }
}

pub(crate) fn image_metadata_config_from_file(
    config: &Vec<ImageMetadataConfigFromFile>,
) -> anyhow::Result<Vec<AuthManifestImageMetadata>> {
    let mut image_metadata_list = Vec::new();
    let mut fw_ids: Vec<u32> = Vec::new();

    for image in config {
        // Check if the firmware ID is already present in the list.
        if fw_ids.contains(&image.fw_id) {
            return Err(anyhow::anyhow!(
                "Duplicate firmware ID found in the image metadata list"
            ));
        } else {
            fw_ids.push(image.fw_id);
        }

        let digest_vec = hex::decode(&image.digest)?;
        let mut flags = ImageMetadataFlags(0);
        flags.set_ignore_auth_check(image.ignore_auth_check);
        flags.set_image_source(image.source);
        if let Some(svn) = image.svn {
            flags.set_svn(svn as u32);
        }
        flags.set_image_load_stage(image.load_stage);

        let image_metadata = AuthManifestImageMetadata {
            fw_id: image.fw_id,
            flags: flags.0,
            digest: digest_vec.try_into().unwrap(),
        };

        image_metadata_list.push(image_metadata);
    }

    Ok(image_metadata_list)
}

pub(crate) fn ecc_key_config_from_file(
    path: &Path,
    fw_config: &Option<AspeedAuthManifestKeyConfigFromFile>,
    man_config: &Option<AspeedAuthManifestKeyConfigFromFile>,
) -> anyhow::Result<Option<AuthManifestGeneratorEccKeyConfig>> {
    if let (Some(fw_config), Some(man_config)) = (fw_config, man_config) {
        if let (
            Some(fw_ecc_pub_key),
            Some(fw_ecc_priv_key),
            Some(man_ecc_pub_key),
            Some(man_ecc_priv_key),
        ) = (
            &fw_config.ecc_pub_key,
            &fw_config.ecc_priv_key,
            &man_config.ecc_pub_key,
            &man_config.ecc_priv_key,
        ) {
            let mut fw_ecc_key_pair = AuthManifestECCKeyPair::default();
            let mut man_ecc_key_pair = AuthManifestECCKeyPair::default();

            let fw_ecc_pub_key_path = path.join(fw_ecc_pub_key);
            fw_ecc_key_pair.ecc_pub_key = Crypto::ecc_pub_key_from_pem(&fw_ecc_pub_key_path)?;
            let fw_ecc_priv_key_path = path.join(fw_ecc_priv_key);
            fw_ecc_key_pair.ecc_priv_key = Crypto::ecc_priv_key_from_pem(&fw_ecc_priv_key_path)?;
            let man_ecc_pub_key_path = path.join(man_ecc_pub_key);
            man_ecc_key_pair.ecc_pub_key = Crypto::ecc_pub_key_from_pem(&man_ecc_pub_key_path)?;
            let man_ecc_priv_key_path = path.join(man_ecc_priv_key);
            man_ecc_key_pair.ecc_priv_key = Crypto::ecc_priv_key_from_pem(&man_ecc_priv_key_path)?;

            Ok(Some(AuthManifestGeneratorEccKeyConfig {
                fw_ecc_key_pair,
                man_ecc_key_pair,
            }))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

pub(crate) fn lms_key_config_from_file(
    path: &Path,
    fw_config: &Option<AspeedAuthManifestKeyConfigFromFile>,
    man_config: &Option<AspeedAuthManifestKeyConfigFromFile>,
) -> anyhow::Result<Option<AuthManifestGeneratorLmsKeyConfig>> {
    if let (Some(fw_config), Some(man_config)) = (fw_config, man_config) {
        if let (
            Some(fw_lms_pub_key),
            Some(fw_lms_priv_key),
            Some(man_lms_pub_key),
            Some(man_lms_priv_key),
        ) = (
            &fw_config.lms_pub_key,
            &fw_config.lms_priv_key,
            &man_config.lms_pub_key,
            &man_config.lms_priv_key,
        ) {
            let mut fw_lms_key_pair = AuthManifestLmsKeyPair::default();
            let mut man_lms_key_pair = AuthManifestLmsKeyPair::default();

            let fw_lms_pub_key_path = path.join(fw_lms_pub_key);
            fw_lms_key_pair.lms_pub_key = lms_pub_key_from_pem(&fw_lms_pub_key_path)?;

            let fw_lms_priv_key_path = path.join(fw_lms_priv_key);
            fw_lms_key_pair.lms_priv_key = lms_priv_key_from_pem(&fw_lms_priv_key_path)?;

            let man_lms_pub_key_path = path.join(man_lms_pub_key);
            man_lms_key_pair.lms_pub_key = lms_pub_key_from_pem(&man_lms_pub_key_path)?;

            let man_lms_priv_key_path = path.join(man_lms_priv_key);
            man_lms_key_pair.lms_priv_key = lms_priv_key_from_pem(&man_lms_priv_key_path)?;

            Ok(Some(AuthManifestGeneratorLmsKeyConfig {
                fw_lms_key_pair,
                man_lms_key_pair,
            }))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

pub(crate) fn ecc_key_optional_config_from_file(
    path: &Path,
    man_config: &Option<AspeedAuthManifestKeyConfigFromFile>,
) -> anyhow::Result<AuthManifestGeneratorEccKeyOptionalConfig> {
    if let Some(man_config) = man_config {
        let mut config = AuthManifestGeneratorEccKeyOptionalConfig::default();

        if let Some(man_ecc_pub_key) = &man_config.ecc_pub_key {
            let man_ecc_pub_key_path = path.join(man_ecc_pub_key);
            config.man_ecc_pub_key = Some(Crypto::ecc_pub_key_from_pem(&man_ecc_pub_key_path)?);
        }

        if let Some(man_ecc_priv_key) = &man_config.ecc_priv_key {
            let man_ecc_priv_key_path = path.join(man_ecc_priv_key);
            config.man_ecc_priv_key = Some(Crypto::ecc_priv_key_from_pem(&man_ecc_priv_key_path)?);
        }

        Ok(config)
    } else {
        Ok(AuthManifestGeneratorEccKeyOptionalConfig {
            man_ecc_pub_key: None,
            man_ecc_priv_key: None,
        })
    }
}

pub(crate) fn lms_key_optional_config_from_file(
    path: &Path,
    man_config: &Option<AspeedAuthManifestKeyConfigFromFile>,
) -> anyhow::Result<AuthManifestGeneratorLmsKeyOptionalConfig> {
    if let Some(man_config) = man_config {
        let mut config = AuthManifestGeneratorLmsKeyOptionalConfig::default();

        if let Some(man_lms_pub_key) = &man_config.lms_pub_key {
            let man_lms_pub_key_path = path.join(man_lms_pub_key);
            config.man_lms_pub_key = Some(lms_pub_key_from_pem(&man_lms_pub_key_path)?);
        }

        if let Some(man_lms_priv_key) = &man_config.lms_priv_key {
            let man_lms_priv_key_path = path.join(man_lms_priv_key);
            config.man_lms_priv_key = Some(lms_priv_key_from_pem(&man_lms_priv_key_path)?);
        }

        Ok(config)
    } else {
        Ok(AuthManifestGeneratorLmsKeyOptionalConfig {
            man_lms_pub_key: None,
            man_lms_priv_key: None,
        })
    }
}
