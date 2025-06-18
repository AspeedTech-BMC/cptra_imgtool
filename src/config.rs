/*++

Licensed under the Apache-2.0 license.

File Name:

   config.rs

Abstract:

    File contains utilities for parsing image authorization configuration files

--*/

use anyhow::Context;
use clap::ArgMatches;
use hex;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::io::Write;
use std::path::PathBuf;

use crate::utility::PathBufExt;

/*  Caliptra defined configuration toml file  */
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

/* Aspeed defined configuration toml file */
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub(crate) struct AspeedManifestToolDependencies {
    pub caliptra_sw_auth: String,

    pub caliptra_mcu_sw: String,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub(crate) struct AspeedAuthManifestGeneralConfigFromFile {
    pub version: u32,

    pub flags: u32,

    pub vnd_prebuilt_sig: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct AspeedImageRuntimeConfigFromFile {
    pub caliptra_file: String,

    pub mcu_file: String,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub(crate) struct AspeedImageMetadataConfigFromFile {
    pub file: String,

    pub source: u32,

    pub fw_id: u32,

    pub ignore_auth_check: bool,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct AspeedAuthManifestConfigFromFile {
    pub authtool: AspeedManifestToolDependencies,

    pub manifest_config: AspeedAuthManifestGeneralConfigFromFile,

    pub vendor_fw_key_config: AuthManifestKeyConfigFromFile,

    pub vendor_man_key_config: AuthManifestKeyConfigFromFile,

    pub owner_fw_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub owner_man_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub image_runtime_list: AspeedImageRuntimeConfigFromFile,

    pub image_metadata_list: Vec<AspeedImageMetadataConfigFromFile>,
}

impl AspeedAuthManifestConfigFromFile {
    fn find_prebuilt_img_path(&mut self, path: &AspeedManifestCreationPath) {
        let sig = &self.manifest_config.vnd_prebuilt_sig;
        self.manifest_config.vnd_prebuilt_sig = match sig.is_empty() {
            true => String::new(),
            false => path.prebuilt_dir.join(sig).to_string(),
        };

        self.image_metadata_list = self
            .image_metadata_list
            .iter()
            .map(|img| {
                let new_file = path.prebuilt_dir.join(&img.file);
                AspeedImageMetadataConfigFromFile {
                    file: new_file.to_string(),
                    ..(*img).clone()
                }
            })
            .collect::<Vec<_>>();

        self.image_runtime_list.caliptra_file = path
            .prebuilt_dir
            .join(&self.image_runtime_list.caliptra_file)
            .to_string();
        self.image_runtime_list.mcu_file = path
            .prebuilt_dir
            .join(&self.image_runtime_list.mcu_file)
            .to_string();
    }

    pub(crate) fn new(
        path: &AspeedManifestCreationPath,
    ) -> anyhow::Result<AspeedAuthManifestConfigFromFile> {
        let config_str = std::fs::read_to_string(&path.aspeed_cfg).with_context(|| {
            format!(
                "Failed to read the config file {}",
                path.aspeed_cfg.display()
            )
        })?;

        let mut config: AspeedAuthManifestConfigFromFile = toml::from_str(&config_str)
            .with_context(|| {
                format!(
                    "Failed to parse the config file {}",
                    path.aspeed_cfg.display()
                )
            })?;

        config.find_prebuilt_img_path(path);

        Ok(config)
    }

    pub(crate) fn save_caliptra_cfg(
        &self,
        path_mngt: &AspeedManifestCreationPath,
    ) -> anyhow::Result<()> {
        let mut cfg: AuthManifestConfigFromFile = AuthManifestConfigFromFile::default();

        /* Read the configuration from aspeed manifest configuration */
        cfg.vendor_fw_key_config = self.vendor_fw_key_config.clone();
        cfg.vendor_man_key_config = self.vendor_man_key_config.clone();
        cfg.owner_fw_key_config = self.owner_fw_key_config.clone();
        cfg.owner_man_key_config = self.owner_man_key_config.clone();
        cfg.image_metadata_list = self
            .image_metadata_list
            .iter()
            .map(|img| {
                let data = std::fs::read(&img.file).unwrap();
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
        let caliptra_cfg = &path_mngt.caliptra_cfg.unwrap_or_err();
        let mut out_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(caliptra_cfg)
            .with_context(|| format!("Failed to create file {}", caliptra_cfg.display()))?;

        out_file.write_all(toml::to_string(&cfg).unwrap().as_bytes())?;

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct AspeedManifestCreationPath {
    pub prebuilt_dir: PathBuf,

    pub key_dir: Option<PathBuf>,

    pub aspeed_cfg: PathBuf,

    pub caliptra_cfg: Option<PathBuf>,

    pub manifest: Option<PathBuf>,

    pub flash_image: Option<PathBuf>,
}

impl AspeedManifestCreationPath {
    fn get_prebuilt_dir_path(prj: &String) -> PathBuf {
        PathBuf::from(format!("prebuilt/{}/", prj)).to_absolute()
    }

    fn get_key_dir_path(prj: &String) -> PathBuf {
        PathBuf::from(format!("key/{}/", prj)).to_absolute()
    }

    fn get_aspeed_cfg_path(prj: &String) -> PathBuf {
        PathBuf::from(format!("config/{}-manifest.toml", prj)).to_absolute()
    }

    fn get_caliptra_cfg_path() -> PathBuf {
        PathBuf::from("config/caliptra-manifest.toml").to_absolute()
    }

    fn get_manifest_path(args: &ArgMatches, prj: &String) -> PathBuf {
        let manifest = args
            .get_one::<PathBuf>("man")
            .cloned()
            .unwrap_or_def(PathBuf::from(format!("out/{}-auth-manifest.bin", prj)));

        manifest.to_absolute()
    }

    fn get_flash_image_path(args: &ArgMatches, prj: &String) -> PathBuf {
        let flash = args
            .get_one::<PathBuf>("flash")
            .cloned()
            .unwrap_or_def(PathBuf::from(format!("out/{}-flash-image.bin", prj)));

        if flash.is_file() {
            let _ = std::fs::remove_file(&flash);
        }

        flash.to_absolute()
    }

    pub(crate) fn new_manifest(args: &ArgMatches) -> anyhow::Result<AspeedManifestCreationPath> {
        let prj: &String = args
            .get_one::<String>("prj")
            .with_context(|| "prj arg not specified")?;

        Ok(AspeedManifestCreationPath {
            prebuilt_dir: Self::get_prebuilt_dir_path(prj),
            key_dir: Some(Self::get_key_dir_path(prj)),
            aspeed_cfg: Self::get_aspeed_cfg_path(prj),
            caliptra_cfg: Some(Self::get_caliptra_cfg_path()),
            manifest: Some(Self::get_manifest_path(args, prj)),
            flash_image: None,
        })
    }

    pub(crate) fn new_flash(args: &ArgMatches) -> anyhow::Result<AspeedManifestCreationPath> {
        let prj: &String = args
            .get_one::<String>("prj")
            .with_context(|| "prj arg not specified")?;

        Ok(AspeedManifestCreationPath {
            prebuilt_dir: Self::get_prebuilt_dir_path(prj),
            key_dir: None,
            aspeed_cfg: Self::get_aspeed_cfg_path(prj),
            caliptra_cfg: None,
            manifest: Some(Self::get_manifest_path(args, prj)),
            flash_image: Some(Self::get_flash_image_path(args, prj)),
        })
    }

    pub(crate) fn manifest_exists(&self, args: &ArgMatches) -> bool {
        args.get_one::<String>("prj").map_or(false, |prj| {
            // perform check with `prj`
            let manifest = Self::get_manifest_path(args, prj);
            manifest.exists() && manifest.is_file()
        })
    }
}
