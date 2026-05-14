/*++

Licensed under the Apache-2.0 license.

File Name:

   config.rs

Abstract:

    File contains utilities for parsing image authorization configuration files

--*/

use anyhow::{anyhow, Context, Result};
use clap::ArgMatches;
use hex;
use log::debug;
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use toml::Value;

use crate::utility::PathBufExt;

/* To meet requirement: add FMC to SoC manifest but not in flash images list */
pub static mut MCU_RUN_TIME_FW_ID: u32 = 1;

static GLOBAL_TMP_DIR: Lazy<TempDir> =
    Lazy::new(|| TempDir::new().expect("Failed to create global temp directory"));

static GLOBAL_DUMMY_PATH: Lazy<PathBuf> = Lazy::new(|| {
    let path: PathBuf = GLOBAL_TMP_DIR.path().join("dummy.bin");
    std::fs::File::create(&path).expect("Failed to create dummy.bin");
    path
});

/*  Caliptra defined configuration toml file  */
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub(crate) struct AuthManifestKeyConfigFromFile {
    pub ecc_pub_key: Option<String>,

    pub ecc_priv_key: Option<String>,

    pub lms_pub_key: Option<String>,

    pub lms_priv_key: Option<String>,

    pub mldsa_pub_key: Option<String>,

    pub mldsa_priv_key: Option<String>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct ImageMetadataConfigFromFile {
    pub digest: String,

    pub source: u32,

    pub fw_id: u32,

    pub ignore_auth_check: bool,

    pub load_stage: u32,

    pub svn: Option<u8>,

    pub exec_bit: Option<u32>,

    pub component_id: Option<u32>,

    pub image_load_address: Option<u64>,

    pub image_staging_address: Option<u64>,

    pub classification: Option<u32>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct AuthManifestConfigFromFile {
    pub vendor_fw_key_config: AuthManifestKeyConfigFromFile,

    pub vendor_man_key_config: AuthManifestKeyConfigFromFile,

    pub owner_fw_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub owner_man_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub image_metadata_list: Vec<ImageMetadataConfigFromFile>,

    pub sign_helper: Option<AspeedAuthManifestSignHelper>,
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

    pub security_version: u32,

    pub padding_align_size: Option<u32>,

    pub padding_out_folder: Option<String>,

    pub manifest_overrides_presigned_key_and_signature: Option<bool>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct AspeedImageRuntimeConfigFromFile {
    pub caliptra_file: String,

    pub zero_caliptra_file_end: Option<u32>,

    pub mcu_file: String,

    pub cptra_out_bundle: Option<bool>,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub(crate) struct AspeedImageMetadataConfigFromFile {
    pub file: String,

    pub source: u32,

    pub fw_id: u32,

    pub ignore_auth_check: bool,

    pub load_stage: u32,

    pub svn: Option<u8>,

    pub exec_bit: Option<u32>,

    pub component_id: Option<u32>,

    pub image_load_address: Option<u64>,

    pub image_staging_address: Option<u64>,

    pub classification: Option<u32>,
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct AspeedAuthManifestSignHelper {
    pub owner_ecc_fw_key_sign_helper: Option<String>,
    pub owner_ecc_man_key_sign_helper: Option<String>,
    pub owner_lms_fw_key_sign_helper: Option<String>,
    pub owner_lms_man_key_sign_helper: Option<String>,
    pub by_file: Option<bool>,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub(crate) struct AspeedAuthManifestConfigFromFile {
    pub manifest_config: AspeedAuthManifestGeneralConfigFromFile,

    pub vendor_fw_key_config: AuthManifestKeyConfigFromFile,

    pub vendor_man_key_config: AuthManifestKeyConfigFromFile,

    pub owner_fw_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub owner_man_key_config: Option<AuthManifestKeyConfigFromFile>,

    pub image_runtime_list: AspeedImageRuntimeConfigFromFile,

    pub image_metadata_list: Vec<AspeedImageMetadataConfigFromFile>,

    pub sign_helper: Option<AspeedAuthManifestSignHelper>,
}

pub fn create_tmp_file(name: &str, size: u64, fill: Option<u8>) -> PathBuf {
    let path = GLOBAL_TMP_DIR.path().join(name);
    let mut file = File::create(&path).unwrap();

    match fill {
        Some(byte) => {
            const CHUNK_SIZE: usize = 4096;
            let buf = [byte; CHUNK_SIZE];
            let mut remaining = size;

            while remaining > 0 {
                let to_write = remaining.min(CHUNK_SIZE as u64) as usize;
                file.write_all(&buf[..to_write]).unwrap();
                remaining -= to_write as u64;
            }
        }
        None => {
            file.set_len(size).unwrap();
        }
    }

    path
}

fn pad_to_aligned(mut data: Vec<u8>, pad: u8, aligned: usize) -> Vec<u8> {
    let pad_len = (aligned - (data.len() % aligned)) % aligned;
    data.extend(vec![pad; pad_len]);
    data
}

pub fn check_path_exists<P: AsRef<Path>>(path: P) -> Result<()> {
    let path_ref = path.as_ref();

    if !path_ref.exists() {
        let msg = format!(
            "\x1b[31;1mError: Path or file not found: {:?}\x1b[0m",
            path_ref
        );
        Err(anyhow!(msg))
    } else {
        Ok(())
    }
}

pub fn remove_tmp_folder() -> Result<()> {
    let tmp_path = GLOBAL_TMP_DIR.path();

    if !tmp_path.exists() {
        return Ok(());
    }

    fs::remove_dir_all(tmp_path)
        .map_err(|e| anyhow!("Failed to remove temp dir {:?}: {}", tmp_path, e))?;

    debug!("Removed temporary directory: {:?}", tmp_path);
    Ok(())
}

pub fn get_dummy_path() -> PathBuf {
    GLOBAL_DUMMY_PATH.clone()
}

pub fn make_aligned_padded_copy(
    src: &Path,
    out_dir: &Path,
    align: u64,
    suffix: &str,
) -> anyhow::Result<PathBuf> {
    // No alignment requested
    if align == 0 {
        return Ok(src.to_path_buf());
    }

    fs::create_dir_all(out_dir)?;

    // Build output file name: <stem><suffix>.<ext>
    let padded_name = match (src.file_stem(), src.extension()) {
        (Some(stem), Some(ext)) => format!(
            "{}{}_align_{align}.{ext}",
            stem.to_string_lossy(),
            suffix,
            ext = ext.to_string_lossy()
        ),
        (Some(stem), None) => format!("{}{}_align_{align}", stem.to_string_lossy(), suffix),
        _ => anyhow::bail!("Invalid file name: {:?}", src),
    };

    let dst = out_dir.join(padded_name);

    // Copy source to destination (overwrites if destination already exists)
    fs::copy(src, &dst)?;

    // Calculate how many zero bytes to append to align to `align`
    let file_size = fs::metadata(&dst)?.len();
    let pad_len = (align - (file_size % align)) % align;

    if pad_len > 0 {
        let mut f = fs::OpenOptions::new().append(true).open(&dst)?;

        const CHUNK: usize = 1024 * 1024; // 1MB chunks
        let zeros = vec![0u8; CHUNK];
        let mut remain = pad_len;

        while remain > 0 {
            let n = std::cmp::min(remain as usize, CHUNK);
            f.write_all(&zeros[..n])?;
            remain -= n as u64;
        }
    }

    debug!(
        "Align padded image: {:?}, size {} → {} (align {})",
        dst,
        file_size,
        file_size + pad_len,
        align
    );

    Ok(dst)
}

impl AuthManifestKeyConfigFromFile {
    pub fn has_any_key(&self) -> bool {
        self.ecc_pub_key.is_some()
            || self.ecc_priv_key.is_some()
            || self.lms_pub_key.is_some()
            || self.lms_priv_key.is_some()
    }
}

impl AspeedAuthManifestConfigFromFile {
    fn find_prebuilt_img_path(&mut self, path: &AspeedManifestCreationPath) -> Result<()> {
        // Generate padded file name (preserve extension)
        const PADDING_SUFFIX: &str = "";

        let dummy_path = GLOBAL_DUMMY_PATH.clone();

        let padding_align_size = self.manifest_config.padding_align_size.unwrap_or(0) as u64;
        let padding_out_folder = match self.manifest_config.padding_out_folder.as_deref() {
            Some(folder) if !folder.is_empty() => PathBuf::from(folder),
            _ => {
                let tmp = GLOBAL_TMP_DIR.path().to_string_lossy().to_string();
                self.manifest_config.padding_out_folder = Some(tmp.clone());
                PathBuf::from(tmp)
            }
        };

        self.image_metadata_list = self
            .image_metadata_list
            .iter()
            .map(|img| -> anyhow::Result<AspeedImageMetadataConfigFromFile> {
                // Resolve source image path
                let new_file = if !img.file.is_empty() {
                    path.prebuilt_dir.join(&img.file)
                } else {
                    dummy_path.clone()
                };

                // Ensure source image exists
                check_path_exists(&new_file)?;

                // If padding is enabled, generate an aligned padded copy and return its path.
                // Otherwise, return the original path.
                let final_file_path: PathBuf = if padding_align_size > 0 && !img.file.is_empty() {
                    let padded_path = make_aligned_padded_copy(
                        &new_file,
                        &padding_out_folder,
                        padding_align_size,
                        PADDING_SUFFIX,
                    )?;

                    padded_path
                } else {
                    debug!("New file path: {:?}", new_file);
                    new_file
                };

                Ok(AspeedImageMetadataConfigFromFile {
                    file: final_file_path.to_string_lossy().to_string(),
                    ..(*img).clone()
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        // ---- caliptra runtime ----
        if !self.image_runtime_list.caliptra_file.is_empty() {
            let src = path
                .prebuilt_dir
                .join(&self.image_runtime_list.caliptra_file);
            check_path_exists(&src.to_string_lossy().to_string())?;

            // Generate aligned padded copy if needed, and return padded path
            let padded = make_aligned_padded_copy(
                &src,
                &padding_out_folder,
                padding_align_size,
                PADDING_SUFFIX,
            )?;
            self.image_runtime_list.caliptra_file = padded.to_string_lossy().to_string();
        } else {
            if let Some(zero_caliptra_file_end) = self.image_runtime_list.zero_caliptra_file_end {
                if zero_caliptra_file_end == 0 {
                    self.image_runtime_list.caliptra_file = dummy_path.to_string();
                } else {
                    let image_num = (self.image_metadata_list.len() as u32) - 1 + 3; // +3 for caliptra_fw, soc manifest,mcu_fw
                    let image_header_size = 16 + 12 * image_num;

                    self.image_runtime_list.caliptra_file = create_tmp_file(
                        "caliptra_fw_tmp.bin",
                        (zero_caliptra_file_end - image_header_size) as u64,
                        Some(0),
                    )
                    .to_string();
                    println!(
                        "Created zero-padded caliptra fw file at {}",
                        self.image_runtime_list.caliptra_file
                    );
                }
            } else {
                self.image_runtime_list.caliptra_file = dummy_path.to_string();
            }
        }
        check_path_exists(&self.image_runtime_list.caliptra_file)?;

        // ---- mcu runtime ----
        if !self.image_runtime_list.mcu_file.is_empty() {
            let src = path.prebuilt_dir.join(&self.image_runtime_list.mcu_file);
            check_path_exists(&src.to_string_lossy().to_string())?;

            // Generate aligned padded copy if needed, and return padded path
            let padded = make_aligned_padded_copy(
                &src,
                &padding_out_folder,
                padding_align_size,
                PADDING_SUFFIX,
            )?;
            self.image_runtime_list.mcu_file = padded.to_string_lossy().to_string();
        } else {
            self.image_runtime_list.mcu_file = dummy_path.to_string();
            check_path_exists(&self.image_runtime_list.mcu_file)?;
        }

        Ok(())
    }

    pub(crate) fn new(
        path: &AspeedManifestCreationPath,
    ) -> Result<AspeedAuthManifestConfigFromFile> {
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

        config.find_prebuilt_img_path(path)?;

        Ok(config)
    }

    pub(crate) fn has_any_key(&self) -> bool {
        self.vendor_fw_key_config.has_any_key()
            || self.vendor_man_key_config.has_any_key()
            || self
                .owner_fw_key_config
                .as_ref()
                .map(|c| c.has_any_key())
                .unwrap_or(false)
            || self
                .owner_man_key_config
                .as_ref()
                .map(|c| c.has_any_key())
                .unwrap_or(false)
    }

    pub(crate) fn validate_key_dir_if_needed(
        &self,
        key_dir: Option<&Path>,
    ) -> anyhow::Result<PathBuf> {
        if self.has_any_key() {
            let dir = key_dir
                .ok_or_else(|| anyhow!("Key directory is required when keys are specified"))?;
            check_path_exists(dir)?;
            Ok(dir.to_path_buf())
        } else {
            let tmp_path = GLOBAL_TMP_DIR.path().to_path_buf();
            Ok(tmp_path.join(""))
        }
    }

    pub(crate) fn save_caliptra_cfg(&self, path_mngt: &AspeedManifestCreationPath) -> Result<()> {
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
                let data_align = pad_to_aligned(data, 0, 4);
                let digest = hex::encode(Sha384::digest(&data_align));
                ImageMetadataConfigFromFile {
                    digest: digest,
                    source: img.source,
                    fw_id: img.fw_id,
                    ignore_auth_check: img.ignore_auth_check,
                    load_stage: img.load_stage,
                    svn: img.svn,
                    exec_bit: img.exec_bit,
                    component_id: img.component_id,
                    image_load_address: img.image_load_address,
                    image_staging_address: img.image_staging_address,
                    classification: img.classification,
                }
            })
            .collect();
        cfg.sign_helper = self.sign_helper.clone();

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

    pub tool_dir: PathBuf,

    pub key_dir: Option<PathBuf>,

    pub aspeed_cfg: PathBuf,

    pub caliptra_cfg: Option<PathBuf>,

    pub manifest: Option<PathBuf>,

    pub flash_image: Option<PathBuf>,

    pub svn_sig: Option<PathBuf>,

    pub fw_toc: Option<PathBuf>,
}

impl AspeedManifestCreationPath {
    fn get_config_value(aspeed_cfg: &PathBuf) -> Result<Value> {
        let content = fs::read_to_string(aspeed_cfg)
            .map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;

        let value: Value =
            toml::from_str(&content).map_err(|e| anyhow::anyhow!("Failed to parse TOML: {}", e))?;

        Ok(value)
    }

    fn get_prebuilt_dir_path(args: &ArgMatches, prj: &String) -> Result<PathBuf> {
        let prebuilt_dir = args
            .get_one::<PathBuf>("prebuilt-dir")
            .cloned()
            .unwrap_or_def(PathBuf::from(format!("prebuilt/{}/", prj)));
        check_path_exists(&prebuilt_dir)?;
        Ok(prebuilt_dir)
    }

    fn get_key_dir_path(args: &ArgMatches, prj: &String) -> Result<PathBuf> {
        let key_dir = args
            .get_one::<PathBuf>("key-dir")
            .cloned()
            .unwrap_or_def(PathBuf::from(format!("key/{}/", prj)));
        // Check later if a key has been assigned
        // check_path_exists(&key_dir)?;
        Ok(key_dir)
    }

    fn get_aspeed_cfg_path(config: &String) -> Result<PathBuf> {
        let path = PathBuf::from(config);
        check_path_exists(&path)?;
        Ok(path)
    }

    fn get_out_folder_path(args: &ArgMatches) -> Result<PathBuf> {
        let dir = if let Ok(Some(manifest_path)) = args.try_get_one::<PathBuf>("man") {
            manifest_path
                .parent()
                .unwrap_or_else(|| Path::new("out"))
                .to_path_buf()
        } else if let Ok(Some(flash_path)) = args.try_get_one::<PathBuf>("flash") {
            flash_path
                .parent()
                .unwrap_or_else(|| Path::new("out"))
                .to_path_buf()
        } else {
            PathBuf::from("out")
        };

        if !dir.exists() {
            return Err(anyhow::anyhow!(
                "Output directory does not exist: {:?}",
                dir
            ));
        }

        Ok(dir)
    }

    fn get_caliptra_cfg_path(args: &ArgMatches) -> Result<PathBuf> {
        let dir = Self::get_out_folder_path(args)?;
        let caliptra_cfg_path = dir.join("caliptra-manifest.toml");
        Ok(caliptra_cfg_path)
    }

    fn get_svn_sig_path(args: &ArgMatches) -> Result<PathBuf> {
        let dir = Self::get_out_folder_path(args)?;
        let svn_sig_path = dir.join("svn_sig.bin");
        Ok(svn_sig_path)
    }

    fn get_manifest_path(args: &ArgMatches, prj: &String) -> Result<PathBuf> {
        let manifest = if let Ok(Some(manifest_path)) = args.try_get_one::<PathBuf>("man") {
            manifest_path.clone()
        } else if let Ok(Some(flash_path)) = args.try_get_one::<PathBuf>("flash") {
            let parent = flash_path.parent().unwrap_or_else(|| Path::new("out"));
            parent.join(format!("{}-auth-manifest.bin", prj))
        } else {
            PathBuf::from(format!("out/{}-auth-manifest.bin", prj))
        };

        if let Some(parent) = manifest.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create manifest directory {:?}", parent))?;
            }
        }

        Ok(manifest)
    }

    fn get_fw_toc_path(args: &ArgMatches, prj: &String) -> Result<PathBuf> {
        // Retrieve the flash image path from command-line arguments or use the default
        let flash = Self::flash_image_path(args, prj);
        let fw_toc = flash.with_file_name("fw_toc.bin");

        // Remove the existing file (if any) to avoid conflicts
        if fw_toc.is_file() {
            fs::remove_file(&fw_toc).map_err(|e| {
                anyhow::anyhow!("Failed to remove existing flash file {:?}: {}", fw_toc, e)
            })?;
        }

        Ok(fw_toc)
    }

    fn flash_image_path(args: &ArgMatches, prj: &String) -> PathBuf {
        let flash = args
            .get_one::<PathBuf>("flash")
            .cloned()
            .unwrap_or_else(|| PathBuf::from(format!("out/{}-flash-image.bin", prj)));
        flash
    }

    fn get_flash_image_path(args: &ArgMatches, prj: &String) -> Result<PathBuf> {
        // Retrieve the flash image path from command-line arguments or use the default
        let flash = Self::flash_image_path(args, prj);

        // Ensure that the parent directory exists; create it if necessary
        if let Some(parent) = flash.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    anyhow::anyhow!("Failed to create output directory {:?}: {}", parent, e)
                })?;
            }
        }

        // Remove the existing file (if any) to avoid conflicts
        if flash.is_file() {
            fs::remove_file(&flash).map_err(|e| {
                anyhow::anyhow!("Failed to remove existing flash file {:?}: {}", flash, e)
            })?;
        }

        Ok(flash)
    }

    fn get_tool_path() -> PathBuf {
        let cur_exe = env::current_exe().unwrap().parent().unwrap().to_path_buf();
        let paths = [
            PathBuf::from("./target/release"),
            PathBuf::from("./target/debug"),
        ];

        for path in paths.iter() {
            let man_tool = path.join("caliptra-auth-manifest-app");
            let flash_tool = path.join("xtask");

            if man_tool.is_file() && flash_tool.is_file() {
                return path.to_path_buf();
            }
        }

        cur_exe
    }

    fn get_project_name(aspeed_cfg: &PathBuf) -> Result<String> {
        let value = Self::get_config_value(aspeed_cfg)?;
        // try to get "manifest_config" -> "prj_name" else default to "default_project"
        let project_name = value
            .get("manifest_config")
            .and_then(|v| v.get("prj_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("default_project");

        Ok(project_name.to_string())
    }

    pub(crate) fn new_manifest(args: &ArgMatches) -> Result<AspeedManifestCreationPath> {
        let config: &String = args
            .get_one::<String>("cfg")
            .with_context(|| "cfg arg not specified")?;

        let aspeed_cfg = Self::get_aspeed_cfg_path(config)?;
        let prj = Self::get_project_name(&aspeed_cfg)?;

        Ok(AspeedManifestCreationPath {
            prebuilt_dir: Self::get_prebuilt_dir_path(&args, &prj)?,
            tool_dir: Self::get_tool_path(),
            key_dir: Some(Self::get_key_dir_path(&args, &prj)?),
            aspeed_cfg,
            caliptra_cfg: Some(Self::get_caliptra_cfg_path(&args)?),
            manifest: Some(Self::get_manifest_path(args, &prj)?),
            flash_image: None,
            svn_sig: Some(Self::get_svn_sig_path(args)?),
            fw_toc: None,
        })
    }

    pub(crate) fn new_flash(args: &ArgMatches) -> Result<AspeedManifestCreationPath> {
        let config: &String = args
            .get_one::<String>("cfg")
            .with_context(|| "cfg arg not specified")?;

        let aspeed_cfg = Self::get_aspeed_cfg_path(config)?;
        let prj = Self::get_project_name(&aspeed_cfg)?;

        Ok(AspeedManifestCreationPath {
            prebuilt_dir: Self::get_prebuilt_dir_path(&args, &prj)?,
            tool_dir: Self::get_tool_path(),
            key_dir: None,
            aspeed_cfg,
            caliptra_cfg: None,
            manifest: Some(Self::get_manifest_path(args, &prj)?),
            flash_image: Some(Self::get_flash_image_path(args, &prj)?),
            svn_sig: None,
            fw_toc: Some(Self::get_fw_toc_path(args, &prj)?),
        })
    }
}
