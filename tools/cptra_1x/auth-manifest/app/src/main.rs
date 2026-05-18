/*++

Licensed under the Apache-2.0 license.

Modified by ASPEED Technology Inc., 2026-04-16: Support generate anti-rollback signature
Modified by ASPEED Technology Inc., 2026-04-16: Make the auth manifest tool more flexible to support different signature combinations
Modified by ASPEED Technology Inc., 2026-04-16: Support sign helper config input
Modified by ASPEED Technology Inc., 2026-05-18: Rename the Rust dependency crate import for compatibility with two versions of the auth manifest
                                                generation tool, and remove unused dependencies: caliptra-drivers and caliptra-image-elf.

File Name:

   main.rs

Abstract:

    Main entry point for Caliptra Authorization Manifest application

--*/

use anyhow::Context;
use caliptra_auth_man_gen_1x::{
    AspeedAuthManifestGeneratorConfig, AuthManifestGenerator, AuthManifestGeneratorConfig,
};
use caliptra_auth_man_types_1x::AuthManifestFlags;
#[cfg(feature = "openssl")]
use caliptra_image_crypto_1x::OsslCrypto as Crypto;
#[cfg(feature = "rustcrypto")]
use caliptra_image_crypto_1x::RustCrypto as Crypto;
use clap::ArgMatches;
use clap::{arg, value_parser, Command};
use std::io::Write;
use std::path::PathBuf;
use zerocopy::IntoBytes;
mod config;

/// Entry point
fn main() {
    let sub_cmds = vec![
        Command::new("create-auth-man")
            .about("Create a new authorization manifest")
            .arg(
                arg!(--"version" <U32> "Manifest Version Number")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                arg!(--"flags" <U32> "Manifest Flags")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                arg!(--"key-dir" <FILE> "Key files directory path")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"config" <FILE> "Manifest configuration file")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"out" <FILE> "Output file")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            ),
        Command::new("create-aspeed-auth-man")
            .about("Create a new authorization manifest")
            .arg(
                arg!(--"version" <U32> "Manifest Version Number")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                arg!(--"flags" <U32> "Manifest Flags")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                arg!(--"key-dir" <FILE> "Key files directory path")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"config" <FILE> "Manifest configuration file")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"out" <FILE> "Output file")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            ),
        Command::new("create-sig-svn")
            .about("Create a new authorization svn manifest")
            .arg(
                arg!(--"version" <U32> "Manifest Version Number")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                arg!(--"sec-version" <U32> "Security Version Number")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                arg!(--"flags" <U32> "Manifest Flags")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                arg!(--"key-dir" <FILE> "Key files directory path")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"config" <FILE> "Manifest configuration file")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"out" <FILE> "Output file")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            ),
    ];

    let cmd = Command::new("caliptra-auth-man-app")
        .arg_required_else_help(true)
        .subcommands(sub_cmds)
        .about("Caliptra authorization manifest tools")
        .get_matches();

    let result = match cmd.subcommand().unwrap() {
        ("create-auth-man", args) => run_auth_man_cmd(args),
        ("create-aspeed-auth-man", args) => run_aspeed_auth_man_cmd(args),
        ("create-sig-svn", args) => run_sig_svn_cmd(args),
        (_, _) => unreachable!(),
    };

    result.unwrap();
}

pub(crate) fn run_auth_man_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let version: &u32 = args
        .get_one::<u32>("version")
        .with_context(|| "version arg not specified")?;

    let flags: AuthManifestFlags = AuthManifestFlags::from_bits_truncate(
        *args
            .get_one::<u32>("flags")
            .with_context(|| "flags arg not specified")?,
    );

    let config_path: &PathBuf = args
        .get_one::<PathBuf>("config")
        .with_context(|| "config arg not specified")?;

    if !config_path.exists() {
        return Err(anyhow::anyhow!("Invalid config file path"));
    }

    let key_dir: &PathBuf = args
        .get_one::<PathBuf>("key-dir")
        .with_context(|| "key-dir arg not specified")?;

    if !key_dir.exists() {
        return Err(anyhow::anyhow!("Invalid key directory path"));
    }

    let out_path: &PathBuf = args
        .get_one::<PathBuf>("out")
        .with_context(|| "out arg not specified")?;

    // Load the manifest configuration from the config file.
    let config = config::load_auth_man_config_from_file(config_path)?;

    // Decode the configuration.
    let gen_config = AuthManifestGeneratorConfig {
        version: *version,
        flags,
        vendor_man_key_info: config::vendor_config_from_file(
            key_dir,
            &config.vendor_man_key_config,
        )?,
        owner_man_key_info: config::owner_config_from_file(key_dir, &config.owner_man_key_config)?,
        vendor_fw_key_info: config::vendor_config_from_file(key_dir, &config.vendor_fw_key_config)?,
        owner_fw_key_info: config::owner_config_from_file(key_dir, &config.owner_fw_key_config)?,
        image_metadata_list: config::image_metadata_config_from_file(&config.image_metadata_list)?,
    };

    let gen = AuthManifestGenerator::new(Crypto::default());
    let manifest = gen.generate(&gen_config).unwrap();

    let mut out_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_path)
        .with_context(|| format!("Failed to create file {}", out_path.display()))?;

    out_file.write_all(manifest.as_bytes())?;

    Ok(())
}

pub(crate) fn run_aspeed_auth_man_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let version: &u32 = args
        .get_one::<u32>("version")
        .with_context(|| "version arg not specified")?;

    let flags: AuthManifestFlags = AuthManifestFlags::from_bits_truncate(
        *args
            .get_one::<u32>("flags")
            .with_context(|| "flags arg not specified")?,
    );

    let config_path: &PathBuf = args
        .get_one::<PathBuf>("config")
        .with_context(|| "config arg not specified")?;

    if !config_path.exists() {
        return Err(anyhow::anyhow!("Invalid config file path"));
    }

    let key_dir: &PathBuf = args
        .get_one::<PathBuf>("key-dir")
        .with_context(|| "key-dir arg not specified")?;

    if !key_dir.exists() {
        return Err(anyhow::anyhow!("Invalid key directory path"));
    }

    let out_path: &PathBuf = args
        .get_one::<PathBuf>("out")
        .with_context(|| "out arg not specified")?;

    // Load the manifest configuration from the config file.
    let config = config::load_aspeed_auth_man_config_from_file(config_path)?;

    // Decode the configuration.
    let gen_config = AspeedAuthManifestGeneratorConfig {
        version: *version,
        flags,
        vendor_ecc_key_config: config::ecc_key_config_from_file(
            key_dir,
            &config.vendor_fw_key_config,
            &config.vendor_man_key_config,
        )?,
        vendor_lms_key_config: config::lms_key_config_from_file(
            key_dir,
            &config.vendor_fw_key_config,
            &config.vendor_man_key_config,
        )?,
        owner_ecc_key_config: config::ecc_key_config_from_file(
            key_dir,
            &config.owner_fw_key_config,
            &config.owner_man_key_config,
        )?,
        owner_lms_key_config: config::lms_key_config_from_file(
            key_dir,
            &config.owner_fw_key_config,
            &config.owner_man_key_config,
        )?,
        owner_ecc_key_optional_config: config::ecc_key_optional_config_from_file(
            key_dir,
            &config.owner_man_key_config,
        )?,
        owner_lms_key_optional_config: config::lms_key_optional_config_from_file(
            key_dir,
            &config.owner_man_key_config,
        )?,
        image_metadata_list: config::image_metadata_config_from_file(&config.image_metadata_list)?,
        sign_helper: config.sign_helper.clone().unwrap_or_default(),
    };

    let gen = AuthManifestGenerator::new(Crypto::default());
    let manifest = gen.aspeed_generate(&gen_config).unwrap();

    let mut out_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_path)
        .with_context(|| format!("Failed to create file {}", out_path.display()))?;

    out_file.write_all(manifest.as_bytes())?;

    Ok(())
}

pub(crate) fn run_sig_svn_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let version: &u32 = args
        .get_one::<u32>("version")
        .with_context(|| "version arg not specified")?;

    let sec_version: &u32 = args
        .get_one::<u32>("sec-version")
        .with_context(|| "secure version arg not specified")?;

    let flags: AuthManifestFlags = AuthManifestFlags::from_bits_truncate(
        *args
            .get_one::<u32>("flags")
            .with_context(|| "flags arg not specified")?,
    );

    let config_path: &PathBuf = args
        .get_one::<PathBuf>("config")
        .with_context(|| "config arg not specified")?;

    if !config_path.exists() {
        return Err(anyhow::anyhow!("Invalid config file path"));
    }

    let key_dir: &PathBuf = args
        .get_one::<PathBuf>("key-dir")
        .with_context(|| "key-dir arg not specified")?;

    if !key_dir.exists() {
        return Err(anyhow::anyhow!("Invalid key directory path"));
    }

    let out_path: &PathBuf = args
        .get_one::<PathBuf>("out")
        .with_context(|| "out arg not specified")?;

    // Load the manifest configuration from the config file.
    let config = config::load_aspeed_auth_man_config_from_file(config_path)?;

    // Decode the configuration.
    let gen_config = AspeedAuthManifestGeneratorConfig {
        version: *version,
        flags,
        vendor_ecc_key_config: config::ecc_key_config_from_file(
            key_dir,
            &config.vendor_fw_key_config,
            &config.vendor_man_key_config,
        )?,
        vendor_lms_key_config: config::lms_key_config_from_file(
            key_dir,
            &config.vendor_fw_key_config,
            &config.vendor_man_key_config,
        )?,
        owner_ecc_key_config: config::ecc_key_config_from_file(
            key_dir,
            &config.owner_fw_key_config,
            &config.owner_man_key_config,
        )?,
        owner_lms_key_config: config::lms_key_config_from_file(
            key_dir,
            &config.owner_fw_key_config,
            &config.owner_man_key_config,
        )?,
        owner_ecc_key_optional_config: config::ecc_key_optional_config_from_file(
            key_dir,
            &config.owner_man_key_config,
        )?,
        owner_lms_key_optional_config: config::lms_key_optional_config_from_file(
            key_dir,
            &config.owner_man_key_config,
        )?,
        image_metadata_list: config::image_metadata_config_from_file(&config.image_metadata_list)?,
        sign_helper: config.sign_helper.clone().unwrap_or_default(),
    };

    let gen = AuthManifestGenerator::new(Crypto::default());
    let sig = gen.generate_sig_svn(*sec_version, &gen_config).unwrap();

    let mut out_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_path)
        .with_context(|| format!("Failed to create file {}", out_path.display()))?;

    out_file.write_all(sig.as_bytes())?;

    Ok(())
}
