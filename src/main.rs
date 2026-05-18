/*++

Licensed under the Apache-2.0 license.

File Name:

   main.rs

Abstract:

    Main entry point for Caliptra Authorization Manifest application

--*/

use anyhow::Context;
use clap::{arg, value_parser, ArgMatches, Command};
use log::debug;
use std::path::PathBuf;
use utility::PathBufExt;

mod config;
mod fw_toc;
mod fw_toc_1x;
mod soc_man;
mod utility;

const FLASH_TOOL_1X: &str = "xtask";
const FLASH_TOOL_2X: &str = "xtask-2x";

fn main() {
    let sub_cmds = vec![
        Command::new("create-auth-man")
            .about("Create a new authorization manifest")
            .arg(
                arg!(--"cfg" <String> "config path")
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                arg!(--"man" <FILE> "Output manifest file")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"key-dir" <String> "key directory")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"prebuilt-dir" <String> "prebuilt directory")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            ),
        Command::new("create-auth-man-2x")
            .about("Create a new authorization manifest")
            .arg(
                arg!(--"cfg" <String> "config path")
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                arg!(--"man" <FILE> "Output manifest file")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"key-dir" <String> "key directory")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"prebuilt-dir" <String> "prebuilt directory")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"pqc-key-type" <U32> "Type of PQC key validation: 1: MLDSA; 3: LMS")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            ),
        Command::new("create-auth-flash")
            .about("Create a new authorization flash image")
            .arg(
                arg!(--"cfg" <String> "config path")
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                arg!(--"man" <FILE> "Input manifest file")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"flash" <FILE> "Output flash file")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"key-dir" <String> "key directory")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"prebuilt-dir" <String> "prebuilt directory")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            ),
        Command::new("create-auth-flash-2x")
            .about("Create a new authorization flash image")
            .arg(
                arg!(--"cfg" <String> "config path")
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                arg!(--"man" <FILE> "Input manifest file")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"flash" <FILE> "Output flash file")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"key-dir" <String> "key directory")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"prebuilt-dir" <String> "prebuilt directory")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(--"pqc-key-type" <U32> "Type of PQC key validation: 1: MLDSA; 3: LMS")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            ),
    ];

    /* Init environment logger */
    env_logger::init();

    let cmd: ArgMatches = Command::new("cptra-imgtool")
        .arg_required_else_help(true)
        .subcommands(sub_cmds)
        .about("Aspeed authorization manifest tools")
        .get_matches();

    let result = match cmd.subcommand().unwrap() {
        ("create-auth-man", args) => run_auth_man_cmd(args),
        ("create-auth-man-2x", args) => run_auth_man_cmd_2x(args),
        ("create-auth-flash", args) => run_auth_flash_cmd(args),
        ("create-auth-flash-2x", args) => run_auth_flash_cmd_2x(args),
        (_, _) => unreachable!(),
    };

    config::remove_tmp_folder().unwrap();
    result.unwrap();
}

fn print_separator() {
    println!("------------------------------------------------------------------------------------------------------------------------------------------------");
}

pub(crate) fn show_important_cfg_path(cfg: &config::AspeedManifestCreationPath) {
    print_separator();
    println!("prebuilt_dir:   {}", cfg.prebuilt_dir.display());
    println!(
        "key_dir:        {}",
        cfg.key_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<None>".to_string())
    );
    println!(
        "svn_sig:        {}",
        cfg.svn_sig
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<None>".to_string())
    );
    println!(
        "manifest:       {}",
        cfg.manifest
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<None>".to_string())
    );
    println!(
        "caliptra_cfg:   {}",
        cfg.caliptra_cfg
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<None>".to_string())
    );
    print_separator();
}

pub(crate) fn run_auth_man_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let path = config::AspeedManifestCreationPath::new_manifest(args)
        .with_context(|| "Failed to create manifest creation path")?;
    debug!("Manifest auth path:\n{:#?}", path);
    show_important_cfg_path(&path);

    /* Create caliptra manifest config according to aspeed manifest config */
    let cfg = config::AspeedAuthManifestConfigFromFile::new(&path)?;
    cfg.save_caliptra_cfg(&path)?;

    /* To satisfy the key-dir validation requirements of caliptra-auth-manifest-app */
    let key_dir = cfg.validate_key_dir_if_needed(path.key_dir.as_deref())?;
    debug!("key_dir_to_auth_manifest_tool: {:#?}", key_dir.display());

    /* Run the caliptra manifest tool to create the manifest */
    let cmd = path.tool_dir.join(soc_man::AUTH_MANIFEST_TOOL_1X);
    println!("Manifest tool:  {}", cmd.display());
    config::check_path_exists(cmd.as_path())?;

    let mut child = std::process::Command::new(cmd)
        .args([
            "create-aspeed-auth-man",
            "--version",
            &cfg.manifest_config.version.to_string(),
            "--flags",
            &cfg.manifest_config.flags.to_string(),
            "--key-dir",
            &key_dir.to_string(),
            "--config",
            &path.caliptra_cfg.to_string(),
            "--out",
            &path.manifest.to_string(),
        ])
        .spawn()
        .expect("Failed to execute command");

    /* Wait for the process to exit */
    let _ = child.wait().expect("Failed to wait on child");

    let overrides_presigned_key_and_signature = cfg
        .manifest_config
        .manifest_overrides_presigned_key_and_signature
        .unwrap_or(true);

    /* Post-Processing to meet aspeed proprietary feature */
    let mut soc_man = soc_man::AspeedAuthorizationManifest::new(&path.manifest.unwrap_or_err());
    if overrides_presigned_key_and_signature {
        soc_man.modify_vnd_ecc_sig()?;
        soc_man.modify_vnd_lms_sig()?;
    }
    soc_man.insert_security_version(&path, &cfg, &key_dir);
    soc_man.close();

    Ok(())
}

pub(crate) fn run_auth_man_cmd_2x(args: &ArgMatches) -> anyhow::Result<()> {
    let path = config::AspeedManifestCreationPath::new_manifest(args)
        .with_context(|| "Failed to create manifest creation path")?;
    debug!("Manifest auth path:\n{:#?}", path);
    show_important_cfg_path(&path);

    /* Create caliptra manifest config according to aspeed manifest config */
    let cfg = config::AspeedAuthManifestConfigFromFile::new(&path)?;
    cfg.save_caliptra_cfg(&path)?;

    /* To satisfy the key-dir validation requirements of caliptra-auth-manifest-app */
    let key_dir = cfg.validate_key_dir_if_needed(path.key_dir.as_deref())?;
    debug!("key_dir_to_auth_manifest_tool: {:#?}", key_dir.display());

    /* Run the caliptra manifest tool to create the manifest */
    let cmd = path.tool_dir.join(soc_man::AUTH_MANIFEST_TOOL_2X);
    println!("Manifest tool:  {}", cmd.display());
    config::check_path_exists(cmd.as_path())?;

    let mut child = std::process::Command::new(cmd)
        .args([
            "create-auth-man",
            "--version",
            &cfg.manifest_config.version.to_string(),
            "--flags",
            &cfg.manifest_config.flags.to_string(),
            "--key-dir",
            &key_dir.to_string(),
            "--config",
            &path.caliptra_cfg.to_string(),
            "--out",
            &path.manifest.to_string(),
            "--pqc-key-type",
            &args.get_one::<u32>("pqc-key-type").unwrap().to_string(),
            "--svn",
            &cfg.manifest_config.security_version.to_string(),
        ])
        .spawn()
        .expect("Failed to execute command");

    /* Wait for the process to exit */
    let _ = child.wait().expect("Failed to wait on child");

    // TODO
    /* Post-Processing to meet aspeed proprietary feature */
    // let mut soc_man = soc_man::AspeedAuthorizationManifest::new(&path.manifest.unwrap_or_err());
    // soc_man.modify_vnd_ecc_sig()?;
    // soc_man.modify_vnd_lms_sig()?;
    // soc_man.insert_security_version(&path, &cfg, &key_dir);
    // soc_man.close();

    // padding the manifest to align 256 bytes for Recovery Interface requirement
    let padding_align_size = cfg.manifest_config.padding_align_size.unwrap_or(0) as u64;
    if padding_align_size != 0 {
        soc_man::padding_file(&path.manifest.unwrap_or_err(), padding_align_size)?;
    }

    Ok(())
}

pub(crate) fn run_auth_flash_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let path = config::AspeedManifestCreationPath::new_flash(args)
        .with_context(|| "Failed to create manifest creation path")?;
    debug!("Flash auth path:\n{:#?}", path);

    /* If the user didn't specify the prebuild manifest, create it. */
    if !args.contains_id("man") {
        run_auth_man_cmd(args)?;
        print_separator();
    }

    /* Get the aspeed configuration */
    let cfg = config::AspeedAuthManifestConfigFromFile::new(&path)?;

    /* To meet requirement: add FMC to SoC manifest but not in flash images list */
    unsafe {
        config::MCU_RUN_TIME_FW_ID = 1;
    }
    /* Run the caliptra flash image tool to create the flash image */
    let bl_list_args = std::iter::once("--soc-images")
        .chain(
            cfg.image_metadata_list
                .iter()
                .filter(|img| img.fw_id != unsafe { config::MCU_RUN_TIME_FW_ID })
                .map(|s| s.file.as_str()),
        )
        .collect::<Vec<_>>();
    debug!("Caliptra flash image tool args: {:#?}", bl_list_args);

    let cmd = path.tool_dir.join(FLASH_TOOL_1X);
    println!("Flash tool:     {}", cmd.display());
    config::check_path_exists(cmd.as_path())?;

    let cptra_out_bundle = cfg.image_runtime_list.cptra_out_bundle.unwrap_or(false);
    let dummy_path = config::get_dummy_path();
    let caliptra_file = if cptra_out_bundle {
        dummy_path.to_str().unwrap()
    } else {
        &cfg.image_runtime_list.caliptra_file
    };
    let mcu_file = if cptra_out_bundle {
        dummy_path.to_str().unwrap()
    } else {
        &cfg.image_runtime_list.mcu_file
    };

    let mut child = std::process::Command::new(cmd)
        .args([
            "flash-image",
            "create",
            "--caliptra-fw",
            caliptra_file,
            "--soc-manifest",
            &path.manifest.to_string(),
            "--mcu-runtime",
            mcu_file,
            "--output",
            &path.flash_image.to_string(),
        ])
        .args(bl_list_args)
        .spawn()
        .expect("Failed to execute command");

    /* Wait for the process to exit */
    let _ = child.wait().expect("Failed to wait on child");

    /* Create fw toc from flash image */
    fw_toc_1x::create_fw_toc_from_flash_image(&path, &cfg)?;

    if cptra_out_bundle {
        soc_man::combine_binaries_overwrite_manifest(
            &cfg.image_runtime_list.caliptra_file,
            &cfg.image_runtime_list.mcu_file,
            &path.flash_image.to_string(),
        )?;

        println!(
            "Created Caliptra out bundle flash image: {}",
            path.flash_image.to_string()
        );
    } else {
        println!(
            "Created Caliptra flash image: {}",
            path.flash_image.to_string()
        );
    }
    print_separator();

    Ok(())
}

pub(crate) fn run_auth_flash_cmd_2x(args: &ArgMatches) -> anyhow::Result<()> {
    let path = config::AspeedManifestCreationPath::new_flash(args)
        .with_context(|| "Failed to create manifest creation path")?;
    debug!("Flash auth path:\n{:#?}", path);

    /* If the user didn't specify the prebuild manifest, create it. */
    if !args.contains_id("man") {
        run_auth_man_cmd_2x(args)?;
        print_separator();
    }

    /* Get the aspeed configuration */
    let cfg = config::AspeedAuthManifestConfigFromFile::new(&path)?;

    /* To meet requirement: add FMC to SoC manifest but not in flash images list */
    unsafe {
        config::MCU_RUN_TIME_FW_ID = 2;
    }

    /* Run the caliptra flash image tool to create the flash image */
    let bl_list_args = std::iter::once("--soc-images")
        .chain(
            cfg.image_metadata_list
                .iter()
                .filter(|img| img.fw_id != unsafe { config::MCU_RUN_TIME_FW_ID })
                .map(|s| s.file.as_str()),
        )
        .collect::<Vec<_>>();
    debug!("Caliptra flash image tool args: {:#?}", bl_list_args);

    let cmd = path.tool_dir.join(FLASH_TOOL_2X);
    println!("Flash tool:     {}", cmd.display());
    config::check_path_exists(cmd.as_path())?;

    let mut child = std::process::Command::new(cmd)
        .args([
            "flash-image",
            "create",
            "--caliptra-fw",
            &cfg.image_runtime_list.caliptra_file,
            "--soc-manifest",
            &path.manifest.to_string(),
            "--mcu-runtime",
            &cfg.image_runtime_list.mcu_file,
            "--output",
            &path.flash_image.to_string(),
        ])
        .args(bl_list_args)
        .spawn()
        .expect("Failed to execute command");

    /* Wait for the process to exit */
    let _ = child.wait().expect("Failed to wait on child");

    /* Create fw toc from flash image */
    fw_toc::create_fw_toc_from_flash_image(&path, &cfg)?;

    println!(
        "Created Caliptra flash image: {}",
        path.flash_image.to_string()
    );

    print_separator();

    Ok(())
}
