/*++

Licensed under the Apache-2.0 license.

File Name:

   main.rs

Abstract:

    Main entry point for Caliptra Authorization Manifest application

--*/

use anyhow::Context;
use clap::{arg, value_parser, ArgMatches, Command};
use std::path::{Path, PathBuf};
use utility::PathBufExt;

mod config;
mod soc_man;
mod utility;

fn main() {
    let sub_cmds = vec![
        Command::new("create-auth-man")
            .about("Create a new authorization manifest")
            .arg(
                arg!(--"prj" <String> "project name")
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                arg!(--"man" <FILE> "Output manifest file")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            ),
        Command::new("create-auth-flash")
            .about("Create a new authorization flash image")
            .arg(
                arg!(--"prj" <String> "project name")
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
            ),
    ];

    let cmd: ArgMatches = Command::new("aspeed-auth-man-app")
        .arg_required_else_help(true)
        .subcommands(sub_cmds)
        .about("Aspeed authorization manifest tools")
        .get_matches();

    let result = match cmd.subcommand().unwrap() {
        ("create-auth-man", args) => run_auth_man_cmd(args),
        ("create-auth-flash", args) => run_auth_flash_cmd(args),
        (_, _) => unreachable!(),
    };

    result.unwrap();
}

pub(crate) fn run_auth_man_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let path = config::AspeedManifestCreationPath::new_manifest(args)
        .with_context(|| "Failed to create manifest creation path")?;

    /* Create caliptra manifest config according to aspeed manifest config */
    let cfg = config::AspeedAuthManifestConfigFromFile::new(&path)?;
    cfg.save_caliptra_cfg(&path)?;

    /* Run the caliptra manifest tool to create the manifest */
    let mut child = std::process::Command::new("cargo")
        .args([
            "+1.70",
            "run",
            "create-auth-man",
            "--version",
            &cfg.manifest_config.version.to_string(),
            "--flags",
            &cfg.manifest_config.flags.to_string(),
            "--key-dir",
            &path.key_dir.to_string(),
            "--config",
            &path.caliptra_cfg.to_string(),
            "--out",
            &path.manifest.to_string(),
        ])
        .current_dir(Path::new(&cfg.authtool.caliptra_sw_auth))
        .spawn()
        .expect("Failed to execute command");

    /* Wait for the process to exit */
    let _ = child.wait().expect("Failed to wait on child");

    /* Post-Processing to meet aspeed proprietary feature */
    let mut soc_man = soc_man::AspeedAuthorizationManifest::new(&path.manifest.unwrap_or_err());
    soc_man.mdy_vnd_ecc_sig(&cfg);
    soc_man.close();

    Ok(())
}

pub(crate) fn run_auth_flash_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let path = config::AspeedManifestCreationPath::new_flash(args)
        .with_context(|| "Failed to create manifest creation path")?;

    /* If the user didn't specify the prebuild manifest, create it. */
    if !args.contains_id("man") {
        run_auth_man_cmd(args)?;
    }

    /* Get the aspeed configuration */
    let cfg = config::AspeedAuthManifestConfigFromFile::new(&path)?;

    /* Run the caliptra flash image tool to create the flash image */
    let bl_list_args = std::iter::once("--soc-images")
        .chain(cfg.image_metadata_list.iter().map(|s| s.file.as_str()))
        .collect::<Vec<_>>();
    let mut child = std::process::Command::new("cargo")
        .args([
            "xtask",
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
        .current_dir(Path::new(&cfg.authtool.caliptra_mcu_sw))
        .spawn()
        .expect("Failed to execute command");

    /* Wait for the process to exit */
    let _ = child.wait().expect("Failed to wait on child");

    Ok(())
}
