/*++

Licensed under the Apache-2.0 license.

File Name:

   main.rs

Abstract:

    Main entry point for Caliptra Authorization Manifest application

--*/

use anyhow::Context;
use clap::{arg, value_parser, ArgMatches, Command};
use std::path::PathBuf;
use utility::PathBufExt;
use log::debug;

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

    /* Init environment logger */
    env_logger::init();

    let cmd: ArgMatches = Command::new("cptra-imgtool")
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
    debug!("Manifest auth path:\n{:#?}", path);

    /* Create caliptra manifest config according to aspeed manifest config */
    let cfg = config::AspeedAuthManifestConfigFromFile::new(&path)?;
    cfg.save_caliptra_cfg(&path)?;

    /* Run the caliptra manifest tool to create the manifest */
    let cmd = path.tool_dir.join("caliptra-auth-manifest-app");
    let mut child = std::process::Command::new(cmd)
        .args([
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
        .spawn()
        .expect("Failed to execute command");

    /* Wait for the process to exit */
    let _ = child.wait().expect("Failed to wait on child");

    /* Post-Processing to meet aspeed proprietary feature */
    let mut soc_man = soc_man::AspeedAuthorizationManifest::new(&path.manifest.unwrap_or_err());
    soc_man.modify_vnd_ecc_sig(&cfg);
    soc_man.modify_vnd_lms_sig(&cfg);
    soc_man.insert_security_version(&path, &cfg);
    soc_man.close();

    Ok(())
}

pub(crate) fn run_auth_flash_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let path = config::AspeedManifestCreationPath::new_flash(args)
        .with_context(|| "Failed to create manifest creation path")?;
    debug!("Flash auth path:\n{:#?}", path);

    /* If the user didn't specify the prebuild manifest, create it. */
    if !args.contains_id("man") {
        run_auth_man_cmd(args)?;
    }

    /* Get the aspeed configuration */
    let cfg = config::AspeedAuthManifestConfigFromFile::new(&path)?;

    /* Run the caliptra flash image tool to create the flash image */
    let bl_list_args = std::iter::once("--soc-images")
        .chain(
            cfg.image_metadata_list
                .iter()
                .map(|s| s.file.as_str())
                .filter(|&filename| filename != cfg.image_runtime_list.mcu_file),
        )
        .collect::<Vec<_>>();
    debug!("Caliptra flash image tool args: {:#?}", bl_list_args);

    let cmd = path.tool_dir.join("xtask");
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

    Ok(())
}
