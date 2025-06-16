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

mod config;

fn main() {
    let sub_cmds = vec![Command::new("create-auth-man")
        .about("Create a new authorization manifest")
        .arg(
            arg!(--"prj" <String> "project name")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!(--"out" <FILE> "Output file")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )];

    let cmd: ArgMatches = Command::new("aspeed-auth-man-app")
        .arg_required_else_help(true)
        .subcommands(sub_cmds)
        .about("Aspeed authorization manifest tools")
        .get_matches();

    let result = match cmd.subcommand().unwrap() {
        ("create-auth-man", args) => run_auth_man_cmd(args),
        (_, _) => unreachable!(),
    };

    result.unwrap();
}

pub(crate) fn run_auth_man_cmd(args: &ArgMatches) -> anyhow::Result<()> {
    let path = config::new_manifest_path_mgnt(args)
        .with_context(|| "Failed to create manifest creation path")?;

    /* Create caliptra manifest config according to aspeed manifest config */
    let cfg = config::load_auth_man_config_from_aspeed_file(&path)?;
    let _ = config::store_auth_man_config_to_file(&cfg, &path)?;

    /* Run the caliptra manifest tool to create the manifest */
    let root = env!("CARGO_MANIFEST_DIR");
    let mut child = std::process::Command::new("cargo")
        .args([
            "run", "create-auth-man",
            "--version", &cfg.version.to_string(),
            "--flags", &cfg.flags.to_string(),
            "--key-dir", path.key_dir.to_str().unwrap(),
            "--config", path.caliptra_cfg.to_str().unwrap(),
            "--out", path.manifest.to_str().unwrap(),
        ])
        .current_dir(Path::new(&format!("{}/../caliptra-sw/auth-manifest/app", root)))
        .spawn()
        .expect("Failed to execute command");

    /* Wait for the process to exit */
    let _ = child.wait().expect("Failed to wait on child");

    Ok(())
}
