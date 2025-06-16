/*++

Licensed under the Apache-2.0 license.

File Name:

   utility.rs

Abstract:

    File contains utilities for parsing image authorization configuration files

--*/

use std::path::PathBuf;

pub trait PathBufExt {
    fn to_absolute(&self) -> PathBuf;
    fn unwrap_or_def(&self, default: PathBuf) -> PathBuf;
    fn unwrap_or_err(&self) -> PathBuf;
    fn to_string(&self) -> String;
}

impl PathBufExt for Option<PathBuf> {
    fn to_absolute(&self) -> PathBuf {
        match self {
            Some(path) => match path.is_absolute() {
                true => path.clone(),
                false => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path),
            },
            None => PathBuf::new(),
        }
    }

    fn unwrap_or_err(&self) -> PathBuf {
        self.as_ref().expect("Unknown path format").to_absolute()
    }

    fn unwrap_or_def(&self, default: PathBuf) -> PathBuf {
        match self {
            Some(p) => p.to_absolute(),
            None => default.to_absolute(),
        }
    }

    fn to_string(&self) -> String {
        self.as_ref()
            .and_then(|p| p.to_str())
            .expect("Unknown path format")
            .to_string()
    }
}

impl PathBufExt for PathBuf {
    fn to_absolute(&self) -> PathBuf {
        match self.is_absolute() {
            true => self.to_path_buf(),
            false => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(self),
        }
    }

    fn unwrap_or_def(&self, _default: PathBuf) -> PathBuf {
        self.to_absolute()
    }

    fn unwrap_or_err(&self) -> PathBuf {
        self.to_absolute()
    }

    fn to_string(&self) -> String {
        self.to_str().expect("Unknown path format").to_string()
    }
}
