// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config file, read once.
//!
//! Every stage of a load (the `env_files` pre-pass, the full extract and the
//! unknown-key check) parses these bytes rather than reopening the path. On
//! Unix they come from the same handle the CONFIG.2 mode check ran on, so the
//! file that was judged is the file that is loaded.

use std::path::{Path, PathBuf};

use figment::providers::{Format, Yaml};
use figment::value::{Dict, Map};
use figment::{Metadata, Profile, Provider};

use crate::Result;

/// A selected config file and the text it held when it was read.
#[derive(Debug, Clone)]
pub(crate) struct ConfigFile {
    path: PathBuf,
    text: String,
}

impl ConfigFile {
    /// Read `path`. On Unix a file other users can read is refused here.
    pub(crate) fn read(path: PathBuf) -> Result<Self> {
        #[cfg(unix)]
        let text =
            super::secret_file::read_secret_file(&path, super::secret_file::SecretFile::Config)?;
        #[cfg(not(unix))]
        let text = std::fs::read_to_string(&path).map_err(|e| {
            crate::Error::Config(format!("Cannot read config file {}: {e}", path.display()))
        })?;
        Ok(Self { path, text })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

/// Parses the bytes already read, but reports them as the file they came from,
/// exactly as `Yaml::file` would, so a parse error still names the path.
impl Provider for ConfigFile {
    fn metadata(&self) -> Metadata {
        Metadata::from("YAML file", self.path.as_path())
    }

    fn data(&self) -> figment::Result<Map<Profile, Dict>> {
        Yaml::string(&self.text).data()
    }
}
