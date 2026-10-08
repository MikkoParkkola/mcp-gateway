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
        let text =
            super::secret_file::read_secret_file(&path, super::secret_file::SecretFile::Config)?;
        Ok(Self { path, text })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

impl super::Config {
    /// [`super::Config::load_literal`] of `path`, with the text it loaded: the
    /// bytes the strict checks ran on, from one read, for a caller that edits
    /// that text and must not edit any other.
    pub(crate) fn load_literal_with_text(path: &Path) -> Result<(Self, String)> {
        let file = ConfigFile::read(path.to_path_buf())?;
        let evaluated = Self::evaluate(
            Some(&file),
            &super::SystemHome,
            super::Tolerance::Warn,
            super::Expansion::Literal,
        )?;
        Ok((evaluated.config, file.text))
    }

    /// `text` loaded as a config file is, `url` resolved, with no environment
    /// layer: what a comment-keeping write proves its edited text loads as.
    #[allow(dead_code)] // throwaway red proof only: used by tests until the fix
    pub(crate) fn from_file_text(text: &str) -> Result<Self> {
        let file = ConfigFile {
            path: PathBuf::from("gateway.yaml"),
            text: text.to_owned(),
        };
        figment::Figment::from(file)
            .extract()
            .map_err(|e| crate::Error::Config(e.to_string()))
    }
}

/// Parses the bytes already read, but reports them as the file they came from,
/// exactly as `Yaml::file` would, so a parse error still names the path.
impl Provider for ConfigFile {
    fn metadata(&self) -> Metadata {
        Metadata::from("YAML file", self.path.as_path())
    }

    fn data(&self) -> figment::Result<Map<Profile, Dict>> {
        let mut data = Yaml::string(&self.text).data()?;
        for dict in data.values_mut() {
            resolve_backend_urls(dict).map_err(figment::Error::from)?;
        }
        Ok(data)
    }
}

/// Turn each backend's `url` into the key its scheme selects (`http_url` or
/// `ws_url`), once, before anything reads the backend. A refusal names the
/// keys and never the URL, which can carry a credential.
fn resolve_backend_urls(dict: &mut Dict) -> std::result::Result<(), String> {
    let Some(figment::value::Value::Dict(_, backends)) = dict.get_mut("backends") else {
        return Ok(());
    };
    for (name, backend) in backends.iter_mut() {
        let figment::value::Value::Dict(_, fields) = backend else {
            continue;
        };
        let Some(url) = fields.remove("url") else {
            continue;
        };
        if let Some(other) = super::backend_transport::TRANSPORT_KEYS
            .iter()
            .find(|k| fields.contains_key(**k))
        {
            return Err(format!(
                "backends.{name}.url and backends.{name}.{other} both choose how to reach the \
                 backend; keep `url` and delete `{other}`."
            ));
        }
        let figment::value::Value::String(tag, address) = url else {
            return Err(format!("backends.{name}.url must be a string."));
        };
        let Some(key) = super::backend_transport::transport_key_for(&address) else {
            return Err(format!(
                "backends.{name}.url must start with http://, https://, ws:// or wss://."
            ));
        };
        fields.insert(key.to_string(), figment::value::Value::String(tag, address));
    }
    Ok(())
}
