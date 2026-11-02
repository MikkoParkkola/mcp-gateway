// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config file, read once.
//!
//! Every stage of a load (the `env_files` pre-pass, the full extract and the
//! unknown-key check) parses these bytes rather than reopening the path. On
//! Unix they come from the same handle the CONFIG.2 mode check ran on, so the
//! file that was judged is the file that is loaded.

use std::path::{Path, PathBuf};

use figment::value::{Dict, Map};
use figment::{Metadata, Profile, Provider};

use crate::Result;

/// Env names the config writer resolves its template's secret slots through
/// while it validates a save, before any store entry exists. Reserved: a
/// config file or env file naming one is refused at load, so no config can
/// reach a slot's stand-in value.
pub(crate) const PENDING_SLOT_PREFIX: &str = "MCPGW_PENDING_SLOT_";

/// The first reference to a reserved name, with its 1-based line: a scalar,
/// key or value, that is `env:NAME` or holds `${NAME}`, the two forms the
/// loader resolves through the overlay (`SecretRef::parse` and the template
/// expander in `secret_ref.rs`). A comment is no scalar, so text that only
/// mentions the prefix never matches. Text that does not parse is left to
/// the loader, which reports it.
pub(crate) fn reserved_slot_reference(text: &str) -> Option<(String, usize)> {
    for item in granit_parser::Parser::new_from_str(text) {
        let (event, span) = item.ok()?;
        let granit_parser::Event::Scalar(value, ..) = event else {
            continue;
        };
        let name = (value.strip_prefix("env:"))
            .filter(|name| name.starts_with(PENDING_SLOT_PREFIX))
            .or_else(|| {
                super::secret_ref::template_names(&value)
                    .find(|name| name.starts_with(PENDING_SLOT_PREFIX))
            });
        if let Some(name) = name {
            return Some((name.to_owned(), span.start.line()));
        }
    }
    None
}

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
        if let Some((name, line)) = reserved_slot_reference(&text) {
            return Err(crate::Error::Config(format!(
                "Refusing to load {}: line {line} references {name}; names starting \
                 {PENDING_SLOT_PREFIX} are reserved for the gateway's config writer, so \
                 rename it",
                path.display()
            )));
        }
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

    /// `text` loaded as the file at `path` would be on a reload against
    /// `env_paths`, with `pending` names resolving above the env files: the
    /// config writer's full validation of a template whose secret slots name
    /// them, so no submitted secret goes through the loader.
    pub(crate) fn load_pending(
        path: &Path,
        text: &str,
        env_paths: &super::ResolvedEnvFiles,
        pending: std::collections::BTreeMap<String, String>,
    ) -> Result<super::Evaluated> {
        let file = ConfigFile {
            path: path.to_path_buf(),
            text: text.to_owned(),
        };
        let overlay =
            super::EnvOverlay::from_paths_checked(env_paths.as_paths())?.with_pending(pending);
        Self::finish(
            Some(&file),
            overlay,
            env_paths.clone(),
            super::Expansion::Resolve,
        )
    }

    /// `text` loaded as a config file is, `url` resolved, with no environment
    /// layer: what a comment-keeping write proves its edited text loads as.
    /// Extraction only: no strict-key check, no two-transport check and no
    /// validation run here, so this is not proof that a file is acceptable.
    pub(crate) fn from_file_text(text: &str) -> Result<Self> {
        let file = ConfigFile {
            path: PathBuf::from("gateway.yaml"),
            text: text.to_owned(),
        };
        figment::Figment::from(file)
            .extract()
            .map_err(super::load_error::from_figment)
    }
}

/// Parses the bytes already read, but reports them as the file they came from,
/// exactly as `Yaml::file` would, so a parse error still names the path.
impl Provider for ConfigFile {
    fn metadata(&self) -> Metadata {
        Metadata::from("YAML file", self.path.as_path())
    }

    fn data(&self) -> figment::Result<Map<Profile, Dict>> {
        // `figment_data`, not `from_str_loose`: the provider's own read keeps
        // the document under its profile and returns figment's error type.
        let mut data = crate::yaml::figment_data(&self.text)?;
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
            // Backend addresses are never expanded, so a reference is not an
            // address; the environment supplies one through the override keys.
            let var = format!(
                "{}BACKENDS__{}",
                super::OverlayEnv::PREFIX,
                name.to_uppercase()
            );
            return Err(if address.contains("${") || address.starts_with("env:") {
                format!(
                    "backends.{name}.url is not expanded, so it must be the address itself; \
                     to take it from the environment, delete backends.{name}.url and set \
                     {var}__HTTP_URL or {var}__WS_URL."
                )
            } else {
                format!("backends.{name}.url must start with http://, https://, ws:// or wss://.")
            });
        };
        fields.insert(key.to_string(), figment::value::Value::String(tag, address));
    }
    Ok(())
}
