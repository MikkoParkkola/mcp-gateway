// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Generated capability output types.
//!
//! Single responsibility: the public `GeneratedCapability` and its auth/cache
//! templates emitted by the converter.

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use serde::Serialize;
use tracing::info;

use crate::{Error, Result};

/// Template for auth configuration
#[derive(Debug, Clone)]
pub struct AuthTemplate {
    /// Auth type (oauth, `api_key`, bearer)
    pub auth_type: String,
    /// Credential key reference
    pub key: String,
    /// Description
    pub description: String,
}

/// Template for cache configuration
#[derive(Debug, Clone)]
pub struct CacheTemplate {
    /// Cache strategy
    pub strategy: String,
    /// TTL in seconds
    pub ttl: u64,
}

/// Generated capability definition (ready to write as YAML)
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedCapability {
    /// Capability name
    pub name: String,
    /// YAML content
    pub yaml: String,
}

/// What an import says for a tool whose capability file is already there:
/// the file is kept as it was, and the sentence names the way forward.
pub(crate) fn name_taken(name: &str) -> String {
    format!(
        "a capability named {name} already exists and was left unchanged; \
         remove that capability or rename the operation, then import again"
    )
}

/// Whether `error` is [`GeneratedCapability::write_to_file`]'s refusal of a
/// name whose capability file is already there. Callers that answer that
/// case on its own ask this, never the message text.
#[cfg(feature = "webui")]
pub(crate) fn is_name_taken(error: &Error) -> bool {
    matches!(error, Error::Io(e) if e.kind() == io::ErrorKind::AlreadyExists)
}

impl GeneratedCapability {
    /// Write capability to a file in the specified directory, never over a
    /// file already there.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or the file cannot
    /// be written; a file of this name already in `directory` is refused with
    /// an [`Error::Io`] of kind `AlreadyExists` (`is_name_taken` tells it
    /// apart) and is left byte-identical.
    pub fn write_to_file(&self, directory: &str) -> Result<()> {
        let dir = Path::new(directory);
        if !dir.exists() {
            fs::create_dir_all(dir)
                .map_err(|e| Error::Config(format!("Failed to create directory: {e}")))?;
        }

        let filename = format!("{}.yaml", self.name);
        let path = dir.join(filename);
        let failed = |e: io::Error| Error::Config(format!("Failed to write capability file: {e}"));
        let taken = || {
            let e = io::Error::new(io::ErrorKind::AlreadyExists, name_taken(&self.name));
            Error::Io(e)
        };

        // The loader reads `.yml` too, so a file (or link) of that name holds
        // the name as well. Best effort: unlike the `.yaml` create below, a
        // `.yml` made by another process after this look is not seen.
        if fs::symlink_metadata(dir.join(format!("{}.yml", self.name))).is_ok() {
            return Err(taken());
        }
        // Created only if absent, in one step: no check made before the write
        // can be passed by two writers at once.
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(taken()),
            Err(e) => return Err(failed(e)),
        };
        // Never removed on failure: by then the path may name another
        // writer's file. The message says a partial file may be left.
        file.write_all(self.yaml.as_bytes()).map_err(|e| {
            Error::Config(format!(
                "Failed to write capability file: {e}; a partial {} may be left, remove it before importing again",
                path.display()
            ))
        })?;

        info!(capability = %self.name, path = %path.display(), "Wrote capability file");
        Ok(())
    }
}
