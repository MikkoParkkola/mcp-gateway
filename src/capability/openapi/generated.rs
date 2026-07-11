// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Generated capability output types.
//!
//! Single responsibility: the public `GeneratedCapability` and its auth/cache
//! templates emitted by the converter.

use std::fs;
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

impl GeneratedCapability {
    /// Write capability to a file in the specified directory
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or the file cannot be written.
    pub fn write_to_file(&self, directory: &str) -> Result<()> {
        let dir = Path::new(directory);
        if !dir.exists() {
            fs::create_dir_all(dir)
                .map_err(|e| Error::Config(format!("Failed to create directory: {e}")))?;
        }

        let filename = format!("{}.yaml", self.name);
        let path = dir.join(filename);

        fs::write(&path, &self.yaml)
            .map_err(|e| Error::Config(format!("Failed to write capability file: {e}")))?;

        info!(capability = %self.name, path = %path.display(), "Wrote capability file");
        Ok(())
    }
}
