// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! gateway.yaml as the web UI's file-backed routes read it: once per request,
//! the config and the revision of the exact bytes it came from. Shared by
//! discovery and the API key routes; each logs a failed read under its own
//! label.

use std::path::Path;

use crate::config::Config;
use crate::config_reload::FileRevision;

/// What gateway.yaml says, read once for one request.
pub(super) enum Gateway {
    /// No config file: nothing can be adopted, the list is still served.
    None,
    /// The file's revision and the backend names and capabilities name in it.
    File {
        revision: FileRevision,
        config: Box<Config>,
    },
}

/// One read, logged as `label` when it fails: the config and the exact text it was loaded from, so the
/// revision and the managed set always describe the same bytes. A missing
/// file is no config; any other failure is logged with its cause (never the
/// file's contents) and answered without one.
pub(super) fn read_gateway(label: &str, path: Option<&Path>) -> Result<Gateway, &'static str> {
    load_gateway(path).map_err(|error| {
        if let Some(path) = path {
            tracing::warn!(%error, path = %path.display(), "{label}: gateway.yaml could not be loaded");
        }
        "gateway.yaml could not be loaded"
    })
}

/// [`read_gateway`] without the log line.
pub(super) fn load_gateway(path: Option<&Path>) -> Result<Gateway, crate::Error> {
    let Some(path) = path else {
        return Ok(Gateway::None);
    };
    if let Err(e) = std::fs::symlink_metadata(path)
        && e.kind() == std::io::ErrorKind::NotFound
    {
        return Ok(Gateway::None);
    }
    let (config, text) = Config::load_literal_with_text(path)?;
    Ok(Gateway::File {
        revision: FileRevision::of(text.as_bytes()),
        config: Box::new(config),
    })
}
