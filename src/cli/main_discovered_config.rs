// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Serve-time config discovery (#1868): the file discovery finds is the file
//! loaded and the file watched. Shared by CLI dispatch and capability commands.

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::gateway::Gateway;

/// `(discovered, load)`: the config file discovery finds when `named` is
/// `None`, and the path to load, which is `named` when one was given.
pub(crate) fn resolve(named: Option<&Path>) -> (Option<PathBuf>, Option<PathBuf>) {
    let discovered = named.is_none().then(Config::fallback_config_path).flatten();
    let load = named.map(Path::to_path_buf).or_else(|| discovered.clone());
    (discovered, load)
}

/// Watch and hot-reload a discovered config, as a named one is.
pub(crate) fn watch(gateway: Gateway, discovered: Option<PathBuf>) -> Gateway {
    match discovered {
        Some(path) => gateway.with_watched_config(path),
        None => gateway,
    }
}
