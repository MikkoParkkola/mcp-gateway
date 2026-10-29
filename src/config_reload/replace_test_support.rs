// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway.yaml in a temp dir, its reload context, and byte replacements:
//! shared by the byte writer's tests and its secret-step tests.

use std::{path::Path, path::PathBuf, sync::Arc, time::Duration};

use super::reload_context::replace::{Expected, Replace, Replaced};
use super::*;
use crate::config::Config;
use crate::gateway::test_helpers::write_owner_only;

pub(super) const WAIT: Duration = Duration::from_secs(5);

/// A commented config, so the bytes test sees comments survive.
pub(super) const START: &str =
    "# operator's note\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\" # first\n";
/// The same file with backend `b` added and every comment kept.
pub(super) const NEXT: &str = "# operator's note\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\" # first\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

pub(super) fn setup() -> (tempfile::TempDir, PathBuf, Arc<ReloadContext>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, START).expect("write config");
    let ctx = context(&path);
    (dir, path, ctx)
}

pub(super) fn context(path: &Path) -> Arc<ReloadContext> {
    let running = Config::load(Some(path)).expect("config loads");
    Arc::new(
        ReloadContext::new(
            path.to_path_buf(),
            Arc::new(LiveConfig::new(running)),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    )
}

/// Replace gateway.yaml with `bytes`.
pub(super) fn to(expected: Expected, bytes: &'static str, replaced: Replaced) -> Replace {
    Replace {
        expected,
        compute: Box::new(move |_| {
            Ok(crate::config_persistence::keyedit::Template::plain(
                bytes.as_bytes().to_vec(),
            ))
        }),
        replaced,
        secrets: None,
    }
}

pub(super) fn running_has_b(ctx: &ReloadContext) -> bool {
    ctx.live_config.get().backends.contains_key("b")
}

pub(super) fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read")
}

/// Every name in `dir`, for "nothing staged beside it" assertions.
pub(super) fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}
