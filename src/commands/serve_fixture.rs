// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test fixture: the two steps both serve paths take, the serve load and the gateway build, so
//! every serve-level row starts and builds a gateway the same way.

use std::path::Path;
use std::sync::Arc;

use crate::config::{Evaluated, LiveEnv};
use crate::gateway::Gateway;

/// The serve load of `config`; a failure fails the row.
pub(crate) async fn serve_load(row: &str, config: &Path) -> Evaluated {
    super::load_for_serve(Some(config))
        .await
        .unwrap_or_else(|error| panic!("{row}: the serve load succeeds: {error}"))
}

/// The gateway built from a serve load, as both serve paths build it; a failure fails the row.
pub(crate) async fn serve_build(
    row: &str,
    evaluated: Evaluated,
    env: Arc<LiveEnv>,
    config: &Path,
) -> Gateway {
    Gateway::new_evaluated(evaluated.config, env, Some(config.to_path_buf()))
        .await
        .unwrap_or_else(|error| panic!("{row}: the gateway builds: {error}"))
}

/// The words of the refusal sentence for an abandoned file a start cannot settle.
pub(crate) const ABANDONED_CLASS: &str = "holds audit records this gateway cannot deliver";

/// A config with auth off whose audit log cannot open: it puts a plain file in `dir` and names
/// a log inside it, so the best-effort open fails.
pub(crate) fn failed_log_config(dir: &Path) -> String {
    let blocker = dir.join("not-a-dir");
    std::fs::write(&blocker, b"x").expect("a file where the log's folder should be");
    format!(
        "auth:\n  enabled: false\nsecurity:\n  transparency_log:\n    enabled: true\n    path: {:?}\n",
        // Debug quoting escapes a Windows path's backslashes, which YAML's double quotes would
        // otherwise read as escape sequences.
        blocker.join("audit.jsonl").display().to_string()
    )
}
