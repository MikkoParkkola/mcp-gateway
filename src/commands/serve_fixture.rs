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
