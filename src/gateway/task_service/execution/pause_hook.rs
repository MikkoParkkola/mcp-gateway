// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Debug builds only: hold a create between its durable commit and its ack, so
//! a process-level test can SIGKILL the real binary in that window (#2298).
//!
//! Compiled out of every release build (`debug_assertions` is off there), and
//! the release job checks the binary does not carry [`PAUSE_AT_PUBLISHED`].
//! With the variable unset the executor is untouched.

use std::path::PathBuf;
use std::sync::Arc;

use super::{CommitObserver, CommitStage, TaskExecutor};

/// Names the marker file to write, as the committed task id, before pausing.
pub(crate) const PAUSE_AT_PUBLISHED: &str = "MCP_GATEWAY_TEST_PAUSE_AT_PUBLISHED";

struct PauseAtPublished {
    marker: PathBuf,
}

#[async_trait::async_trait]
impl CommitObserver for PauseAtPublished {
    async fn reached(&self, stage: CommitStage, task_id: &str) {
        if stage != CommitStage::Published {
            return;
        }
        // The id reaches the test only through this file, written whole by a
        // rename so a reader never sees half of it. A failed write would leave
        // the test waiting on a marker that never comes, so it is loud.
        let partial = self.marker.with_extension("partial");
        let written = std::fs::write(&partial, task_id)
            .and_then(|()| std::fs::rename(&partial, &self.marker));
        if let Err(error) = written {
            tracing::error!(%error, "pause-at-published marker write failed");
        }
        std::future::pending::<()>().await;
    }
}

/// Install the pause when [`PAUSE_AT_PUBLISHED`] names a marker path.
pub(crate) fn install_from_env(executor: &TaskExecutor) {
    if let Some(marker) = std::env::var_os(PAUSE_AT_PUBLISHED) {
        executor.observe_commits(Arc::new(PauseAtPublished {
            marker: marker.into(),
        }));
    }
}
