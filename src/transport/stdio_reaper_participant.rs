// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one participant a gateway stop runs besides its registry: backends
//! built outside the registry (the capability executor's MCP children) join
//! the stop through the deadline they already share with it.

use tracing::warn;

use super::StopDeadline;

/// What the stop calls with its stage deadline. Set once; the owner keeps
/// only a weak link inside it, so a dropped owner makes it a no-op.
type Run = Box<dyn Fn(tokio::time::Instant) + Send + Sync>;

/// A deadline's participant slot.
#[derive(Default)]
pub(super) struct Participant(std::sync::OnceLock<Run>);

impl std::fmt::Debug for Participant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Participant")
            .field(&self.0.get().is_some())
            .finish()
    }
}

impl StopDeadline {
    /// Join the stop under this deadline: `run` is called with the stage
    /// deadline, on the stopping thread, before the stop waits for anything.
    /// The gateway builds one executor per registry, so a second participant
    /// is a wiring fault: it fails a debug build, and a release build keeps
    /// the first and says so.
    pub(crate) fn join_stop(&self, run: impl Fn(tokio::time::Instant) + Send + Sync + 'static) {
        let first = self.participant.0.set(Box::new(run)).is_ok();
        debug_assert!(first, "a stop deadline has one participant");
        if !first {
            warn!("second stop participant ignored: the gateway stop will not end its children");
        }
    }

    /// Run the participant, if one joined, with the stage deadline.
    pub(crate) fn run_participant(&self, deadline: tokio::time::Instant) {
        if let Some(run) = self.participant.0.get() {
            run(deadline);
        }
    }
}
