// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Process-tree ownership for the stdio transport (MIK-8895, ported from the
//! release line's `stdio_tree.rs`; its frame reading stays 4.0-only).

use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use tokio::process::Command;

use super::StdioTransport;
use crate::{Error, Result};

impl Drop for StdioTransport {
    /// A dropped transport ends the whole tree. `KillOnDrop` only kills the
    /// group leader, so `npx`/`uvx` descendants would outlive it.
    fn drop(&mut self) {
        // The reaper ends the tree, settle and reap included, with no runtime
        // (MIK-7923): `ChildTree`'s own Drop is only the fallback.
        if let Some(tree) = self.child.get_mut().tree.take() {
            let _ = super::reaper::hand_over(tree);
        }
    }
}

/// Start `cmd` as the leader of its own process group (Unix) or Job object
/// (Windows), so stopping the backend ends every process it started:
/// `npx`/`uvx`-style launchers otherwise leave the real server behind. Its
/// own group also keeps a stop sent to the gateway's group (tini -g, ^C) from
/// reaching it before the gateway drains.
pub(super) fn spawn_in_own_tree(cmd: Command) -> Result<Box<dyn ChildWrapper>> {
    let mut wrap = CommandWrap::from(cmd);
    wrap.wrap(KillOnDrop);
    #[cfg(unix)]
    wrap.wrap(process_wrap::tokio::ProcessGroup::leader());
    #[cfg(windows)]
    wrap.wrap(process_wrap::tokio::JobObject);
    wrap.spawn().map_err(|e| match e.kind() {
        // A command path that does not exist, or a file that is not
        // executable. No amount of waiting fixes either, and warm-start
        // retries transport failures indefinitely -- so before this, a
        // typo in a backend command was respawned once a minute for the
        // life of the process with no indication the config was wrong.
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            Error::TransportPermanent(format!("Failed to spawn: {e}"))
        }
        _ => Error::Transport(format!("Failed to spawn: {e}")),
    })
}
