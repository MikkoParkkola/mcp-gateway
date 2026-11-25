// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

/// T1-nothread: when the OS refuses the reaper thread, the start
/// is refused (so `StdioTransport::start` spawns no child, since it calls
/// `ensure_started` before the spawn) and nothing is cached: the next start
/// tries again.
#[test]
fn a_refused_reaper_thread_fails_the_start_and_is_retried() {
    let cell = OnceLock::new();
    let refused = start_once(&cell, |_| Err(std::io::Error::other("no threads")));
    assert!(refused.is_err(), "a refused thread fails the start");
    assert!(cell.get().is_none(), "a failed start caches nothing");
    let started = start_once(&cell, |receiver| {
        drop(receiver);
        Ok(())
    });
    assert!(started.is_ok(), "the next start tries again");
    assert!(cell.get().is_some());
}
