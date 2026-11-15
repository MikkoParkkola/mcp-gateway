// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only: what the reaper sent to an armed leader's process group, in
//! order. An entry is recorded only when its syscall returned Ok, so a row
//! proves "SIGTERM, then the kill" from the sender's side; a child's own
//! handler proves it only when a loaded host schedules the child inside the
//! gap. Only armed pids are recorded, so parallel rows never share entries.
use rustix::process::Pid;

/// One signal the reaper sent to a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sent {
    Term,
    Kill,
}

type Log = std::collections::BTreeMap<i32, Vec<Sent>>;

static LOG: std::sync::Mutex<Log> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// The log; a row that panicked while holding it left nothing half-written.
fn log() -> std::sync::MutexGuard<'static, Log> {
    LOG.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Start recording for `pid`, before the stop that signals it. A live pid
/// is unique, so an entry already there is a stale one a failed row left
/// before the kernel reused the pid: it is replaced.
pub(crate) fn arm(pid: Pid) {
    log().insert(pid.as_raw_nonzero().get(), Vec::new());
}

/// Append `sent` for `pid` when a row armed it; otherwise nothing.
pub(super) fn record(pid: Pid, sent: Sent) {
    if let Some(entries) = log().get_mut(&pid.as_raw_nonzero().get()) {
        entries.push(sent);
    }
}

/// `pid`'s entries in order; it is disarmed.
fn take(pid: Pid) -> Vec<Sent> {
    log()
        .remove(&pid.as_raw_nonzero().get())
        .unwrap_or_default()
}

/// `pid`'s entries once a kill is among them (30 s watchdog). The reaper
/// records a send after its syscall returns, so a row that saw the group
/// end can read the log just before the kill's entry lands; every kill goes
/// through `send_group_signal`, and sends are sequential, so a SIGTERM is
/// always in before the kill that follows it.
async fn after_the_kill(pid: Pid) -> Vec<Sent> {
    let by = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !log()
        .get(&pid.as_raw_nonzero().get())
        .is_some_and(|sent| sent.contains(&Sent::Kill))
    {
        if std::time::Instant::now() >= by {
            return take(pid);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    take(pid)
}

/// One SIGTERM first, then one or more kills and no later SIGTERM.
pub(crate) async fn assert_term_then_kill(pid: Pid, what: &str) {
    let sent = after_the_kill(pid).await;
    assert!(
        matches!(sent.split_first(), Some((Sent::Term, rest))
            if !rest.is_empty() && rest.iter().all(|s| *s == Sent::Kill)),
        "{what}: the reaper sent {sent:?}, not one SIGTERM followed by the kill"
    );
}

/// One or more kills and no SIGTERM.
pub(crate) async fn assert_kill_without_term(pid: Pid, what: &str) {
    let sent = after_the_kill(pid).await;
    assert!(
        !sent.is_empty() && sent.iter().all(|s| *s == Sent::Kill),
        "{what}: the reaper sent {sent:?}, not the kill alone"
    );
}
