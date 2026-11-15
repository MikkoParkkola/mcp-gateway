// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only: what the reaper sent to an armed leader's process group, in
//! order. An entry is recorded only when its syscall returned Ok, so a row
//! proves "SIGTERM, then the kill" from the sender's side; a child's own
//! handler proves it only when a loaded host schedules the child inside the
//! gap. Only armed pids are recorded, so parallel rows never share entries.
use rustix::process::Pid;

/// One entry: a signal the reaper sent to a group, or why a due SIGTERM was
/// not sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sent {
    Term,
    Kill,
    /// A due SIGTERM skipped: the step landed `late` past the kill instant,
    /// with no room left for SIGTERM's minimum phase inside the stop's slack.
    SkipLate {
        late: std::time::Duration,
    },
    /// SIGTERM not sent: the leader had already exited.
    LeaderGone,
    /// SIGTERM not sent this step: the group's ownership was not shown.
    Unproven,
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

/// How late a step must land past the kill instant before the reaper may skip
/// a due SIGTERM: the stop's slack past the reap deadline, less SIGTERM's
/// minimum phase. Computed here from the constants, not read from the record,
/// so a skip whose own lateness does not justify it fails.
fn skip_threshold() -> std::time::Duration {
    super::super::reaper::KILL_RESERVE
        .saturating_sub(super::REAP_DEADLINE)
        .saturating_sub(super::super::reaper::MIN_PHASE)
}

/// The SIGTERM and kill entries alone, in order.
fn signals(sent: &[Sent]) -> Vec<Sent> {
    sent.iter()
        .copied()
        .filter(|s| matches!(s, Sent::Term | Sent::Kill))
        .collect()
}

/// One SIGTERM first, then one or more kills and no later SIGTERM.
fn term_then_kill(sent: &[Sent]) -> bool {
    matches!(signals(sent).split_first(), Some((Sent::Term, rest))
        if !rest.is_empty() && rest.iter().all(|s| *s == Sent::Kill))
}

/// One SIGTERM, then the kill; or, on a host that starved the reaper past its
/// slack, the kill after a recorded skip whose lateness exceeds the threshold.
/// Any other shape fails by name.
pub(crate) async fn assert_term_then_kill(pid: Pid, what: &str) {
    let sent = after_the_kill(pid).await;
    if term_then_kill(&sent) {
        return;
    }
    assert!(
        !sent.contains(&Sent::Term),
        "{what}: the reaper sent {sent:?}: a SIGTERM out of order"
    );
    assert!(
        !sent.contains(&Sent::LeaderGone),
        "{what}: SIGTERM not sent, the leader was already gone: {sent:?}"
    );
    let skips: Vec<std::time::Duration> = sent
        .iter()
        .filter_map(|s| match s {
            Sent::SkipLate { late } => Some(*late),
            _ => None,
        })
        .collect();
    if skips.is_empty() {
        assert!(
            !sent.contains(&Sent::Unproven),
            "{what}: SIGTERM not sent, the group's ownership was not shown: {sent:?}"
        );
        panic!("{what}: killed with no SIGTERM and no recorded reason: {sent:?}");
    }
    let threshold = skip_threshold();
    for late in skips {
        assert!(
            late > threshold,
            "{what}: SIGTERM skipped {late:?} late, under the {threshold:?} the slack allows: {sent:?}"
        );
    }
    assert!(
        signals(&sent).iter().all(|s| *s == Sent::Kill) && sent.contains(&Sent::Kill),
        "{what}: the reaper sent {sent:?}, not the kill after its skip"
    );
}

/// The normal path only: one SIGTERM, then the kill, with no skip recorded.
/// For a row on the full, uncut plan, which leaves the reaper seconds of room.
pub(crate) async fn assert_term_then_kill_strict(pid: Pid, what: &str) {
    let sent = after_the_kill(pid).await;
    assert!(
        term_then_kill(&sent)
            && !sent
                .iter()
                .any(|s| matches!(s, Sent::SkipLate { .. } | Sent::LeaderGone)),
        "{what}: the reaper sent {sent:?}, not one SIGTERM followed by the kill"
    );
}

/// One or more kills and no SIGTERM; a recorded late skip is allowed (these
/// plans leave no room for one), any other unsent reason fails by name.
pub(crate) async fn assert_kill_without_term(pid: Pid, what: &str) {
    let sent = after_the_kill(pid).await;
    assert!(
        !sent.contains(&Sent::LeaderGone) && !sent.contains(&Sent::Unproven),
        "{what}: a SIGTERM was due but not sent for another reason: {sent:?}"
    );
    let signals = signals(&sent);
    assert!(
        !signals.is_empty() && signals.iter().all(|s| *s == Sent::Kill),
        "{what}: the reaper sent {sent:?}, not the kill alone"
    );
}
