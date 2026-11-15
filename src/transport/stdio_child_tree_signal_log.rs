// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only: what the reaper sent to an armed leader's process group, in
//! order. A SIGTERM is recorded only when its syscall returned Ok, and every
//! kill with its outcome, so a row proves "SIGTERM, then the kill" from the
//! sender's side; a child's own handler proves it only when a loaded host
//! schedules the child inside the gap. Only armed pids are recorded, so
//! parallel rows never share entries.
use rustix::process::Pid;

/// One entry: a signal the reaper sent to a group, or why a due SIGTERM was
/// not sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sent {
    Term,
    Kill,
    /// The kill was sent and found no process (ESRCH), and the leader had been
    /// seen exiting before it was sent: the group had already ended. macOS
    /// answers so for a group whose members have all exited; Linux answers Ok.
    KillGone,
    /// A kill's syscall failed, and not as `KillGone`: the group may not have
    /// been the child's.
    KillFailed,
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

static GONE: std::sync::Mutex<std::collections::BTreeSet<i32>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// Make every kill of `pid`'s group answer ESRCH, as macOS answers for a group
/// whose members have all exited; the kill itself is still sent.
pub(crate) fn inject_gone(pid: Pid) {
    GONE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(pid.as_raw_nonzero().get());
}

/// `sent`, or ESRCH when a row injected it for `pid`.
pub(super) fn injected(pid: Option<Pid>, sent: std::io::Result<()>) -> std::io::Result<()> {
    let gone = pid.is_some_and(|pid| {
        GONE.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&pid.as_raw_nonzero().get())
    });
    if gone {
        Err(std::io::Error::from_raw_os_error(
            rustix::io::Errno::SRCH.raw_os_error(),
        ))
    } else {
        sent
    }
}

/// `pid`'s entries in order; it is disarmed.
fn take(pid: Pid) -> Vec<Sent> {
    log()
        .remove(&pid.as_raw_nonzero().get())
        .unwrap_or_default()
}

/// `pid`'s entries once a kill, of any outcome, is among them (30 s watchdog). The reaper
/// records a send after its syscall returns, so a row that saw the group
/// end can read the log just before the kill's entry lands; every kill goes
/// through `send_group_signal`, and sends are sequential, so a SIGTERM is
/// always in before the kill that follows it.
async fn after_the_kill(pid: Pid) -> Vec<Sent> {
    let by = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !log().get(&pid.as_raw_nonzero().get()).is_some_and(|sent| {
        sent.iter()
            .any(|s| matches!(s, Sent::Kill | Sent::KillGone | Sent::KillFailed))
    }) {
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

fn has_skip(sent: &[Sent]) -> bool {
    sent.iter().any(|s| matches!(s, Sent::SkipLate { .. }))
}

/// The live rows' rule: one SIGTERM, then the kill, with no skip recorded; or,
/// on a host that starved the reaper past its slack, no SIGTERM at all, only
/// late skips whose lateness exceeds the threshold, then the kill. Any other
/// shape is refused with its reason.
fn judge_term_then_kill(sent: &[Sent]) -> Result<(), String> {
    if sent.contains(&Sent::Term) {
        return if term_then_kill(sent) && !has_skip(sent) && !sent.contains(&Sent::LeaderGone) {
            Ok(())
        } else {
            Err(format!("not one SIGTERM followed by the kill: {sent:?}"))
        };
    }
    if sent.contains(&Sent::LeaderGone) {
        return Err(format!(
            "SIGTERM not sent, the leader was already gone: {sent:?}"
        ));
    }
    if sent.contains(&Sent::Unproven) {
        return Err(format!(
            "SIGTERM not sent, the group's ownership was not shown: {sent:?}"
        ));
    }
    if !has_skip(sent) {
        return Err(format!(
            "killed with no SIGTERM and no recorded reason: {sent:?}"
        ));
    }
    let threshold = skip_threshold();
    for s in sent {
        if let Sent::SkipLate { late } = s
            && *late <= threshold
        {
            return Err(format!(
                "SIGTERM skipped {late:?} late, under the {threshold:?} the slack allows: {sent:?}"
            ));
        }
    }
    if sent.contains(&Sent::Kill) {
        Ok(())
    } else {
        Err(format!("no kill after the skip: {sent:?}"))
    }
}

/// The normal path only: one SIGTERM, then the kill, with nothing skipped.
fn judge_strict(sent: &[Sent]) -> Result<(), String> {
    if term_then_kill(sent) && !has_skip(sent) && !sent.contains(&Sent::LeaderGone) {
        Ok(())
    } else {
        Err(format!("not one SIGTERM followed by the kill: {sent:?}"))
    }
}

/// The kill with no SIGTERM; a late skip is allowed (these plans leave no
/// room for one), any other unsent reason is refused.
fn judge_kill_without_term(sent: &[Sent]) -> Result<(), String> {
    if sent.contains(&Sent::LeaderGone) || sent.contains(&Sent::Unproven) {
        return Err(format!(
            "a SIGTERM was due but not sent for another reason: {sent:?}"
        ));
    }
    let signals = signals(sent);
    if !signals.is_empty() && signals.iter().all(|s| *s == Sent::Kill) {
        Ok(())
    } else {
        Err(format!("not the kill alone: {sent:?}"))
    }
}

/// See [`judge_term_then_kill`].
pub(crate) async fn assert_term_then_kill(pid: Pid, what: &str) {
    if let Err(why) = judge_term_then_kill(&after_the_kill(pid).await) {
        panic!("{what}: {why}");
    }
}

/// See [`judge_strict`]: for a row on the full, uncut plan, which leaves the
/// reaper seconds of room.
pub(crate) async fn assert_term_then_kill_strict(pid: Pid, what: &str) {
    if let Err(why) = judge_strict(&after_the_kill(pid).await) {
        panic!("{what}: {why}");
    }
}

/// See [`judge_kill_without_term`].
pub(crate) async fn assert_kill_without_term(pid: Pid, what: &str) {
    if let Err(why) = judge_kill_without_term(&after_the_kill(pid).await) {
        panic!("{what}: {why}");
    }
}

/// A kill that failed while the leader was not seen exiting is recorded as a
/// failed kill, and the live rule refuses it by that name.
pub(crate) async fn assert_failed_kill_refused(pid: Pid, what: &str) {
    let sent = after_the_kill(pid).await;
    assert!(
        sent.contains(&Sent::KillFailed),
        "{what}: no failed kill recorded: {sent:?}"
    );
    match judge_term_then_kill(&sent) {
        Err(why) if why.contains("a kill failed") => {}
        other => panic!("{what}: a failed kill was not refused by name: {other:?}"),
    }
}

#[cfg(test)]
#[path = "stdio_child_tree_signal_log_tests.rs"]
mod tests;
