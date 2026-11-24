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
    /// The kill was sent and found no process (ESRCH), and the leader was seen
    /// exiting, before the send or right after the ESRCH: the group had already
    /// ended. macOS answers so for a group whose members have all exited; Linux
    /// answers Ok.
    KillGone,
    /// A kill's syscall failed, and not as `KillGone`, with its raw errno: the
    /// group may not have been the child's, or a member was beyond its reach.
    KillFailed {
        errno: i32,
    },
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
    let raw = pid.as_raw_nonzero().get();
    log().insert(raw, Vec::new());
    kills_at().remove(&raw);
    forget_injection(pid);
    // Read while the leader runs: macOS refuses getpgid once it is exiting.
    if rustix::process::getpgid(Some(pid)) == Ok(pid) {
        own_groups().insert(raw);
    } else {
        own_groups().remove(&raw);
    }
}

/// Pids that led their own group (pgid == pid, as spawned) when armed.
static OWN_GROUP: std::sync::Mutex<std::collections::BTreeSet<i32>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

fn own_groups() -> std::sync::MutexGuard<'static, std::collections::BTreeSet<i32>> {
    OWN_GROUP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether `pid` led its own group when it was armed.
fn own_group(pid: Pid) -> bool {
    own_groups().contains(&pid.as_raw_nonzero().get())
}

/// Drop an injection a stale row left for `pid`, or the one a finished row set.
fn forget_injection(pid: Pid) {
    injections().remove(&pid.as_raw_nonzero().get());
}

/// Append `sent` for `pid` when a row armed it; otherwise nothing.
pub(super) fn record(pid: Pid, sent: Sent) {
    if let Some(entries) = log().get_mut(&pid.as_raw_nonzero().get()) {
        entries.push(sent);
        if matches!(sent, Sent::Kill | Sent::KillGone | Sent::KillFailed { .. }) {
            kills_at()
                .entry(pid.as_raw_nonzero().get())
                .or_insert_with(std::time::Instant::now);
        }
    }
}

/// When the reaper sent its first kill to each armed pid's group.
static KILLS_AT: std::sync::Mutex<std::collections::BTreeMap<i32, std::time::Instant>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn kills_at() -> std::sync::MutexGuard<'static, std::collections::BTreeMap<i32, std::time::Instant>>
{
    KILLS_AT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// When the reaper sent its first kill to the armed `pid`'s group, if it did:
/// a row compares it with marks of its own, since a kill may come before the
/// plan's instant (a leader already gone is killed at once).
pub(crate) fn kill_sent_at(pid: Pid) -> Option<std::time::Instant> {
    kills_at().get(&pid.as_raw_nonzero().get()).copied()
}

/// How an injected group kill answers ESRCH, as macOS answers a group with no
/// live member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Esrch {
    /// Nothing is sent: the kill names a group the leader is not in.
    Only,
    /// The leader gets SIGKILL and is seen a zombie first, as the descendant
    /// sweep's kill can land between the check and the group kill; then the
    /// group kill finds no member.
    AfterKillingLeader,
    /// macOS's gap on any host: the leader gets SIGKILL and the group kill
    /// answers ESRCH at once, while the record reads the leader running for
    /// the next `steps` kills (one per reaper step); kills are judged on macOS
    /// rules throughout.
    MacGap { steps: u8 },
}

static INJECTED: std::sync::Mutex<std::collections::BTreeMap<i32, Esrch>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn injections() -> std::sync::MutexGuard<'static, std::collections::BTreeMap<i32, Esrch>> {
    INJECTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Make every group kill of `pid` answer ESRCH, as `mode` says.
pub(crate) fn inject(pid: Pid, mode: Esrch) {
    injections().insert(pid.as_raw_nonzero().get(), mode);
}

/// The injection a row set for `pid`, if any.
pub(super) fn injection(pid: Option<Pid>) -> Option<Esrch> {
    pid.and_then(|pid| injections().get(&pid.as_raw_nonzero().get()).copied())
}

/// The injected answer: ESRCH, after the leader is killed and seen a zombie
/// for `Esrch::AfterKillingLeader` (bounded at 30 s; a setup failure panics by
/// name rather than reading as a classified kill).
pub(super) fn answer(mode: Esrch, pid: Option<Pid>) -> std::io::Result<()> {
    if let (Esrch::MacGap { .. }, Some(pid)) = (mode, pid) {
        // No wait for the zombie: the gap is the point.
        match rustix::process::kill_process(pid, rustix::process::Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(e) => panic!("the injected gap kills the leader: {e}"),
        }
    }
    if let (Esrch::AfterKillingLeader, Some(pid)) = (mode, pid) {
        use rustix::process::{WaitId, WaitIdOptions, waitid};
        // A setup failure is the injection's own, never a classified kill.
        match rustix::process::kill_process(pid, rustix::process::Signal::KILL) {
            // macOS answers ESRCH for a leader already a zombie, as the
            // sweep's SIGKILL leaves it just before the group kill.
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(e) => panic!("the injected answer kills the leader: {e}"),
        }
        let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
        let by = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match waitid(WaitId::Pid(pid), options) {
                Ok(Some(_)) => break,
                // EINTR probes again, as the reaper's own leader probe does.
                Ok(None) | Err(rustix::io::Errno::INTR) => {}
                Err(e) => panic!("the injected answer waits on the leader: {e}"),
            }
            assert!(
                std::time::Instant::now() < by,
                "the injected answer's leader was not a zombie within 30 s"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    Err(std::io::Error::from_raw_os_error(
        rustix::io::Errno::SRCH.raw_os_error(),
    ))
}

/// Whether `sent` is ESRCH: no process left in the group.
pub(super) fn is_esrch(sent: &std::io::Result<()>) -> bool {
    sent.as_ref()
        .is_err_and(|e| e.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()))
}

/// What a group kill's ESRCH means for a leader not yet seen exited. A kill is
/// only sent while the leader is unreaped, so its group id cannot be reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EsrchOn {
    /// Linux: an unreaped leader, a zombie included, still takes the signal,
    /// so ESRCH means a group the leader is not in.
    Linux,
    /// macOS: a process given SIGKILL leaves signal delivery before waitid can
    /// report its exit, so ESRCH from the leader's own group means it is ending.
    MacOs,
}

/// This host's [`EsrchOn`]; other Unix hosts keep the strict Linux reading.
const HOST: EsrchOn = if cfg!(target_os = "macos") {
    EsrchOn::MacOs
} else {
    EsrchOn::Linux
};

/// What a kill's syscall result records: the kill; the kill of a group already
/// gone, for an error from the leader's own group that says no member is left
/// to signal (ESRCH with the leader seen exiting, before the send or right
/// after, or on macOS at once; on macOS, EPERM with no live member left, which
/// BSD killpg answers for a group of zombies); otherwise a failed kill with its
/// errno. EPERM with a live member, or on Linux, which signals zombies, stays a
/// failure: a member beyond our reach.
pub(super) fn classify(
    sent: &std::io::Result<()>,
    exited: bool,
    own_group: bool,
    live_member: bool,
    host: EsrchOn,
) -> Sent {
    let Err(error) = sent else {
        return Sent::Kill;
    };
    let errno = error.raw_os_error().unwrap_or(0);
    let esrch_gone =
        errno == rustix::io::Errno::SRCH.raw_os_error() && (exited || host == EsrchOn::MacOs);
    let eperm_gone =
        errno == rustix::io::Errno::PERM.raw_os_error() && !live_member && host == EsrchOn::MacOs;
    if own_group && (esrch_gone || eperm_gone) {
        Sent::KillGone
    } else {
        Sent::KillFailed { errno }
    }
}

/// [`classify`] for an armed `pid` on this host, or on macOS rules with the
/// gap's masked steps under `Esrch::MacGap`.
pub(super) fn kill_outcome(pid: Pid, sent: &std::io::Result<()>, exited: bool) -> Sent {
    let (exited, host) = match gap_step(pid) {
        Some(in_gap) => (exited && !in_gap, EsrchOn::MacOs),
        None => (exited, HOST),
    };
    let live = !is_eperm(sent) || group_has_live_member(pid);
    classify(sent, exited, own_group(pid), live, host)
}

/// Whether `sent` is EPERM: members found, none signalled.
fn is_eperm(sent: &std::io::Result<()>) -> bool {
    sent.as_ref()
        .is_err_and(|e| e.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error()))
}

/// Whether the group `pid` leads still holds a member that is not a zombie,
/// read right after an EPERM. A table that cannot be read counts as live, and
/// so does every host but macOS, whose killpg is the one that answers EPERM for
/// a group of zombies: there EPERM stays a failure.
fn group_has_live_member(pid: Pid) -> bool {
    #[cfg(target_os = "macos")]
    {
        u32::try_from(pid.as_raw_nonzero().get())
            .ok()
            .and_then(super::super::sweep::PlatformTable::group_has_live_member)
            .unwrap_or(true)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        true
    }
}

/// Under `Esrch::MacGap`, whether this kill falls in the gap (the record reads
/// the leader running), counting the gap down; `None` without that injection.
fn gap_step(pid: Pid) -> Option<bool> {
    match injections().get_mut(&pid.as_raw_nonzero().get()) {
        Some(Esrch::MacGap { steps }) => {
            let in_gap = *steps > 0;
            *steps = steps.saturating_sub(1);
            Some(in_gap)
        }
        _ => None,
    }
}

/// `pid`'s entries in order; it is disarmed.
pub(crate) fn take(pid: Pid) -> Vec<Sent> {
    forget_injection(pid);
    own_groups().remove(&pid.as_raw_nonzero().get());
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
            .any(|s| matches!(s, Sent::Kill | Sent::KillGone | Sent::KillFailed { .. }))
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

/// The SIGTERM and kill entries alone, in order; a kill of a group already
/// gone reads as the kill. No rule can ask for a kill that landed: the sweep
/// SIGKILLs the leader and its tree just before the group kill, so on macOS
/// even a SIGTERM-resisting tree's first kill can find the group gone.
fn signals(sent: &[Sent]) -> Vec<Sent> {
    sent.iter()
        .filter_map(|s| match s {
            Sent::Term | Sent::Kill => Some(*s),
            Sent::KillGone => Some(Sent::Kill),
            _ => None,
        })
        .collect()
}

/// One SIGTERM first, then one or more kills and no later SIGTERM.
fn term_then_kill(sent: &[Sent]) -> bool {
    matches!(signals(sent).split_first(), Some((Sent::Term, rest))
        if !rest.is_empty() && rest.iter().all(|s| *s == Sent::Kill))
}

/// A failed kill anywhere is refused first, by name.
fn no_failed_kill(sent: &[Sent]) -> Result<(), String> {
    if sent.iter().any(|s| matches!(s, Sent::KillFailed { .. })) {
        Err(format!("a kill failed: {sent:?}"))
    } else {
        Ok(())
    }
}

fn has_skip(sent: &[Sent]) -> bool {
    sent.iter().any(|s| matches!(s, Sent::SkipLate { .. }))
}

/// The live rows' rule: one SIGTERM, then the kill, with no skip recorded; or,
/// on a host that starved the reaper past its slack, no SIGTERM at all, only
/// late skips whose lateness exceeds the threshold, then the kill. Any other
/// shape is refused with its reason.
fn judge_term_then_kill(sent: &[Sent]) -> Result<(), String> {
    no_failed_kill(sent)?;
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
    if mutant!("J2", false, !has_skip(sent)) {
        return Err(format!(
            "killed with no SIGTERM and no recorded reason: {sent:?}"
        ));
    }
    let threshold = skip_threshold();
    for s in sent {
        if let Sent::SkipLate { late } = s
            && mutant!("J1", *late < threshold, *late <= threshold)
        {
            return Err(format!(
                "SIGTERM skipped {late:?} late, under the {threshold:?} the slack allows: {sent:?}"
            ));
        }
    }
    if signals(sent).contains(&Sent::Kill) {
        Ok(())
    } else {
        Err(format!("no kill after the skip: {sent:?}"))
    }
}

/// The kill with no SIGTERM; a late skip is allowed (these plans leave no
/// room for one), any other unsent reason is refused.
fn judge_kill_without_term(sent: &[Sent]) -> Result<(), String> {
    no_failed_kill(sent)?;
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

/// See [`judge_kill_without_term`].
pub(crate) async fn assert_kill_without_term(pid: Pid, what: &str) {
    if let Err(why) = judge_kill_without_term(&after_the_kill(pid).await) {
        panic!("{what}: {why}");
    }
}

/// A kill that found the group gone is recorded as such, and
/// [`judge_term_then_kill`] takes it as the kill.
pub(crate) async fn assert_gone_kill_counts(pid: Pid, what: &str) {
    let sent = after_the_kill(pid).await;
    assert!(
        sent.contains(&Sent::KillGone),
        "{what}: no kill of a group already gone recorded: {sent:?}"
    );
    if let Err(why) = judge_term_then_kill(&sent) {
        panic!("{what}: {why}");
    }
}

#[cfg(tp5)]
#[cfg(test)]
#[path = "stdio_child_tree_signal_log_tests.rs"]
mod tests;
