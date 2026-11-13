// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stdio tree's graceful ending: the MCP stdio stop order (close stdin,
//! wait, SIGTERM, wait, then the kill), each wait fitted to the stop's
//! budget, and the gateway stop deadline that cuts trees already in their
//! waits. Helpers are the parent module's.

use super::*;

/// A backend that writes on its way out after stdin closes (a gateway run as
/// a stdio backend saves its telemetry, costs and audit then) gets to finish
/// that write: closing the transport waits, bounded, for the leader to exit
/// before the group is killed.
#[tokio::test]
async fn a_shutdown_write_after_stdin_closes_lands_before_close_returns() {
    let (w, t) = started(
        "cat >/dev/null\nsleep 0.3\necho landed > shutdown.mark",
        None,
    )
    .await;
    t.close().await.expect("close");
    assert_eq!(
        std::fs::read_to_string(w.path().join("shutdown.mark"))
            .ok()
            .as_deref(),
        Some("landed\n"),
        "the backend was killed before its shutdown write, 300 ms after stdin closed"
    );
}

/// A backend that ignores EOF but saves on SIGTERM (the MCP stdio order:
/// close stdin, wait, SIGTERM, wait, SIGKILL) gets its SIGTERM, and its save
/// lands, before the group is killed.
#[tokio::test]
async fn a_backend_that_ignores_eof_gets_sigterm_before_sigkill() {
    let (w, t) = started(
        "trap 'echo termed > term.mark; exit 0' TERM\nwhile :; do sleep 0.05; done",
        None,
    )
    .await;
    t.close().await.expect("close");
    assert_eq!(
        std::fs::read_to_string(w.path().join("term.mark"))
            .ok()
            .as_deref(),
        Some("termed\n"),
        "the backend was SIGKILLed without a SIGTERM first"
    );
}

/// A backend that ignores EOF and SIGTERM is still killed, and close still
/// returns, within the bound: no backend can hold a stop open.
#[tokio::test]
async fn a_backend_that_ignores_eof_and_sigterm_dies_within_the_bound() {
    // The fixed plan outside a shutdown (EOF wait, SIGTERM wait, the reap
    // deadline) plus slack for a loaded host.
    const BOUND: Duration = Duration::from_secs(15);
    let (w, t) = started(&resists_term(), None).await;
    let child = descendant(w.path()).await;
    let pid = leader(&t).await;
    let started_at = std::time::Instant::now();
    tokio::time::timeout(BOUND, t.close())
        .await
        .expect("close returns within the bound")
        .expect("close");
    assert!(
        started_at.elapsed() < BOUND,
        "close took {:?}",
        started_at.elapsed()
    );
    assert_killed(pid).await;
    gone(child).await;
}

/// A tree already in its exit waits when the gateway stop begins (an
/// orphaned fresh build, closed under a long budget of its own) is cut to the
/// stop's deadline: its kill lands with the reap's reserve left, not when its
/// own plan would have ended.
#[tokio::test]
async fn a_tree_in_its_waits_is_killed_by_a_later_gateway_stop_deadline() {
    let (w, t) = started(&resists_term(), None).await;
    let child = descendant(w.path()).await;
    let pid = leader(&t).await;
    let deadline = Arc::new(super::super::super::reaper::StopDeadline::default());
    t.attach_stop_deadline(Arc::clone(&deadline));
    let own_plan_end = tokio::time::Instant::now() + Duration::from_secs(120);
    let closing = Arc::clone(&t);
    let close = tokio::spawn(async move {
        super::super::super::reaper::within_stop_deadline(own_plan_end, closing.close()).await
    });
    poll_until("the tree is handed over", || t.child.lock().tree.is_none()).await;
    let started_at = std::time::Instant::now();
    let cut = super::super::super::reaper::KILL_RESERVE + Duration::from_secs(1);
    deadline.move_earlier(started_at + cut);
    assert_killed(pid).await;
    assert!(
        started_at.elapsed() < Duration::from_secs(10),
        "the kill waited for the tree's own plan: {:?}",
        started_at.elapsed()
    );
    close.await.expect("close task").expect("close");
    gone(child).await;
}

/// Ends a row's tree when the row ends, through its owner, so a red run leaks
/// no backend built to ignore signals: the row's stop deadline moves to now
/// (a tree already handed over is killed on the reaper's next step) and a
/// tree still in its slot is killed at once by the transport. No pid is
/// signalled from test code: a reaped pid may name someone else's group.
struct EndOnDrop(
    Arc<StdioTransport>,
    Arc<super::super::super::reaper::StopDeadline>,
);

impl EndOnDrop {
    /// A guard over `t`, with a fresh stop deadline attached to it.
    fn new(t: &Arc<StdioTransport>) -> Self {
        let deadline = Arc::new(super::super::super::reaper::StopDeadline::default());
        t.attach_stop_deadline(Arc::clone(&deadline));
        Self(Arc::clone(t), deadline)
    }

    fn deadline(&self) -> &Arc<super::super::super::reaper::StopDeadline> {
        &self.1
    }
}

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        self.1.move_earlier(std::time::Instant::now());
        self.0.kill_tree_now();
    }
}

/// A backend that ignores EOF, records each SIGTERM in `term.mark`, and runs
/// on: only the kill ends it.
const MARKS_TERM: &str = "trap 'echo termed > term.mark' TERM\nwhile :; do sleep 0.05; done";

/// A hurry keeps SIGTERM even when a reaper tick consumes part of its 300 ms.
/// Red if the hurried tree is killed without a preceding SIGTERM phase.
#[tokio::test]
async fn a_hurried_tree_keeps_its_term_phase_after_a_reaper_tick() {
    use super::super::super::reaper::{HURRY_WINDOW, KILL_RESERVE};
    let (w, t) = started(
        "trap '' TERM\necho ready > ready.mark\nwhile :; do sleep 0.05; done",
        None,
    )
    .await;
    let end = EndOnDrop::new(&t);
    poll_until("the TERM handler is installed", || {
        w.path().join("ready.mark").exists()
    })
    .await;
    with_tree(&t, |tree| {
        let now = std::time::Instant::now();
        tree.set_ending(
            Ending::Graceful {
                eof: Duration::from_secs(60),
                term: Duration::from_secs(30),
            },
            Some(Arc::clone(end.deadline())),
        );
        assert!(matches!(tree.reap_step(now), Reap::Pending));
        let cut = end.deadline().hurry(now);
        assert!(cut <= now + KILL_RESERVE + HURRY_WINDOW);
        let kill = cut
            .checked_sub(KILL_RESERVE)
            .expect("the hurry cut leaves the kill reserve");
        let before_kill = |ms: u64| {
            kill.checked_sub(Duration::from_millis(ms))
                .expect("the hurry window exceeds the probe offset")
        };
        // Model a tick's latency without making the row race a 300 ms clock.
        tree.reap_step(now + Duration::from_millis(10));
        tree.reap_step(before_kill(101));
        assert_eq!(tree.term_signals_sent, 0);
        tree.reap_step(before_kill(100));
        assert_eq!(tree.term_signals_sent, 1, "SIGTERM precedes the kill");
        assert_eq!(tree.group_signals_sent, 0, "the term phase is retained");
        tree.reap_step(kill);
        assert!(
            tree.group_signals_sent > 0,
            "the kill still lands at the cut"
        );
    })
    .await;
    tokio::time::timeout(Duration::from_secs(10), t.close())
        .await
        .expect("tree reaped")
        .expect("close");
}

/// Close `t` under a plan ending at `own_plan_end`, and wait for the handover.
async fn close_under(t: &Arc<StdioTransport>, own_plan_end: tokio::time::Instant) {
    let closing = Arc::clone(t);
    tokio::spawn(async move {
        super::super::super::reaper::within_stop_deadline(own_plan_end, closing.close()).await
    });
    poll_until("the tree is handed over", || t.child.lock().tree.is_none()).await;
}

/// Close `t` under a long plan of its own, then cut it with the guard's stop
/// deadline `cut_in` (plus the reap reserve) from now; returns the leader.
async fn cut_close(t: &Arc<StdioTransport>, end: &EndOnDrop, cut_in: Duration) -> Pid {
    let pid = leader(t).await;
    close_under(t, tokio::time::Instant::now() + Duration::from_secs(120)).await;
    let cut = std::time::Instant::now() + super::super::super::reaper::KILL_RESERVE + cut_in;
    end.deadline().move_earlier(cut);
    pid
}

/// A gateway stop that cuts a tree's waits short still sends SIGTERM before
/// the kill when what is left leaves room for both: the rest is split as the
/// plan was, its last third after SIGTERM.
#[tokio::test]
async fn a_cut_stop_still_sends_sigterm_before_the_kill() {
    let (w, t) = started(MARKS_TERM, None).await;
    let end = EndOnDrop::new(&t);
    let pid = cut_close(&t, &end, Duration::from_secs(3)).await;
    assert_killed(pid).await;
    assert_eq!(
        std::fs::read_to_string(w.path().join("term.mark"))
            .ok()
            .as_deref(),
        Some("termed\n"),
        "the cut stop killed the backend without a SIGTERM first"
    );
}

/// A cut that leaves under the minimum phase skips SIGTERM: the kill comes
/// at the cut, with nothing sent for a wait too short to use.
#[tokio::test]
async fn a_cut_under_the_minimum_phase_skips_sigterm() {
    let (w, t) = started(MARKS_TERM, None).await;
    let end = EndOnDrop::new(&t);
    let pid = cut_close(&t, &end, Duration::from_millis(50)).await;
    assert_killed(pid).await;
    assert!(
        !w.path().join("term.mark").exists(),
        "a SIGTERM was sent with no time left to act on it"
    );
}

/// A cut that leaves under the minimum phase skips SIGTERM even when the
/// uncut plan had its SIGTERM due before the cut: the plan (330 ms of waits:
/// 220 ms after EOF, then 110 ms after SIGTERM) is cut on its first step to
/// 295 ms, whose last third is under the minimum, so no SIGTERM goes out at
/// 220 ms (the old `min` with the uncut time sent one there).
#[tokio::test]
async fn a_short_cut_drops_an_earlier_uncut_sigterm() {
    let (w, t) = started(MARKS_TERM, None).await;
    let end = EndOnDrop::new(&t);
    let pid = leader(&t).await;
    let reserve = super::super::super::reaper::KILL_RESERVE;
    // The cut is set before the close, so the handover's first step applies it.
    end.deadline()
        .move_earlier(std::time::Instant::now() + reserve + Duration::from_millis(295));
    close_under(
        &t,
        tokio::time::Instant::now() + reserve + Duration::from_millis(330),
    )
    .await;
    assert_killed(pid).await;
    assert!(
        !w.path().join("term.mark").exists(),
        "the uncut plan's earlier SIGTERM survived a cut that left too little for one"
    );
}

/// Hand `t`'s tree straight to the reaper with a graceful ending under
/// `deadline`, as a close does; returns how many handovers the deadline then
/// tracks.
fn hand_over_gracefully(
    t: &StdioTransport,
    deadline: &Arc<super::super::super::reaper::StopDeadline>,
) -> usize {
    let mut slot = t.child.lock();
    let mut tree = slot.tree.take().expect("a started tree");
    let ending = Ending::Graceful {
        eof: Duration::from_secs(60),
        term: Duration::from_secs(30),
    };
    tree.set_ending(ending, Some(Arc::clone(deadline)));
    let _ = slot.track(tree);
    deadline.handed_len()
}

/// A graceful handover joins its gateway stop deadline in the handover
/// itself, before its first step: no window in which a stop's snapshot can
/// miss a handover that is already in its waits.
#[tokio::test]
async fn a_graceful_handover_joins_its_stop_deadline_in_the_handover() {
    let (_w, t) = started(&resists_term(), None).await;
    let end = EndOnDrop::new(&t);
    let pid = leader(&t).await;
    assert_eq!(
        hand_over_gracefully(&t, end.deadline()),
        1,
        "the handover is tracked"
    );
    end.deadline().move_earlier(std::time::Instant::now());
    assert_killed(pid).await;
}

/// The same for a handover whose stop deadline has already passed: it is
/// tracked too, so a stop's wait sees it, whichever reaper step ends it.
#[tokio::test]
async fn a_handover_whose_deadline_already_passed_is_tracked() {
    let (_w, t) = started(&resists_term(), None).await;
    let end = EndOnDrop::new(&t);
    let pid = leader(&t).await;
    end.deadline().move_earlier(std::time::Instant::now());
    assert_eq!(
        hand_over_gracefully(&t, end.deadline()),
        1,
        "the handover is tracked"
    );
    assert_killed(pid).await;
}

/// A second gateway stop with an earlier deadline moves it earlier; a later
/// one leaves it, so a second stop can shorten the waits, never extend them.
#[test]
fn a_second_earlier_stop_deadline_takes_effect_and_a_later_one_does_not() {
    let deadline = super::super::super::reaper::StopDeadline::default();
    assert_eq!(deadline.get(), None, "unset until a stop");
    let now = std::time::Instant::now();
    deadline.move_earlier(now + Duration::from_secs(30));
    deadline.move_earlier(now + Duration::from_secs(10));
    let earlier = deadline.get().expect("set");
    assert!(
        earlier <= now + Duration::from_secs(10),
        "the earlier stop took effect"
    );
    deadline.move_earlier(now + Duration::from_secs(60));
    assert_eq!(
        deadline.get(),
        Some(earlier),
        "a later stop changes nothing"
    );
}

/// The helper and its leaf sleep 600 s, far beyond `HANG_BOUND`: a leaf that merely
/// expired inside the wait would make a row pass without any sweep.
/// Start a helper that stays attached to the backend by parent pid but leads
/// its own session, so the backend's group kill never reaches it. The leaf's
/// pid lands in `leaf.pid`. The backend ignores EOF and SIGTERM alike.
async fn started_with_session_leaf(tail: &str) -> (tempfile::TempDir, Arc<StdioTransport>, u32) {
    let after = format!("trap '' TERM
cat > helper.py <<'PY'
import os, subprocess, time
null = subprocess.DEVNULL
leaf = subprocess.Popen(['sleep', '600'], start_new_session=True, stdin=null, stdout=null, stderr=null)
open('leaf.tmp', 'w').write(str(leaf.pid))
os.rename('leaf.tmp', 'leaf.pid')
time.sleep(600)
PY
python3 helper.py </dev/null >/dev/null 2>&1 &
{tail}");
    let (w, t) = started(&after, None).await;
    let leaf_file = w.path().join("leaf.pid");
    poll_until("the helper starts its leaf", || leaf_file.exists()).await;
    let leaf = std::fs::read_to_string(&leaf_file)
        .expect("leaf pid")
        .trim()
        .parse()
        .expect("a pid");
    (w, t, leaf)
}

/// Whether `pid` is a live process: a zombie waiting for its reaper is dead.
fn alive(pid: u32) -> bool {
    let out = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps runs");
    let stat = String::from_utf8_lossy(&out.stdout);
    let stat = stat.trim();
    !stat.is_empty() && !stat.starts_with('Z')
}

/// The descendant sweep runs on the ordinary stop as well as the hurried one:
/// a helper still attached to the backend, leading its own session, dies with
/// it. Red if the sweep is skipped on the ordinary path: the group kill alone
/// never reaches the leaf.
#[tokio::test]
async fn an_ordinary_close_kills_a_leaf_in_its_own_session() {
    let (_w, t, leaf) = started_with_session_leaf("while :; do sleep 0.05; done").await;
    assert!(alive(leaf), "the leaf runs before the stop");
    t.close().await.expect("close");
    poll_until("the leaf dies with the backend", || !alive(leaf)).await;
}

/// A backend that exits the moment its stdin closes reparents its helper before
/// the reaper's first step; the sweep's snapshot, taken before the stdin close,
/// still has the helper and its leaf. Red if the snapshot is taken only after
/// the close: the helper is no longer a descendant and the leaf survives.
#[tokio::test]
async fn a_leaf_of_a_backend_that_exits_on_eof_is_killed() {
    let (_w, t, leaf) = started_with_session_leaf("cat >/dev/null").await;
    assert!(alive(leaf), "the leaf runs before the stop");
    t.close().await.expect("close");
    poll_until("the leaf dies although its backend exited on EOF", || {
        !alive(leaf)
    })
    .await;
}

/// The parent pid of `pid`, or `None` once it is gone.
fn ppid_of(pid: u32) -> Option<u32> {
    let out = std::process::Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .expect("ps runs");
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Start a backend (ignoring EOF and SIGTERM) whose helper detaches BEFORE any
/// stop begins. `helper` is the Python the backend runs: it writes the
/// survivor's pid to `leaf.pid` and leaves it running, outside the backend's
/// descendants by parent pid.
async fn started_with_detached(helper: &str) -> (tempfile::TempDir, Arc<StdioTransport>, u32) {
    let after = format!(
        "trap '' TERM
cat > helper.py <<'PY'
{helper}
PY
python3 helper.py </dev/null >/dev/null 2>&1 &
while :; do sleep 0.05; done"
    );
    let (w, t) = started(&after, None).await;
    let leaf_file = w.path().join("leaf.pid");
    poll_until("the helper leaves its survivor", || leaf_file.exists()).await;
    let leaf = std::fs::read_to_string(&leaf_file)
        .expect("leaf pid")
        .trim()
        .parse()
        .expect("a pid");
    (w, t, leaf)
}

/// A process that left the backend's tree before the stop is outside the
/// sweep's reach: the stated limit, pinned. The row stops it afterwards.
async fn a_detached_survivor_outlives_the_stop(helper: &str, what: &str) {
    let (_w, t, leaf) = started_with_detached(helper).await;
    let backend = u32::try_from(leader(&t).await.as_raw_nonzero().get()).expect("pid fits");
    poll_until("the survivor is no longer the backend's child", || {
        ppid_of(leaf).is_some_and(|parent| parent != backend)
    })
    .await;
    t.close().await.expect("close");
    // timing: absence
    tokio::time::sleep(Duration::from_millis(300)).await;
    let survived = alive(leaf);
    assert!(
        survived,
        "{what} detached before the stop, so the sweep must leave it running"
    );
}

/// A helper that started a process and exited before the stop (the process is
/// orphaned and in its own session) is detached, so it survives the stop.
#[tokio::test]
async fn a_helper_detached_before_the_stop_survives_it() {
    let helper = "import os, subprocess
null = subprocess.DEVNULL
leaf = subprocess.Popen(['sleep', '30'], start_new_session=True, stdin=null, stdout=null, stderr=null)
open('leaf.tmp', 'w').write(str(leaf.pid))
os.rename('leaf.tmp', 'leaf.pid')";
    a_detached_survivor_outlives_the_stop(helper, "an orphaned helper process").await;
}

/// A double-forked daemon survives the stop, as it always did.
#[tokio::test]
async fn a_double_forked_daemon_survives_the_stop() {
    let helper = "import os, time
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        open('leaf.tmp', 'w').write(str(os.getpid()))
        os.rename('leaf.tmp', 'leaf.pid')
        time.sleep(30)
    os._exit(0)
os.wait()";
    a_detached_survivor_outlives_the_stop(helper, "a double-forked daemon").await;
}
