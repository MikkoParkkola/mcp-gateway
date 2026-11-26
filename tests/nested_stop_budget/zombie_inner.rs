// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SNAP.7 zombie-inner rows. The inner gateway's leaf keeps an unreaped zombie
//! child, so the inner's own descendant sweep never settles and freezes for its
//! whole slice. Whatever the outer does, no process of the tree may outlive the
//! outer. Both gateways log each sweep's freeze start and end at debug; a row
//! that needs one of those lines and does not find it fails.

use super::*;

/// Info for every module, debug for the sweep's two freeze lines.
const SWEEP_LOG: &str = "mcp_gateway=info,mcp_gateway::transport::stdio::sweep=debug";
const FREEZE_START: &str = "descendant sweep: freeze start";
const FREEZE_END: &str = "descendant sweep: freeze end";

/// How the stdio outer ends: EOF only (its planned stop, natural ordering), or
/// EOF, then a SIGTERM sent once the inner's sweep has begun, which hurries the
/// outer to a kill after roughly 300 ms, inside the inner's freeze.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    Eof,
    Hurried,
}

/// What one zombie-inner stop left: the tree's pids still alive once the outer
/// had exited, every recorded pid, and both gateways' logs without colour codes.
struct Ended {
    alive: Vec<u32>,
    tree: Vec<u32>,
    outer_log: String,
    inner_log: String,
}

/// A log as plain text: colour escapes dropped, so field matches are exact.
fn plain(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for skipped in chars.by_ref() {
                if skipped.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The stdio outer's process: both log filters set, its stdout and stderr
/// into `gateway.log`, its own process group so a panic's cleanup ends it.
fn outer_command(root: &Path, config: &Path) -> tokio::process::Command {
    let config_path = config.display().to_string();
    let home = root.join("home");
    let inherit = gateway_bin::Inherit::Environment;
    let std_command = gateway_bin::command(&home, inherit);
    let mut command = tokio::process::Command::from(std_command);
    command.args(["--config", config_path.as_str(), "serve", "--stdio"]);
    command.current_dir(root);
    command.env("RUST_LOG", SWEEP_LOG);
    command.env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"));
    let out_file = std::fs::File::create(root.join("gateway.log")).expect("outer log file");
    let err_file = out_file.try_clone().expect("second outer log handle");
    command.stdin(Stdio::piped());
    command.stdout(Stdio::from(out_file));
    command.stderr(Stdio::from(err_file));
    command.process_group(0).kill_on_drop(true);
    command
}

/// Wait up to `READY_BOUND` for `done`, polling; the row fails with `what` and
/// the logs if it never comes.
async fn until(root: &Path, what: &str, done: impl Fn() -> bool) {
    let give_up = Instant::now() + READY_BOUND;
    while !done() {
        assert!(Instant::now() < give_up, "{what}\n{}", logs(root));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Start the stdio outer over an inner gateway with one zombie-holding leaf,
/// put the leaf on a held call, stop the outer the given way and wait for the
/// outer process itself to exit; then read which pids of the tree are alive.
async fn zombie_chain(stop: Stop) -> Ended {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path();
    let names = ["zombie"];
    let inner = write_inner_config(root, &names, Duration::from_secs(30));
    let config = write_chain_parent(
        root,
        "outer",
        "inner",
        &inner,
        During::Nothing,
        Some(SWEEP_LOG),
    );
    // spawn-check: the outer's exit is awaited below; Reaped reaps it, KillGroup ends the tree on a panic
    let spawned = outer_command(root, &config)
        .spawn()
        .expect("the stdio outer starts");
    let mut outer = gateway_bin::Reaped::new(spawned);
    let pid = outer.child_mut().id().expect("outer pid");
    let guard = KillGroup {
        pid,
        root: root.into(),
    };
    let mut input = outer.child_mut().stdin.take().expect("outer stdin");
    let notified = json!({"jsonrpc":"2.0", "method":"notifications/initialized"});
    let opening = format!("{}\n{notified}\n{}\n", initialize(), invoke(names[0], 1));
    input
        .write_all(opening.as_bytes())
        .await
        .expect("the opening reaches the outer");
    let called = root.join(format!("called-{}", names[0]));
    until(root, "the zombie leaf never held its call", || {
        called.exists()
    })
    .await;
    let tree: Vec<u32> = chain_roles(root, &names).iter().map(|(_, p)| *p).collect();
    assert_eq!(
        alive_pids(&tree),
        tree,
        "premise: every recorded pid is live before the stop"
    );
    drop(input);
    until(root, "the outer never logged its EOF", || {
        logs(root).contains("stdio: EOF reached, shutting down")
    })
    .await;
    if stop == Stop::Hurried {
        // Forced takeover (F8): the SIGTERM waits for the inner's own sweep to
        // begin, so the outer's hurry lands inside the inner's freeze. Left to
        // the clock, the inner's 1 s pre-reap grace always loses to the outer's
        // 300 ms hurry. No line within the bound fails the row: a premise.
        let inner_log = root.join("inner.log");
        until(
            root,
            "premise: the inner logged no freeze start before the SIGTERM",
            || std::fs::read_to_string(&inner_log).is_ok_and(|text| text.contains(FREEZE_START)),
        )
        .await;
        sigterm(pid);
    }
    let exit = tokio::time::timeout(STDIO_SIGTERM_EXIT_BOUND, outer.child_mut().wait()).await;
    exit.unwrap_or_else(|_| panic!("the outer did not exit\n{}", logs(root)))
        .expect("the outer's exit status");
    let read = |name: &str| plain(&std::fs::read_to_string(root.join(name)).unwrap_or_default());
    let ended = Ended {
        alive: alive_pids(&tree),
        tree,
        outer_log: read("gateway.log"),
        inner_log: read("inner.log"),
    };
    outer.reap().await;
    std::mem::forget(guard);
    ended
}

/// The first line of `log` that carries `marker`, if any.
fn line_with<'a>(log: &'a str, marker: &str) -> Option<&'a str> {
    log.lines().find(|line| line.contains(marker))
}

/// The leading RFC 3339 timestamp of a log line. Both gateways write the same
/// UTC format, so two of them order correctly as text. A line without one
/// fails the row: an order that cannot be read is never a pass.
fn stamp(line: &str) -> &str {
    let first = line.split_whitespace().next().unwrap_or_default();
    assert!(
        first.len() >= 20 && first.as_bytes()[4] == b'-' && first.ends_with('Z'),
        "a sweep line has no UTC timestamp: {line}"
    );
    first
}

/// Planned stop (EOF only) of an outer whose inner holds a zombie: the inner's
/// own sweep must have run unsettled to the end of its slice (the premise that
/// the zombie rule was exercised), and no process of the tree may survive.
/// Red if a zombie-holding tree leaves a leaf behind, or if the inner's sweep
/// settled with a zombie in its tree.
#[tokio::test]
async fn a_zombie_holding_inner_still_leaves_no_leaf() {
    let ended = zombie_chain(Stop::Eof).await;
    let end = line_with(&ended.inner_log, FREEZE_END).unwrap_or_else(|| {
        panic!(
            "the inner logged no freeze end (missing line = FAIL)\n{}",
            ended.inner_log
        )
    });
    assert!(
        end.contains("settled=false"),
        "the inner's sweep settled with a zombie in its tree: {end}"
    );
    assert!(
        ended.alive.is_empty(),
        "tree pids alive after the outer exited: {:?} of {:?}\n{}\n--- inner ---\n{}",
        ended.alive,
        ended.tree,
        ended.outer_log,
        ended.inner_log
    );
}

/// Hurried stop of the same chain, forced to overlap: the outer's SIGTERM is
/// sent only once the inner logged its freeze start (a premise: no line, the
/// row fails), and the outer's kill comes about 300 ms later, while the inner's
/// unsettled freeze runs for its 700 ms slice. No process of the tree may
/// survive, and the outer (which always sweeps) must have logged a freeze start.
/// The run prints one TAKEOVER line: `yes` only when the outer's sweep started at
/// or after the inner's freeze start and before the inner's freeze end (or the
/// inner logged no end, being frozen or killed mid-freeze). The SNAP.7 harness
/// counts those lines (bar: at least 19 of 20); the row itself asserts only what
/// every run must show.
/// Red if a hurried takeover of a zombie-holding inner leaves a leaf behind.
#[tokio::test]
async fn a_hurried_takeover_of_a_freezing_inner_leaves_no_leaf() {
    let ended = zombie_chain(Stop::Hurried).await;
    let outer_start = line_with(&ended.outer_log, FREEZE_START)
        .map(stamp)
        .unwrap_or_else(|| {
            panic!(
                "the outer logged no freeze start (missing line = FAIL)\n{}",
                ended.outer_log
            )
        });
    let inner_start = line_with(&ended.inner_log, FREEZE_START).map(stamp);
    let inner_end = line_with(&ended.inner_log, FREEZE_END).map(stamp);
    let takeover = inner_start.is_some_and(|start| start <= outer_start)
        && inner_end.is_none_or(|end| outer_start < end);
    println!(
        "TAKEOVER={} inner_start={} outer_start={outer_start} inner_end={}",
        if takeover { "yes" } else { "no" },
        inner_start.unwrap_or("none"),
        inner_end.unwrap_or("none")
    );
    assert!(
        ended.alive.is_empty(),
        "tree pids alive after the hurried outer exited: {:?} of {:?}\n{}\n--- inner ---\n{}",
        ended.alive,
        ended.tree,
        ended.outer_log,
        ended.inner_log
    );
}
