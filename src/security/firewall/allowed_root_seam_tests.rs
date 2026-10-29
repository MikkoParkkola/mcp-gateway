// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Seam rows: the shared deadline, the resolver pool and directory-read
//! errors, through the per-firewall seams (test plan 2.1, 9.1, 9.7). No row
//! reads a real clock: deadlines are decided by the clock seam, progress by
//! events. Batch 3.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::super::*;

/// The real filesystem, as the production resolver reads it.
pub(super) fn real(op: &ResolveOp) -> std::io::Result<Resolved> {
    match op {
        ResolveOp::Metadata(p) => {
            let t = std::fs::symlink_metadata(p)?.file_type();
            Ok(Resolved::Kind(if t.is_symlink() {
                EntryKind::Symlink
            } else if t.is_dir() {
                EntryKind::Directory
            } else {
                EntryKind::File
            }))
        }
        ResolveOp::Canonicalize(p) => std::fs::canonicalize(p).map(Resolved::Path),
        ResolveOp::ReadDir(p) => Ok(Resolved::Entries(
            std::fs::read_dir(p)?
                .map(|e| e.map(|e| e.file_name()))
                .collect(),
        )),
    }
}

/// Blocks every read until opened; sends an event as each read enters and
/// counts reads by kind. Dropping the last handle opens the gate, so a
/// panicking row never leaves a pool thread held.
#[derive(Default)]
pub(super) struct Gated {
    open: Mutex<bool>,
    wake: Condvar,
    entered: Mutex<Option<mpsc::Sender<ResolveOp>>>,
    pub(super) calls: AtomicUsize,
    pub(super) deadlines: Mutex<Vec<Instant>>,
}

impl Gated {
    /// A gated resolver and the receiver of its "entered" events.
    pub(super) fn new() -> (Arc<Self>, mpsc::Receiver<ResolveOp>) {
        let (tx, rx) = mpsc::channel();
        let gated = Arc::new(Self::default());
        *gated.entered.lock().expect("entered") = Some(tx);
        (gated, rx)
    }

    pub(super) fn open(&self) {
        *self.open.lock().expect("gate") = true;
        self.wake.notify_all();
    }

    /// Opens the gate when the returned guard drops.
    pub(super) fn guard(self: &Arc<Self>) -> OpenOnDrop {
        OpenOnDrop(Arc::clone(self))
    }
}

pub(super) struct OpenOnDrop(Arc<Gated>);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        self.0.open();
    }
}

impl Resolve for Gated {
    fn resolve(&self, op: &ResolveOp, deadline: Instant) -> std::io::Result<Resolved> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.deadlines.lock().expect("deadlines").push(deadline);
        if let Some(tx) = self.entered.lock().expect("entered").as_ref() {
            let _ = tx.send(op.clone());
        }
        let mut open = self.open.lock().expect("gate");
        while !*open {
            open = self.wake.wait(open).expect("gate");
        }
        drop(open);
        real(op)
    }
}

/// Which directory read fails, for R33g and R33h.
#[derive(Clone, Copy)]
pub(super) enum Fail {
    /// `read_dir` itself is refused.
    ReadDir,
    /// The listing opens, then one entry fails to read.
    Entry,
}

pub(super) struct Failing(pub(super) Fail);

impl Resolve for Failing {
    fn resolve(&self, op: &ResolveOp, _deadline: Instant) -> std::io::Result<Resolved> {
        let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        match (op, self.0) {
            (ResolveOp::ReadDir(_), Fail::ReadDir) => Err(denied()),
            (ResolveOp::ReadDir(_), Fail::Entry) => {
                let Resolved::Entries(mut entries) = real(op)? else {
                    unreachable!("read_dir answers entries")
                };
                entries.push(Err(denied()));
                Ok(Resolved::Entries(entries))
            }
            _ => real(op),
        }
    }
}

/// A clock a row moves by hand.
pub(super) struct Manual(Mutex<Instant>);

impl Manual {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Instant::now())))
    }

    pub(super) fn advance(&self, by: Duration) {
        *self.0.lock().expect("clock") += by;
    }
}

impl Clock for Manual {
    fn now(&self) -> Instant {
        *self.0.lock().expect("clock")
    }
}

/// Records every read and the deadline it was given, and moves `clock` by
/// `step` as each read runs, so a row decides the deadline without waiting.
pub(super) struct Stepping {
    clock: Arc<Manual>,
    step: Duration,
    pub(super) ops: Mutex<Vec<(ResolveOp, Instant)>>,
}

impl Stepping {
    pub(super) fn new(clock: &Arc<Manual>, step: Duration) -> Arc<Self> {
        Arc::new(Self {
            clock: Arc::clone(clock),
            step,
            ops: Mutex::new(Vec::new()),
        })
    }
}

impl Resolve for Stepping {
    fn resolve(&self, op: &ResolveOp, deadline: Instant) -> std::io::Result<Resolved> {
        self.ops.lock().expect("ops").push((op.clone(), deadline));
        self.clock.advance(self.step);
        real(op)
    }
}

use super::tree::{Fx, target};
use serde_json::{Value, json};

/// `fx` with `seams` applied to its firewall.
fn seamed(fx: Fx, seams: impl FnOnce(Firewall) -> Firewall) -> Fx {
    Fx {
        fw: seams(fx.fw),
        ..fx
    }
}

fn forced(fx: &Fx, args: &Value) -> Option<RootReason> {
    let sender = fx.sender();
    root_check(&fx.fw, target("read_file"), args, sender.as_deref())
        .forced
        .map(|refusal| refusal.reason)
}

/// R16: a read that outlives the budget refuses the call `timeout`, and no
/// read starts after it; control: a zero step completes.
#[test]
fn r16_a_read_past_the_deadline_times_out() {
    let clock = Manual::new();
    let slow = Stepping::new(&clock, Duration::from_secs(3));
    let (c, s) = (Arc::clone(&clock), Arc::clone(&slow));
    let fx = seamed(Fx::new(&["path"], FirewallAction::Block), |fw| {
        fw.with_clock(c).with_resolver(s)
    });
    assert_eq!(
        forced(&fx, &json!({"path": fx.path("safe/f")})),
        Some(RootReason::Timeout)
    );
    assert_eq!(
        slow.ops.lock().expect("ops").len(),
        1,
        "nothing starts past the deadline"
    );

    let quick = Stepping::new(&clock, Duration::ZERO);
    let (c, q) = (Arc::clone(&clock), Arc::clone(&quick));
    let fx = seamed(Fx::new(&["path"], FirewallAction::Block), |fw| {
        fw.with_clock(c).with_resolver(q)
    });
    assert_eq!(forced(&fx, &json!({"path": fx.path("safe/f")})), None);
}

/// R16b: two values share one 2 s budget: at 1.5 s a read, the call times
/// out once the original instant passes, and every read got that instant.
#[test]
fn r16b_values_share_one_deadline() {
    let clock = Manual::new();
    let step = Stepping::new(&clock, Duration::from_millis(1500));
    let (c, s) = (Arc::clone(&clock), Arc::clone(&step));
    let fx = Fx::with_rules(|safe| {
        let args = ["a", "b"];
        vec![super::tree::root_rule(
            "read_file",
            &[safe],
            &args,
            FirewallAction::Block,
        )]
    });
    let fx = seamed(fx, |fw| fw.with_clock(c).with_resolver(s));
    let args = json!({"a": fx.path("safe/f"), "b": fx.path("safe/f")});
    assert_eq!(forced(&fx, &args), Some(RootReason::Timeout));
    let ops = step.ops.lock().expect("ops");
    assert!(ops.len() >= 2, "both values started: {ops:?}");
    assert!(
        ops.iter().all(|(_, d)| *d == ops[0].1),
        "one deadline: {ops:?}"
    );
}

/// R33g, R33h: a refused `read_dir` and a failing entry are `unresolvable`,
/// never an empty directory; control: the real filesystem allows it.
#[test]
fn r33g_r33h_directory_read_errors_refuse() {
    for (row, fail) in [("R33g", Fail::ReadDir), ("R33h", Fail::Entry)] {
        let fx = seamed(Fx::new(&["path"], FirewallAction::Block), |fw| {
            fw.with_resolver(Arc::new(Failing(fail)))
        });
        let args = json!({"path": fx.path("safe/new.txt")});
        assert_eq!(forced(&fx, &args), Some(RootReason::Unresolvable), "{row}");
    }
    let fx = Fx::new(&["path"], FirewallAction::Block);
    assert_eq!(forced(&fx, &json!({"path": fx.path("safe/new.txt")})), None);
}

/// R44: ten array values under one root and one parent: the root is
/// canonicalised once and the directory listed once.
#[test]
fn r44_reads_are_cached_within_a_call() {
    let reads = Stepping::new(&Manual::new(), Duration::ZERO);
    let r = Arc::clone(&reads);
    let fx = Fx::with_rules(|safe| {
        let args = ["paths[]"];
        vec![super::tree::root_rule(
            "read_file",
            &[safe],
            &args,
            FirewallAction::Block,
        )]
    });
    let fx = seamed(fx, |fw| fw.with_resolver(r));
    let paths: Vec<String> = (0..10).map(|i| fx.path(&format!("safe/n{i}"))).collect();
    assert_eq!(forced(&fx, &json!({"paths": paths})), None);
    let root = fx.dir.path().join("safe");
    let ops = reads.ops.lock().expect("ops");
    let canonicalised = |p: &std::path::Path| {
        ops.iter()
            .filter(|(op, _)| *op == ResolveOp::Canonicalize(p.to_path_buf()))
            .count()
    };
    assert_eq!(canonicalised(&root), 1, "the root, once: {ops:?}");
    let mut listed: Vec<_> = ops
        .iter()
        .filter_map(|(op, _)| match op {
            ResolveOp::ReadDir(p) => Some(p.clone()),
            _ => None,
        })
        .collect();
    assert!(
        listed.iter().any(|p| p.ends_with("safe")),
        "safe/ listed: {ops:?}"
    );
    let total = listed.len();
    listed.sort();
    listed.dedup();
    assert_eq!(listed.len(), total, "no directory listed twice: {ops:?}");
}
