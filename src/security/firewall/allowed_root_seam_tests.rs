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
