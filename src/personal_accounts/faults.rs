// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only fault control for the durable-commit persistence boundaries.
//!
//! A directory mode denies a write. It cannot deny an `fsync`, a rename or a
//! parent-directory sync, and those are exactly the steps that decide whether
//! an acknowledged credential mutation survives a crash. This module makes each
//! boundary individually selectable, once, deterministically.
//!
//! CONTRACT FOR THE RUNTIME, so the later commit path cannot drift from what
//! these tests assert. The design persists BOTH files the same way — owner-only
//! exclusive temporary creation, write, file sync, atomic rename, parent
//! directory sync — so both get the whole sequence. `commit_grant` calls
//! `reached` at exactly these points, in this order, propagating the error
//! unchanged:
//!
//! 1. `RecordWrite` — writing the candidate's bytes to its temporary file
//! 2. `RecordSync` — the fsync of that candidate
//! 3. `RecordRename` — the atomic rename of the candidate into `store_dir`
//! 4. `RecordParentSync` — the fsync of `store_dir` after that rename
//! 5. `CommitCheckpoint` — the candidate is durable, the manifest has not moved
//! 6. `ManifestWrite` — writing the new manifest's bytes to its temporary file
//! 7. `ManifestSync` — the fsync of that manifest
//! 8. `ManifestRename` — the atomic replacement of the authority manifest
//! 9. `ParentSync` — the fsync of the AUTHORITY directory after that rename
//!
//! `ParentSync` keeps its established name and means the authority directory;
//! the candidate's own is `RecordParentSync`. If a symmetric `ManifestParentSync`
//! reads better later, that is a rename, not a missing boundary.
//!
//! An armed fault fires ONCE and then disarms, so the retry after it is a clean
//! control: a store that is merely wedged cannot pass. `CommitCheckpoint` is
//! the abort point a crash test needs; it is selected by environment variable
//! because it must cross a process boundary, and it kills the process outright
//! rather than returning, since a returned error is not a crash.
//!
//! Nothing here is compiled outside `cfg(test)`.

use super::AccountError;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// Environment variable naming the boundary at which a child process dies.
pub(super) const ABORT_AT: &str = "MCP_ACCOUNTS_ABORT_AT";

/// Line a child flushes immediately before dying at a boundary. The parent
/// reads WHICH window the crash used; a process that merely ended is not
/// evidence that the intended window was ever entered.
pub(super) const CHECKPOINT: &str = "ACCOUNT_CHILD_CHECKPOINT:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Boundary {
    RecordWrite,
    RecordSync,
    RecordRename,
    RecordParentSync,
    CommitCheckpoint,
    ManifestWrite,
    ManifestSync,
    ManifestRename,
    ParentSync,
}

/// Every durable step, in commit order. A case that iterates this cannot miss a
/// boundary by forgetting to list it.
pub(super) const ALL: [Boundary; 9] = [
    Boundary::RecordWrite,
    Boundary::RecordSync,
    Boundary::RecordRename,
    Boundary::RecordParentSync,
    Boundary::CommitCheckpoint,
    Boundary::ManifestWrite,
    Boundary::ManifestSync,
    Boundary::ManifestRename,
    Boundary::ParentSync,
];

impl Boundary {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::RecordWrite => "record_write",
            Self::RecordSync => "record_sync",
            Self::RecordRename => "record_rename",
            Self::RecordParentSync => "record_parent_sync",
            Self::CommitCheckpoint => "commit_checkpoint",
            Self::ManifestWrite => "manifest_write",
            Self::ManifestSync => "manifest_sync",
            Self::ManifestRename => "manifest_rename",
            Self::ParentSync => "parent_sync",
        }
    }
}

thread_local! {
    static ARMED: RefCell<Option<(Boundary, Rc<Cell<bool>>)>> = const { RefCell::new(None) };
}

/// A live fault selection. Dropping it disarms, so one test cannot leak a fault
/// into the next case on the same thread.
pub(super) struct Armed {
    fired: Rc<Cell<bool>>,
}

impl Armed {
    /// Whether the selected boundary was actually reached. A durability case
    /// that never reaches its boundary proves nothing and must say so.
    pub(super) fn fired(&self) -> bool {
        self.fired.get()
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        ARMED.with(|slot| *slot.borrow_mut() = None);
    }
}

pub(super) fn arm(boundary: Boundary) -> Armed {
    let fired = Rc::new(Cell::new(false));
    ARMED.with(|slot| *slot.borrow_mut() = Some((boundary, Rc::clone(&fired))));
    Armed { fired }
}

/// Called by the commit path at each persistence boundary. Returns the error
/// the boundary would produce, or dies here when a child was told to.
pub(super) fn reached(boundary: Boundary) -> Result<(), AccountError> {
    if std::env::var(ABORT_AT).is_ok_and(|name| name == boundary.name()) {
        // Announce the exact boundary and flush BEFORE dying, so the parent
        // observes which window the crash used instead of inferring it from a
        // process that simply ended. Then: no unwinding, no Drop, no manifest
        // replacement, no lock release.
        println!("{CHECKPOINT}{}", boundary.name());
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::process::abort();
    }
    ARMED.with(|slot| {
        let mut slot = slot.borrow_mut();
        match slot.as_ref() {
            Some((armed, fired)) if *armed == boundary => {
                fired.set(true);
                *slot = None;
                Err(AccountError::StorageUnavailable)
            }
            _ => Ok(()),
        }
    })
}

#[test]
fn a_fault_fires_once_at_its_own_boundary_and_then_disarms() {
    let armed = arm(Boundary::ManifestRename);
    assert!(!armed.fired());
    assert_eq!(
        reached(Boundary::RecordSync),
        Ok(()),
        "another boundary is untouched"
    );
    assert!(!armed.fired());
    assert_eq!(
        reached(Boundary::ManifestRename),
        Err(AccountError::StorageUnavailable)
    );
    assert!(armed.fired(), "the selection records that it was reached");
    assert_eq!(
        reached(Boundary::ManifestRename),
        Ok(()),
        "one shot only, so the retry after a fault is a clean control"
    );
}

#[test]
fn an_unarmed_boundary_is_transparent() {
    for boundary in ALL {
        assert_eq!(reached(boundary), Ok(()));
    }
}

#[test]
fn every_boundary_is_listed_once_and_named_uniquely() {
    let mut names: Vec<&str> = ALL.iter().map(|boundary| boundary.name()).collect();
    let listed = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        listed,
        "two boundaries sharing a name would let a crash test select the wrong one"
    );
    // The environment selector and the flushed marker both carry these names,
    // so an empty or whitespace one would silently select nothing.
    assert!(names.iter().all(|name| !name.trim().is_empty()));
}
