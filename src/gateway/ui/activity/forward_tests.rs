// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stream's forward read of one log: order, keep, budget, the cursor's
//! search and its resume.

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::super::reader::Limits;
use super::{ForwardPage, Log, MAX_RESTARTS, Mark, Search, StreamKind, rows_after};
use crate::gateway::ui::activity::access::Access;
use crate::security::transparency_log::recompute_entry_hash;
use crate::security::transparency_log::segments::sealed_path;

#[path = "forward_resume_tests.rs"]
mod resume;
#[path = "forward_rows_tests.rs"]
mod rows;

thread_local! {
    /// Run once, after a resume has decided the segment's identity and before
    /// its first byte is read.
    static AFTER_IDENTITY: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    /// How many identity reads fail, once `IDENTITY_SKIP` reads have passed.
    static IDENTITY_FAILS: Cell<u32> = const { Cell::new(0) };
    /// How many identity reads pass before `IDENTITY_FAILS` starts failing:
    /// 0 fails the next one, 1 the one after it.
    static IDENTITY_SKIP: Cell<u32> = const { Cell::new(0) };
    /// Every segment whose identity was read, by sequence, in order.
    static OPENED: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

/// The resume's seam between deciding the identity and the first read.
pub(super) fn after_identity() {
    if let Some(hook) = AFTER_IDENTITY.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// Whether the identity read of segment `seq` should fail: the reads to let
/// pass are used up first, then each failure uses one up.
pub(super) fn identity_fails(seq: u64) -> bool {
    OPENED.with(|o| o.borrow_mut().push(seq));
    if IDENTITY_SKIP.with(|s| {
        let left = s.get();
        s.set(left.saturating_sub(1));
        left > 0
    }) {
        return false;
    }
    IDENTITY_FAILS.with(|f| {
        let left = f.get();
        f.set(left.saturating_sub(1));
        left > 0
    })
}

fn set_after_identity(hook: impl FnOnce() + 'static) {
    AFTER_IDENTITY.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
}

const X: &str = "https://issuer-x";

/// One line of a fixture log.
#[derive(Clone)]
enum Rec {
    /// A call, by the verified `(issuer, subject)` when there is one.
    Call(Option<(&'static str, &'static str)>),
    /// A call padded to about this many bytes.
    Big(usize),
    Admin,
    Config,
    /// A record Activity does not list (a grant decision).
    Grant,
    /// Bytes that are not a record, then a newline.
    Junk(usize),
    /// This many junk lines of this length each.
    Junks(usize, usize),
    /// A whole call record, then on the same line this byte repeated past
    /// the record cap: a line that starts with a valid record.
    Padded(u8),
    /// As `Padded`, the line one byte longer than the record cap.
    JustOver(u8),
}

/// What a fixture wrote: each record's place and offsets, in counter order.
struct Written {
    marks: Vec<Mark>,
    /// `(segment file, start, end after newline)` per record.
    at: Vec<(PathBuf, u64, u64)>,
}

fn mark_of(entry: &Value) -> Mark {
    Mark {
        counter: entry["counter"].as_u64().unwrap(),
        hash16: entry["entry_hash"].as_str().unwrap()["sha256:".len()..][..16].to_owned(),
    }
}

fn body(rec: &Rec, counter: u64) -> Option<Value> {
    let mut e = match rec {
        Rec::Call(_) | Rec::Big(_) | Rec::Padded(_) | Rec::JustOver(_) => {
            let mut w = json!({"account": "a"});
            if let Rec::Call(Some((issuer, subject))) = rec {
                w["authority"] = (*issuer).into();
                w["subject"] = (*subject).into();
            }
            json!({"outcome": "ok", "server": "srv", "tool": format!("tool_{counter}"),
                   "route": "meta_invoke", "request_hash": "sha256:aa", "who": w})
        }
        Rec::Admin => json!({"event": "admin_action", "surface": "ui", "route": "/x"}),
        Rec::Config => json!({"kind": "control_plane_audit", "action": "set", "actor_id": "a"}),
        Rec::Grant => json!({"event": "grant_decision"}),
        _ => return None,
    };
    if let Rec::Big(n) = rec {
        e["pad"] = "p".repeat(*n).into();
    }
    e["timestamp"] = "2026-11-02T10:00:00+00:00".into();
    Some(e)
}

/// Write `segments` as one log at `path`: every one but the last sealed,
/// numbered from `first_seq`; the last is the active file. Counters start at
/// `first_counter` and chain from `prev`.
fn write_from(path: &Path, segments: &[Vec<Rec>], first_seq: u64, first_counter: u64) -> Written {
    let mut prev = "genesis".to_owned();
    let mut counter = first_counter;
    let mut out = Written {
        marks: Vec::new(),
        at: Vec::new(),
    };
    for (i, seg) in segments.iter().enumerate() {
        let file = if i + 1 == segments.len() {
            path.to_path_buf()
        } else {
            sealed_path(path, first_seq + i as u64)
        };
        let mut bytes = Vec::new();
        for rec in seg {
            match rec {
                Rec::Junks(count, n) => {
                    for _ in 0..*count {
                        bytes.extend(std::iter::repeat_n(b'x', *n));
                        bytes.push(b'\n');
                    }
                }
                Rec::Junk(n) => {
                    bytes.extend(std::iter::repeat_n(b'x', *n));
                    bytes.push(b'\n');
                }
                rec => {
                    let mut e = body(rec, counter).unwrap();
                    e["counter"] = counter.into();
                    e["prev_entry_hash"] = prev.clone().into();
                    let hash = recompute_entry_hash(&e).unwrap();
                    e["entry_hash"] = hash.clone().into();
                    prev = hash;
                    let start = bytes.len() as u64;
                    bytes.extend(e.to_string().as_bytes());
                    let window = crate::security::transparency_log::pager::ASSEMBLY_WINDOW;
                    let window = usize::try_from(window).expect("the cap fits in memory");
                    match rec {
                        Rec::Padded(pad) => bytes.extend(std::iter::repeat_n(*pad, window)),
                        // The cap is the window less one, its newline included:
                        // pad the line to the window, one byte past the cap.
                        Rec::JustOver(pad) => {
                            let line = bytes.len() - usize::try_from(start).expect("in memory");
                            bytes.extend(std::iter::repeat_n(*pad, window - line - 1));
                        }
                        _ => {}
                    }
                    bytes.push(b'\n');
                    out.marks.push(mark_of(&e));
                    out.at.push((file.clone(), start, bytes.len() as u64));
                    counter += 1;
                }
            }
        }
        std::fs::write(&file, bytes).unwrap();
    }
    out
}

fn write(path: &Path, segments: &[Vec<Rec>]) -> Written {
    write_from(path, segments, 1, 1)
}

fn calls(n: usize) -> Vec<Rec> {
    vec![Rec::Call(Some((X, "s"))); n]
}

fn log(path: &Path, kind: StreamKind) -> Log<'_> {
    Log {
        path,
        kind,
        generation: 0,
        secret: None,
    }
}

const WIDE: Limits = Limits {
    matches: 200,
    bytes: 8 << 20,
};

/// Call until the page no longer says `more`; every page, in order.
fn drain(
    log: &Log<'_>,
    cursor: Option<&Mark>,
    stop: Option<&Mark>,
    access: &Access,
    budget: Limits,
    search: &mut Search,
) -> Vec<ForwardPage> {
    let mut pages = Vec::new();
    let mut at = cursor.cloned();
    loop {
        let page = rows_after(log, at.as_ref(), stop, access, budget, search).unwrap();
        let more = page.more;
        at = page.next.clone().or(at);
        pages.push(page);
        if !more || pages.len() > 10_000 {
            return pages;
        }
    }
}

fn counters(pages: &[ForwardPage]) -> Vec<u64> {
    pages
        .iter()
        .flat_map(|p| p.rows.iter().map(|r| r.mark.counter))
        .collect()
}
