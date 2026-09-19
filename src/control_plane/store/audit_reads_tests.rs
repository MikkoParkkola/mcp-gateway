//! MIK-6710 — bounded, cursor-paged audit reads.
//!
//! These tests pin the *cost* contract, not just the values: a page must cost
//! what the page costs, never what the log costs, and a scan that runs out of
//! budget must say so instead of silently truncating.

use super::*;
use crate::control_plane::ControlPlaneAction;
use crate::security::TransparencyLogConfig;
use std::path::Path;

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// One NDJSON audit line, padded to a controllable size.
///
/// `pad` is the number of filler bytes in `reason`, so a caller can build a log
/// of a known byte size without caring about the surrounding envelope.
fn line(event_id: &str, actor: &str, pad: usize) -> String {
    let entry = serde_json::json!({
        "kind": AUDIT_KIND,
        "event_id": event_id,
        "actor_id": actor,
        "action": "mutate_grant",
        "target_id": "target-1",
        "reason": "x".repeat(pad),
        "rollback_summary": "revert",
        "rollback_step": "helm rollback",
        "entry_hash": format!("sha256:{event_id}"),
    });
    serde_json::to_string(&entry).expect("encode fixture line")
}

/// Write `lines` as an NDJSON log, oldest first (append order).
fn write_lines(path: &Path, lines: &[String]) {
    let mut buf = String::new();
    for l in lines {
        buf.push_str(l);
        buf.push('\n');
    }
    std::fs::write(path, buf).expect("write fixture log");
}

/// Open a store over `dir` with injected read bounds.
///
/// The logger is opened FIRST, on a path that must not exist yet, and the
/// synthetic fixture is written afterwards — opening over an existing log is a
/// different code path and would rewrite the fixture's chain.
fn store_with(dir: &Path, scan: u64, max_record: u64) -> FileControlPlaneStore {
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir.join("audit.jsonl").to_string_lossy().to_string(),
        key_id: "gov".to_string(),
        shared_secret: "governance-secret-at-least-32-bytes-long!".to_string(),
    });
    let logger = Arc::new(TransparencyLogger::open(cfg).expect("open governance log"));
    FileControlPlaneStore::with_read_bounds(dir.join("store"), logger, scan, max_record)
        .expect("open store")
}

/// Naive parse-the-whole-log oracle: every audit line, newest first, filtered by
/// the same predicates but with NO limit and NO budget. The paged reader must
/// agree with this, in order, for whatever prefix it returns.
fn full_scan_oracle(path: &Path, filter: &AuditFilter) -> Vec<ControlPlaneAuditEvent> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut events: Vec<ControlPlaneAuditEvent> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
        .filter_map(|v| audit_event_from_entry(&v))
        .filter(|e| filter.matches(e))
        .collect();
    events.reverse();
    events
}

/// Build a log whose newest `head` events are small and distinctive, preceded by
/// filler padded out to at least `filler_bytes`. Returns the byte size of the
/// head region (including newlines).
fn fixture_with_head(path: &Path, head: usize, filler_bytes: u64) -> u64 {
    let mut lines = Vec::new();
    let mut written: u64 = 0;
    let mut i = 0usize;
    while written < filler_bytes {
        let l = line(&format!("filler-{i}"), "carol", 1000);
        written += l.len() as u64 + 1;
        lines.push(l);
        i += 1;
    }
    let mut head_bytes = 0u64;
    for h in 0..head {
        let l = line(&format!("head-{h}"), "alice", 100);
        head_bytes += l.len() as u64 + 1;
        lines.push(l);
    }
    write_lines(path, &lines);
    head_bytes
}

// ── 1. Page cost tracks the page, not the log ─────────────────────────────────

// MIK-6710.READ.1 — the same page read from a 2 MiB log and an 8 MiB log must
// cost the same bytes. This is the whole point of the ticket: cost is a function
// of the page, not of history.
#[test]
fn page_cost_is_proportional_to_page_not_log() {
    // GIVEN: two logs sharing the same newest 50 events, one 4x longer.
    let small = tempfile::tempdir().unwrap();
    let large = tempfile::tempdir().unwrap();
    let head_small = fixture_with_head(&small.path().join("audit.jsonl"), 50, 2 * 1024 * 1024);
    let head_large = fixture_with_head(&large.path().join("audit.jsonl"), 50, 8 * 1024 * 1024);
    assert_eq!(head_small, head_large, "fixture heads must be identical");

    // WHEN: both are read with the same 50-event limit.
    let filter = AuditFilter::new(50);
    let a = store_with(small.path(), 1024 * 1024, 64 * 1024)
        .read_audit(&filter)
        .unwrap();
    let b = store_with(large.path(), 1024 * 1024, 64 * 1024)
        .read_audit(&filter)
        .unwrap();

    // THEN: identical full pages, identical cost, bounded by the page size.
    assert_eq!(a.events.len(), 50);
    assert_eq!(b.events.len(), 50);
    assert!(matches!(a.end, AuditPageEnd::LimitReached(_)));
    assert!(matches!(b.end, AuditPageEnd::LimitReached(_)));
    let cost_a = a.stats.bytes_examined.expect("file backend reports bytes");
    let cost_b = b.stats.bytes_examined.expect("file backend reports bytes");
    assert_eq!(cost_a, cost_b, "page cost must not depend on log length");
    assert!(
        cost_a <= 64 * 1024 + head_small,
        "page cost {cost_a} exceeds one block plus the page itself ({head_small})"
    );
}

// ── 2/3. A scan that cannot finish stays inside its budget and says so ────────

/// A 2 MiB log whose only `alice` event is at the OLDEST end, so any filter for
/// her must traverse the entire log to find it.
fn rare_match_fixture(dir: &Path) -> u64 {
    let path = dir.join("audit.jsonl");
    let mut lines = vec![line("needle", "alice", 100)];
    let mut written: u64 = lines[0].len() as u64 + 1;
    let mut i = 0usize;
    while written < 2 * 1024 * 1024 {
        let l = line(&format!("filler-{i}"), "carol", 1000);
        written += l.len() as u64 + 1;
        lines.push(l);
        i += 1;
    }
    write_lines(&path, &lines);
    written
}

// MIK-6710.READ.2 — a filter that matches only at the far end must stop at the
// budget, not walk the log.
#[test]
fn rare_filter_stays_within_budget() {
    // GIVEN: a 2 MiB log, a 64 KiB scan budget, one match at the oldest end.
    let dir = tempfile::tempdir().unwrap();
    rare_match_fixture(dir.path());
    let store = store_with(dir.path(), 64 * 1024, 16 * 1024);
    let mut filter = AuditFilter::new(10);
    filter.actor_id = Some("alice".to_string());

    // WHEN: the page is read.
    let page = store.read_audit(&filter).unwrap();

    // THEN: it gave up inside the budget rather than finding the needle.
    assert!(
        page.stats.bytes_examined.unwrap() <= 64 * 1024,
        "scan overshot its budget: {:?}",
        page.stats.bytes_examined
    );
    assert!(
        matches!(page.end, AuditPageEnd::BudgetExhausted(_)),
        "expected BudgetExhausted, got {:?}",
        page.end
    );
}

// MIK-6710.READ.3 — a filter matching nothing must be bounded AND must report
// that it stopped early, so an empty page is never mistaken for "no events".
#[test]
fn no_match_filter_stays_bounded_and_says_so() {
    // GIVEN: the same 2 MiB log and budget, a filter matching nobody.
    let dir = tempfile::tempdir().unwrap();
    rare_match_fixture(dir.path());
    let store = store_with(dir.path(), 64 * 1024, 16 * 1024);
    let mut filter = AuditFilter::new(10);
    filter.actor_id = Some("nobody".to_string());

    // WHEN: the page is read.
    let page = store.read_audit(&filter).unwrap();

    // THEN: empty, bounded, and explicitly incomplete.
    assert!(page.events.is_empty());
    assert!(page.stats.bytes_examined.unwrap() <= 64 * 1024);
    assert!(
        matches!(page.end, AuditPageEnd::BudgetExhausted(_)),
        "an empty page must not claim Complete: {:?}",
        page.end
    );
}

// ── 4. A cursor walk equals a full scan ───────────────────────────────────────

/// Walk every page to completion, returning the concatenated events and the
/// per-page byte costs. Panics rather than looping forever if the walk fails to
/// make progress.
fn walk(store: &FileControlPlaneStore, base: &AuditFilter) -> (Vec<ControlPlaneAuditEvent>, Vec<u64>) {
    let mut events = Vec::new();
    let mut costs = Vec::new();
    let mut cursor = None;
    for _ in 0..1000 {
        let filter = AuditFilter {
            cursor,
            ..base.clone()
        };
        let page = store.read_audit(&filter).unwrap();
        costs.push(page.stats.bytes_examined.unwrap_or(0));
        events.extend(page.events);
        match page.end {
            AuditPageEnd::Complete => return (events, costs),
            AuditPageEnd::LimitReached(c) | AuditPageEnd::BudgetExhausted(c) => cursor = Some(c),
        }
    }
    panic!("cursor walk did not terminate in 1000 pages");
}

fn ids(events: &[ControlPlaneAuditEvent]) -> Vec<String> {
    events.iter().map(|e| e.event_id.clone()).collect()
}

// MIK-6710.READ.4a — walking by limit reproduces the full scan exactly, in order.
#[test]
fn cursor_walk_on_limit_matches_oracle() {
    // GIVEN: a log of 200 events and a 7-per-page limit.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = store_with(dir.path(), 1024 * 1024, 64 * 1024);
    let lines: Vec<String> = (0..200)
        .map(|i| line(&format!("e{i}"), if i % 3 == 0 { "alice" } else { "bob" }, 50))
        .collect();
    write_lines(&path, &lines);
    let base = AuditFilter::new(7);

    // WHEN: the walk runs to completion.
    let (events, _) = walk(&store, &base);

    // THEN: same events, same newest-first order, as a naive full scan.
    assert_eq!(ids(&events), ids(&full_scan_oracle(&path, &base)));
}

// MIK-6710.READ.4b — a walk forced across budget boundaries still reproduces the
// full scan, and EVERY page (including the anchor revalidation that resumes it)
// stays inside the budget.
#[test]
fn cursor_walk_on_budget_boundaries_matches_oracle() {
    // GIVEN: a log far larger than a deliberately tiny scan budget.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = store_with(dir.path(), 32 * 1024, 8 * 1024);
    let lines: Vec<String> = (0..400)
        .map(|i| line(&format!("e{i}"), if i % 5 == 0 { "alice" } else { "bob" }, 200))
        .collect();
    write_lines(&path, &lines);
    let mut base = AuditFilter::new(10_000);
    base.actor_id = Some("alice".to_string());

    // WHEN: the walk runs to completion across many budget stops.
    let (events, costs) = walk(&store, &base);

    // THEN: identical to the oracle, and no page exceeded the budget — proving
    // the resume's anchor validation is charged, not free.
    assert_eq!(ids(&events), ids(&full_scan_oracle(&path, &base)));
    assert!(costs.len() > 1, "fixture failed to force a budget stop");
    for (i, c) in costs.iter().enumerate() {
        assert!(*c <= 32 * 1024, "page {i} cost {c} exceeds the budget");
    }
}

// MIK-6710.READ.4c — an append landing mid-walk must not appear in that walk.
// A walk is a consistent view of the log as of its first page.
#[test]
fn cursor_walk_isolates_concurrent_append() {
    // GIVEN: a 30-event log, a 4-per-page walk, and a snapshot oracle.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = store_with(dir.path(), 1024 * 1024, 64 * 1024);
    let mut lines: Vec<String> = (0..30).map(|i| line(&format!("e{i}"), "alice", 50)).collect();
    write_lines(&path, &lines);
    let base = AuditFilter::new(4);
    let before = full_scan_oracle(&path, &base);

    // WHEN: a new event is appended after the first page is taken.
    let first = store.read_audit(&base).unwrap();
    let mut cursor = first.end.cursor().cloned();
    lines.push(line("appended", "alice", 50));
    write_lines(&path, &lines);
    let mut events = first.events;
    while let Some(c) = cursor.take() {
        let page = store
            .read_audit(&AuditFilter {
                cursor: Some(c),
                ..base.clone()
            })
            .unwrap();
        events.extend(page.events);
        cursor = page.end.cursor().cloned();
    }

    // THEN: the walk matches the snapshot taken before the append …
    assert_eq!(ids(&events), ids(&before));
    assert!(!ids(&events).contains(&"appended".to_string()));
    // … and a fresh scan does see it, as the newest event.
    let after = full_scan_oracle(&path, &base);
    assert_eq!(after.first().map(|e| e.event_id.as_str()), Some("appended"));
}

// ── 5/7. Both backends agree on order and on reporting work done ──────────────

// MIK-6710.READ.5 — newest-first ordering is a contract of the trait, not of one
// backend.
#[test]
fn both_backends_return_newest_first() {
    // GIVEN: the same five events appended to each backend.
    let dir = tempfile::tempdir().unwrap();
    let mem = InMemoryControlPlaneStore::new();
    let file = store_with(dir.path(), 1024 * 1024, 64 * 1024);
    for i in 0..5 {
        let e = ControlPlaneAuditEvent {
            event_id: format!("e{i}"),
            actor_id: "alice".to_string(),
            action: ControlPlaneAction::MutateGrant,
            target_id: "t".to_string(),
            reason: "r".to_string(),
            rollback: ControlPlaneRollbackPlan {
                summary: "s".to_string(),
                step: "p".to_string(),
            },
        };
        mem.append_audit(&e).unwrap();
        file.append_audit(&e).unwrap();
    }
    let filter = AuditFilter::new(10);

    // WHEN/THEN: both return the newest event first, in the same order.
    let expected = ["e4", "e3", "e2", "e1", "e0"];
    assert_eq!(ids(&mem.read_audit(&filter).unwrap().events), expected);
    assert_eq!(ids(&file.read_audit(&filter).unwrap().events), expected);
}

// MIK-6710.READ.4d — a resume anchor must round-trip through the REAL writer.
// Every other cursor test builds its own line, so all of them would still pass
// if the anchor field the reader re-checks were not the field the logger emits.
#[test]
fn cursor_walk_over_real_appends_matches_unpaged_read() {
    // GIVEN: five events written by the production append path.
    let dir = tempfile::tempdir().unwrap();
    let store = store_with(dir.path(), 1024 * 1024, 64 * 1024);
    for i in 0..5 {
        store
            .append_audit(&ControlPlaneAuditEvent {
                event_id: format!("e{i}"),
                actor_id: "alice".to_string(),
                action: ControlPlaneAction::MutateGrant,
                target_id: "t".to_string(),
                reason: "r".to_string(),
                rollback: ControlPlaneRollbackPlan {
                    summary: "s".to_string(),
                    step: "p".to_string(),
                },
            })
            .unwrap();
    }
    let unpaged = ids(&store.read_audit(&AuditFilter::new(10)).unwrap().events);

    // WHEN: the same log is walked two events at a time.
    let (paged, _) = walk(&store, &AuditFilter::new(2));

    // THEN: the walk reproduces the single-page read exactly.
    assert_eq!(paged.len(), 5, "every appended event is reachable by cursor");
    assert_eq!(ids(&paged), unpaged);
}

// MIK-6710.READ.7 — an empty page must still report the work it did, so a caller
// can tell "nothing matched" from "nothing was looked at".
#[test]
fn records_examined_nonzero_on_no_match_both_backends() {
    // GIVEN: both backends holding events that the filter excludes.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mem = InMemoryControlPlaneStore::new();
    let file = store_with(dir.path(), 1024 * 1024, 64 * 1024);
    write_lines(
        &path,
        &(0..5)
            .map(|i| line(&format!("e{i}"), "bob", 50))
            .collect::<Vec<_>>(),
    );
    for i in 0..5 {
        mem.append_audit(&ControlPlaneAuditEvent {
            event_id: format!("e{i}"),
            actor_id: "bob".to_string(),
            action: ControlPlaneAction::MutateGrant,
            target_id: "t".to_string(),
            reason: "r".to_string(),
            rollback: ControlPlaneRollbackPlan {
                summary: "s".to_string(),
                step: "p".to_string(),
            },
        })
        .unwrap();
    }
    let mut filter = AuditFilter::new(10);
    filter.actor_id = Some("alice".to_string());

    // WHEN/THEN: empty pages, but both admit they examined records.
    for page in [mem.read_audit(&filter).unwrap(), file.read_audit(&filter).unwrap()] {
        assert!(page.events.is_empty());
        assert_eq!(page.stats.records_examined, 5);
    }
}

// ── 6. A cursor into a log that moved is stale, never silently wrong ──────────

/// Build a 40-event log and take one 5-event page, returning the store, the log
/// path, the resume cursor, and the byte offset it anchors on.
fn paged_once(dir: &Path) -> (FileControlPlaneStore, PathBuf, AuditCursor, u64) {
    let path = dir.join("audit.jsonl");
    let store = store_with(dir, 1024 * 1024, 64 * 1024);
    let lines: Vec<String> = (0..40).map(|i| line(&format!("e{i}"), "alice", 200)).collect();
    write_lines(&path, &lines);
    let page = store.read_audit(&AuditFilter::new(5)).unwrap();
    let cursor = page.end.cursor().cloned().expect("a partial page has a cursor");
    let next_end = match &cursor.0 {
        CursorKind::File { next_end, .. } => *next_end,
        CursorKind::Index(_) => panic!("file backend must issue a file cursor"),
    };
    (store, path, cursor, next_end)
}

/// Resume with `cursor` after `mutate` has damaged the log.
fn resume_after(dir: &Path, mutate: impl FnOnce(&Path, u64)) -> StoreResult<AuditPage> {
    let (store, path, cursor, next_end) = paged_once(dir);
    mutate(&path, next_end);
    store.read_audit(&AuditFilter {
        cursor: Some(cursor),
        ..AuditFilter::new(5)
    })
}

// MIK-6710.READ.6a — the log was truncated past the cursor.
#[test]
fn stale_cursor_when_log_truncated_below_offset() {
    let dir = tempfile::tempdir().unwrap();
    let r = resume_after(dir.path(), |path, next_end| {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_len(next_end / 2).unwrap();
    });
    assert!(matches!(r, Err(StoreError::StaleCursor)), "got {r:?}");
}

// MIK-6710.READ.6b — the log was rotated: same shape, different content.
#[test]
fn stale_cursor_when_log_rotated() {
    let dir = tempfile::tempdir().unwrap();
    let r = resume_after(dir.path(), |path, _| {
        let lines: Vec<String> = (0..40).map(|i| line(&format!("r{i}"), "alice", 200)).collect();
        write_lines(path, &lines);
    });
    assert!(matches!(r, Err(StoreError::StaleCursor)), "got {r:?}");
}

// MIK-6710.READ.6c — the log was emptied. This must NOT read as a clean
// "Complete with zero events": the remaining pages are gone, not absent.
#[test]
fn stale_cursor_when_log_emptied() {
    let dir = tempfile::tempdir().unwrap();
    let r = resume_after(dir.path(), |path, _| std::fs::write(path, "").unwrap());
    assert!(matches!(r, Err(StoreError::StaleCursor)), "got {r:?}");
}

// MIK-6710.READ.6d — the cut lands inside the anchored record. The anchor no
// longer reconstructs, which is staleness, not an oversized record.
#[test]
fn stale_cursor_when_truncation_splits_anchor_record() {
    let dir = tempfile::tempdir().unwrap();
    let r = resume_after(dir.path(), |path, next_end| {
        let len = std::fs::metadata(path).unwrap().len();
        let cut = next_end + (len - next_end).min(120) / 2;
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_len(cut.max(next_end + 1)).unwrap();
    });
    assert!(matches!(r, Err(StoreError::StaleCursor)), "got {r:?}");
}

// ── 8. Bounds that cannot be satisfied are errors, not silent stalls ──────────

// MIK-6710.READ.8a — a record too large to read within `max_record` must error.
// Returning a budget-exhausted page here would let the same page be requested
// forever without progress.
#[test]
fn oversized_record_errors_instead_of_stalling() {
    // GIVEN: a 20 KiB record at the newest end, a 16 KiB per-record cap.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = store_with(dir.path(), 64 * 1024, 16 * 1024);
    write_lines(
        &path,
        &[line("small", "alice", 50), line("huge", "alice", 20 * 1024)],
    );

    // WHEN/THEN: reading errors rather than producing an unprogressable page.
    let r = store.read_audit(&AuditFilter::new(5));
    assert!(
        matches!(r, Err(StoreError::OversizedRecord { .. })),
        "got {r:?}"
    );
}

// MIK-6710.READ.8b — every page boundary moves strictly toward the start of the
// log, so a walk cannot revisit a region.
#[test]
fn cursor_walk_boundaries_strictly_decrease() {
    // GIVEN: a log walked in small pages.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = store_with(dir.path(), 1024 * 1024, 64 * 1024);
    let lines: Vec<String> = (0..60).map(|i| line(&format!("e{i}"), "alice", 100)).collect();
    write_lines(&path, &lines);

    // WHEN: each page's boundary offset is recorded.
    let mut offsets = Vec::new();
    let mut cursor = None;
    loop {
        let page = store
            .read_audit(&AuditFilter {
                cursor,
                ..AuditFilter::new(6)
            })
            .unwrap();
        match page.end {
            AuditPageEnd::Complete => break,
            AuditPageEnd::LimitReached(c) | AuditPageEnd::BudgetExhausted(c) => {
                match &c.0 {
                    CursorKind::File { next_end, .. } => offsets.push(*next_end),
                    CursorKind::Index(_) => panic!("file backend must issue a file cursor"),
                }
                cursor = Some(c);
            }
        }
    }

    // THEN: the boundaries strictly decrease.
    assert!(offsets.len() > 2, "fixture failed to produce several pages");
    assert!(
        offsets.windows(2).all(|w| w[1] < w[0]),
        "boundaries did not strictly decrease: {offsets:?}"
    );
}

// MIK-6710.READ.8c — bounds that cannot page (a record cap the scan budget
// cannot fit twice) are a programming error, caught at construction.
#[test]
#[should_panic(expected = "scan budget")]
fn with_read_bounds_panics_when_unpaginable() {
    let dir = tempfile::tempdir().unwrap();
    let _ = store_with(dir.path(), 16 * 1024, 16 * 1024);
}

// ── 10. Fail closed: a damaged audit line is never silently dropped ───────────

// MIK-6710.READ.10a — a line that is not JSON at all.
#[test]
fn corrupt_json_line_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = store_with(dir.path(), 1024 * 1024, 64 * 1024);
    write_lines(
        &path,
        &[line("e0", "alice", 50), "{not json".to_string(), line("e2", "alice", 50)],
    );
    assert!(
        matches!(store.read_audit(&AuditFilter::new(10)), Err(StoreError::Corrupt(_))),
        "a corrupt line must not be skipped"
    );
}

// MIK-6710.READ.10b — a line tagged as ours that cannot be reconstructed.
#[test]
fn unreconstructable_audit_line_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = store_with(dir.path(), 1024 * 1024, 64 * 1024);
    let broken = serde_json::json!({ "kind": AUDIT_KIND, "event_id": "e1" }).to_string();
    write_lines(&path, &[line("e0", "alice", 50), broken]);
    assert!(
        matches!(store.read_audit(&AuditFilter::new(10)), Err(StoreError::Corrupt(_))),
        "a malformed audit entry must not vanish from the view"
    );
}

// MIK-6710.READ.10c — the load-bearing one: the damaged line would have been
// filtered out anyway. An implementation that tests the filter before parsing
// hides the damage; this must still fail closed.
#[test]
fn unreconstructable_line_fails_closed_even_when_filtered_out() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = store_with(dir.path(), 1024 * 1024, 64 * 1024);
    let broken =
        serde_json::json!({ "kind": AUDIT_KIND, "event_id": "e1", "actor_id": "bob" }).to_string();
    write_lines(&path, &[line("e0", "alice", 50), broken]);
    let mut filter = AuditFilter::new(10);
    filter.actor_id = Some("alice".to_string());
    assert!(
        matches!(store.read_audit(&filter), Err(StoreError::Corrupt(_))),
        "damage must be detected before the filter excludes the line"
    );
}
