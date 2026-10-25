// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-8774 STREAM.3: the peak memory redaction adds for a JSON text over the
//! 1 MiB cap, measured by a counting global allocator rather than claimed. The
//! streaming walk keeps about one output's worth; the walk on collected
//! literals, taken where a key is renamed, at most about 11x the leaf (a
//! document of tiny strings, lead ruling 2026-10-25). One test in this binary,
//! so no other test's allocations land in the counters.
#![cfg(feature = "firewall")]
// The counting allocator forwards to `System`; implementing `GlobalAlloc` is
// unsafe by definition, as in src/gateway/server/tests/alloc_meter.rs.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use mcp_gateway::security::firewall::redactor::Redactor;
use serde_json::json;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// Bytes allocated at the peak of redacting `text` as a tool answer's text,
/// above what was live when the call began (the answer itself is built first),
/// and the length of the redacted text that peak includes.
fn peak_of(redactor: &Redactor, text: &str) -> (usize, usize) {
    let mut answer = json!({ "content": [{ "type": "text", "text": text }] });
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let findings = redactor.scan_and_redact(&mut answer);
    let peak = PEAK.load(Ordering::Relaxed) - before;
    assert!(!findings.is_empty(), "the leaf held a credential");
    let out = answer["content"][0]["text"].as_str().map_or(0, str::len);
    (peak, out)
}

/// The peak minus the output it allocates, as a multiple of the input: the
/// working memory, apart from the redacted text that is the result.
fn report(label: &str, len: usize, (peak, out): (usize, usize)) -> usize {
    let work = peak.saturating_sub(out);
    println!(
        "{label}: {len} bytes in, {out} out, peak {peak}, working {work} ({}.{:02}x)",
        work / len,
        work * 100 / len % 100
    );
    work
}

#[test]
fn redaction_over_the_cap_stays_within_its_stated_memory() {
    let redactor = Redactor::new();
    let dsn = serde_json::to_string(&format!("{}://u:pw@{}", "postgres", "db.local:5432/app"))
        .expect("encodes");
    let slack = 64 * 1024;
    // The control: allocating and holding a known amount reads as that much.
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let held = vec![0_u8; 1 << 20];
    assert!(PEAK.load(Ordering::Relaxed) - before >= held.len());
    drop(held);
    assert!(
        LIVE.load(Ordering::Relaxed) <= before + slack,
        "a free lowers live bytes"
    );

    // Streaming: a page of rows, the connection string in one value.
    let rows = vec![r#"{"name":"o/r","note":"short words here"}"#; 60_000].join(",");
    let page = format!(r#"{{"items":[{{"homepage":{dsn}}},{rows}],"total_count":3}}"#);
    let len = page.len();
    assert!(len > 2 << 20);
    let work = report("streaming", len, peak_of(&redactor, &page));
    assert!(
        work <= len + slack,
        "streaming working memory {work} over 1x {len}"
    );

    // A key a match starts in, its greedy span over every tiny value after it:
    // one projected range per value on top of the literal list.
    let values = vec![r#""a""#; 600_000].join(",");
    let doc = format!("{{{dsn}:[{values}]}}");
    let len = doc.len();
    let work = report("key then values", len, peak_of(&redactor, &doc));
    assert!(
        work <= 9 * len + slack,
        "key-then-values working memory {work} over 9x {len}"
    );

    // The collected walk's worst case: tiny strings, and a key to rename.
    let tiny = vec![r#""a""#; 600_000].join(",");
    let doc = format!("[{tiny},{{{dsn}:1,\"n\":3}}]");
    let len = doc.len();
    assert!(len > 2 << 20);
    let work = report("collected", len, peak_of(&redactor, &doc));
    assert!(
        work <= 9 * len + slack,
        "collected working memory {work} over 9x {len}"
    );
}
