// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows W1-W10 for the recent-write sample: window edges, ring reuse, the
//! running total, the counting rules and a reference model.
use super::*;

use std::time::Duration;

fn at(base: Instant, ms: u64) -> Instant {
    base + Duration::from_millis(ms)
}

#[test]
fn w1_note_in_current_second_is_counted() {
    let base = Instant::now();
    let rw = RecentWrites::new(base);
    let t = at(base, 500);
    rw.note(t);
    let s = rw.sample(t);
    assert_eq!(s.count, 1, "a note in the current second counts");
    assert_eq!(s.writes_total, 1);
    assert_eq!(s.taken_at_mono, t);
}

#[test]
fn w2_window_edges_keep_sixty_drop_sixty_one() {
    let base = Instant::now();
    let rw = RecentWrites::new(base);
    let t = at(base, 5_000);
    rw.note(t);
    for later in [0, 59_000, 60_000] {
        let s = rw.sample(t + Duration::from_millis(later));
        assert_eq!(s.count, 1, "note at t is in the sample at t+{later}ms");
        assert_eq!(s.writes_total, 1);
    }
    let out = rw.sample(t + Duration::from_secs(61));
    assert_eq!(out.count, 0, "note at t is out of the sample at t+61s");
    assert_eq!(out.writes_total, 1, "writes_total keeps the aged-out note");
}

#[test]
fn w3_complete_secs_counts_whole_seconds_then_caps() {
    let base = Instant::now();
    let rw = RecentWrites::new(base);
    for (ms, want) in [
        (0, 0),
        (30_500, 30),
        (59_900, 59),
        (60_000, 60),
        (500_000, 60),
    ] {
        assert_eq!(
            rw.sample(at(base, ms)).complete_secs,
            want,
            "complete_secs at base+{ms}ms"
        );
    }
}

#[test]
fn w4_reused_ring_slot_resets_and_idle_reads_zero() {
    let base = Instant::now();
    let rw = RecentWrites::new(base);
    rw.note(at(base, 5_000));
    // 66 - 5 = 61: the same slot of a 61-bucket ring.
    rw.note(at(base, 66_000));
    let s = rw.sample(at(base, 66_000));
    assert_eq!(s.count, 1, "the stale slot resets, it does not add");
    assert_eq!(s.writes_total, 2);
    let idle = rw.sample(at(base, 700_000));
    assert_eq!(idle.count, 0, "ten idle minutes read zero");
    assert_eq!(idle.writes_total, 2);
}

#[test]
fn w5_writes_total_moves_by_one_and_samples_are_frozen_copies() {
    let base = Instant::now();
    let rw = RecentWrites::new(base);
    let mut prev = 0;
    let mut frozen = None;
    for i in 0..100u64 {
        // Varied, non-decreasing instants over about 134 seconds.
        let t = at(base, i * 1_337 + (i % 7) * 13);
        rw.note(t);
        let s = rw.sample(t);
        assert_eq!(s.writes_total, i + 1, "one note moves the total by one");
        assert!(s.writes_total >= prev, "writes_total never decreases");
        assert!(s.count >= 1, "the note just made is in its own sample");
        assert!(s.count <= s.writes_total);
        prev = s.writes_total;
        if i == 49 {
            frozen = Some(s);
        }
    }
    let frozen = frozen.expect("sample taken at the fiftieth note");
    let copy = frozen;
    assert_eq!(copy.writes_total, 50, "a taken sample keeps its old total");
    assert_eq!(copy, frozen);
    assert_eq!(rw.sample(at(base, 200_000)).writes_total, 100);
}

#[test]
fn w6_counts_as_write_only_read_only_is_free() {
    assert!(counts_as_write(Some(Effect::MayWrite)));
    assert!(counts_as_write(Some(Effect::Undeclared)));
    assert!(counts_as_write(None), "no declaration counts");
    assert!(!counts_as_write(Some(Effect::ReadOnly)));
}

// W7 (the MetaArm table) lives with the meta-arm hook, not here.

const ALL_EFFECTS: [Option<Effect>; 4] = [
    None,
    Some(Effect::ReadOnly),
    Some(Effect::MayWrite),
    Some(Effect::Undeclared),
];

#[test]
fn w8_direct_read_list_is_free_and_the_rest_count() {
    for method in [
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "prompts/list",
        "prompts/get",
    ] {
        for effect in ALL_EFFECTS {
            assert!(
                !direct_method_counts(method, effect),
                "{method} with {effect:?} is on the read list"
            );
        }
    }
    assert!(!direct_method_counts("tools/call", Some(Effect::ReadOnly)));
    assert!(direct_method_counts("tools/call", Some(Effect::MayWrite)));
    assert!(
        direct_method_counts("logging/setLevel", None),
        "an unlisted method counts"
    );
}

/// The reference rule: a note is in a sample when the sample's whole second
/// minus the note's whole second, both from `base`, is 0..=60.
fn model_count(base: Instant, notes: &[Instant], s: Instant) -> u64 {
    let s_sec = s.duration_since(base).as_secs();
    let n = notes
        .iter()
        .filter(|n| {
            let n_sec = n.duration_since(base).as_secs();
            s_sec.checked_sub(n_sec).is_some_and(|d| d <= 60)
        })
        .count();
    u64::try_from(n).expect("note count fits u64")
}

#[test]
fn w9_ring_agrees_with_the_reference_model() {
    const OFFSETS_MS: [u64; 5] = [0, 1, 499, 500, 999];
    const LATER_MS: [u64; 12] = [
        0, 1, 499, 500, 999, 1_000, 59_000, 59_999, 60_000, 60_999, 61_000, 120_500,
    ];
    let base = Instant::now();
    let rw = RecentWrites::new(base);
    let mut notes = Vec::new();
    for sec in 0..130u64 {
        // Three idle seconds in every thirteen; two notes in every other one.
        if sec % 13 >= 10 {
            continue;
        }
        for (i, off) in (0u64..).zip(OFFSETS_MS) {
            if (sec * 7 + i * 3) % 5 >= 2 {
                continue;
            }
            let n = at(base, sec * 1_000 + off);
            rw.note(n);
            notes.push(n);
            for later in LATER_MS {
                let s = n + Duration::from_millis(later);
                let got = rw.sample(s);
                assert_eq!(
                    got.count,
                    model_count(base, &notes, s),
                    "note at {sec}s+{off}ms, sample {later}ms later"
                );
                assert_eq!(
                    got.writes_total,
                    u64::try_from(notes.len()).expect("fits u64")
                );
            }
        }
    }
    assert!(notes.len() > 100, "the sweep made enough notes");
}

#[test]
fn w10_concurrent_notes_are_all_counted() {
    use std::sync::atomic::{AtomicBool, Ordering};

    for round in 0..20 {
        let base = Instant::now();
        let rw = RecentWrites::new(base);
        let t = at(base, 10_000);
        let start = std::sync::Barrier::new(5);
        let done = AtomicBool::new(false);
        let (rw_ref, start_ref, done_ref) = (&rw, &start, &done);
        std::thread::scope(|scope| {
            let noters: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(move || {
                        start_ref.wait();
                        for _ in 0..1_000 {
                            rw_ref.note(t);
                        }
                    })
                })
                .collect();
            let sampler = scope.spawn(move || {
                start_ref.wait();
                let mut prev_total = 0;
                while !done_ref.load(Ordering::Acquire) {
                    let s = rw_ref.sample(t);
                    assert!(s.count <= s.writes_total, "round {round}: {s:?}");
                    assert!(
                        s.writes_total >= prev_total,
                        "round {round}: writes_total went back"
                    );
                    prev_total = s.writes_total;
                }
            });
            for noter in noters {
                noter.join().expect("noter thread panicked");
            }
            done_ref.store(true, Ordering::Release);
            sampler.join().expect("sampler thread panicked");
        });
        let s = rw.sample(t);
        assert_eq!(s.count, 4_000, "round {round}: no lost note");
        assert_eq!(s.writes_total, 4_000, "round {round}");
    }
}

/// The hook sites: file, and how many notes it holds.
const HOOK_SITES: [(&str, usize); 3] = [
    ("src/gateway/meta_mcp/invoke/send.rs", 1),
    (
        "src/gateway/router/backend_handlers/direct_dispatch/forward.rs",
        2,
    ),
    ("src/gateway/meta_mcp/call_dispatch.rs", 1),
];

fn source(path: &str) -> String {
    let full = format!("{}/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{full}: {e}"))
}

/// F2: the counter and every hook site build in every feature set. The
/// counter file has no feature cfg; each hook site sits in a function whose
/// attributes and body above the site carry none either.
#[test]
fn f2_counter_and_hook_sites_carry_no_feature_cfg() {
    // Any feature form: cfg(feature, cfg_attr(feature and cfg!(feature
    // all read `feature =`. Gating through an enclosing impl or module is
    // F1's to catch: its no-default-features run executes R1, R5 and R6.
    let gated = |line: &str| line.contains("feature =");
    let counter = source("src/gateway/recent_writes.rs");
    assert!(
        !counter.lines().any(gated),
        "recent_writes.rs is feature-gated"
    );
    let parent = source("src/gateway/mod.rs");
    let lines: Vec<&str> = parent.lines().collect();
    let decl = lines
        .iter()
        .position(|l| l.trim() == "mod recent_writes;")
        .expect("gateway/mod.rs declares recent_writes");
    assert!(
        !gated(lines[decl.saturating_sub(1)]),
        "the recent_writes module declaration is feature-gated"
    );
    for (path, want) in HOOK_SITES {
        let text = source(path);
        let lines: Vec<&str> = text.lines().collect();
        let sites: Vec<usize> = (0..lines.len())
            .filter(|&i| lines[i].contains("recent_writes") && lines[i].contains(".note("))
            .collect();
        assert_eq!(sites.len(), want, "{path}: hook sites {sites:?}");
        for site in sites {
            let is_fn = |l: &str| {
                let l = l.trim_start();
                l.starts_with("fn ") || l.starts_with("async fn ") || l.contains(" fn ")
            };
            let start = (0..=site)
                .rev()
                .find(|&i| is_fn(lines[i]))
                .unwrap_or_else(|| panic!("{path}:{}: no enclosing fn", site + 1));
            let attrs = (0..start)
                .rev()
                // Attributes and doc lines, multi-line ones too: up to the
                // blank line or the end of the previous item.
                .take_while(|&i| {
                    let l = lines[i].trim();
                    !l.is_empty() && !l.ends_with(['}', ';', '{'])
                })
                .last()
                .unwrap_or(start);
            let gated = (attrs..=site).find(|&i| gated(lines[i]));
            assert_eq!(
                gated,
                None,
                "{path}:{}: a feature cfg above the hook",
                site + 1
            );
        }
    }
}
