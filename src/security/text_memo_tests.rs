// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::{MAX_ENTRIES, MAX_STORED_BYTES, MAX_TEXT_BYTES, MIN_TEXT_BYTES, TextMemo};
use std::sync::atomic::{AtomicUsize, Ordering};

fn text(n: usize, len: usize) -> String {
    let head = format!("text-{n}-");
    format!("{head}{}", "x".repeat(len - head.len()))
}

#[test]
fn a_repeated_text_is_a_hit_and_a_changed_text_a_miss() {
    let memo = TextMemo::new("test");
    let runs = AtomicUsize::new(0);
    let run = |t: &str| memo.get_or_compute(t, || runs.fetch_add(1, Ordering::Relaxed) + 100);
    let a = text(1, 2000);
    let b = text(2, 2000);
    assert_eq!(run(&a), 100);
    assert_eq!(run(&a), 100, "the held result, not a new run");
    assert_eq!(run(&b), 101, "a changed text computes again");
    assert_eq!(runs.load(Ordering::Relaxed), 2);
    assert_eq!((memo.hits(), memo.misses()), (1, 2));
}

#[test]
fn texts_outside_the_size_window_always_compute() {
    let memo = TextMemo::new("test");
    let runs = AtomicUsize::new(0);
    for t in [text(1, MIN_TEXT_BYTES - 1), text(2, MAX_TEXT_BYTES + 1)] {
        memo.get_or_compute(&t, || runs.fetch_add(1, Ordering::Relaxed));
        memo.get_or_compute(&t, || runs.fetch_add(1, Ordering::Relaxed));
    }
    assert_eq!(runs.load(Ordering::Relaxed), 4);
    assert_eq!(memo.held(), (0, 0));
    assert_eq!((memo.hits(), memo.misses()), (0, 0));
    for t in [text(3, MIN_TEXT_BYTES), text(4, MAX_TEXT_BYTES)] {
        memo.get_or_compute(&t, || 0);
        memo.get_or_compute(&t, || 0);
    }
    assert_eq!(memo.hits(), 2, "both edges of the window are memoised");
}

/// MEMO.3: a backend that varies its text on every list cannot grow it.
#[test]
fn ten_thousand_distinct_texts_stay_under_the_bounds() {
    let memo = TextMemo::new("test");
    for n in 0..10_000 {
        let t = text(n, MIN_TEXT_BYTES + (n % 7) * 20_000);
        memo.get_or_compute(&t, || n);
        let (entries, bytes) = memo.held();
        assert!(
            entries <= MAX_ENTRIES && bytes <= MAX_STORED_BYTES,
            "{n}: {entries} entries, {bytes} B"
        );
    }
    assert_eq!(memo.hits(), 0);
}

#[test]
fn the_least_recently_used_entry_is_evicted_first() {
    let memo = TextMemo::new("test");
    let texts: Vec<String> = (0..=MAX_ENTRIES).map(|n| text(n, 2000)).collect();
    for (n, t) in texts.iter().enumerate() {
        memo.get_or_compute(t, || n);
    }
    let runs = AtomicUsize::new(0);
    memo.get_or_compute(&texts[1], || runs.fetch_add(1, Ordering::Relaxed));
    assert_eq!(
        runs.load(Ordering::Relaxed),
        0,
        "the second-oldest is still held"
    );
    memo.get_or_compute(&texts[0], || runs.fetch_add(1, Ordering::Relaxed));
    assert_eq!(runs.load(Ordering::Relaxed), 1, "the oldest was evicted");
}

#[test]
fn concurrent_lookups_keep_the_bounds_and_the_results() {
    let memo = TextMemo::new("test");
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let memo = &memo;
            scope.spawn(move || {
                for n in 0..400 {
                    let key = (n + worker) % 40;
                    let got = memo.get_or_compute(&text(key, 3000), || key * 2);
                    assert_eq!(got, key * 2, "a text's own result, never another's");
                }
            });
        }
    });
    let (entries, bytes) = memo.held();
    assert!(entries <= MAX_ENTRIES && bytes <= MAX_STORED_BYTES);
}

/// A hit moves its text to the back: a catalogue re-read between one-shot
/// texts survives any number of them (FIFO would drop it after 16).
#[test]
fn a_re_read_catalogue_survives_newer_one_shot_texts() {
    let memo = TextMemo::new("test");
    let catalogue = text(0, 6000);
    let runs = AtomicUsize::new(0);
    memo.get_or_compute(&catalogue, || runs.fetch_add(1, Ordering::Relaxed));
    for n in 1..=(2 * MAX_ENTRIES) {
        memo.get_or_compute(&text(n, 2000), || 0);
        memo.get_or_compute(&catalogue, || runs.fetch_add(1, Ordering::Relaxed));
    }
    assert_eq!(
        runs.load(Ordering::Relaxed),
        1,
        "the catalogue was never evicted"
    );
}
