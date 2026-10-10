// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Throwaway probe (never merged): which texts the egress regex sets scan,
//! and whether they hold non-ASCII bytes (MIK-8259 premise check).
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Mutex;

static STATE: Mutex<Option<(HashSet<u64>, std::collections::BTreeMap<&'static str, [u64; 4]>)>> = Mutex::new(None);

/// Count one scan at `site`; log each distinct non-ASCII text once.
pub fn note(site: &'static str, text: &str) {
    let ascii = text.is_ascii();
    let mut g = STATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (seen, counts) = g.get_or_insert_with(Default::default);
    let c = counts.entry(site).or_default();
    // [ascii scans, non-ascii scans, ascii bytes, non-ascii bytes]
    let i = usize::from(!ascii);
    c[i] += 1;
    c[2 + i] += text.len() as u64;
    let total = c[0] + c[1];
    if total % 2000 == 0 {
        eprintln!("SCANPROBE-COUNT site={site} ascii={} nonascii={} ascii_bytes={} nonascii_bytes={}", c[0], c[1], c[2], c[3]);
    }
    if !ascii && seen.len() < 40 {
        let mut h = DefaultHasher::new();
        (site, text).hash(&mut h);
        if seen.insert(h.finish()) {
            let at = text.bytes().position(|b| !b.is_ascii()).unwrap_or(0);
            let lo = text.floor_char_boundary(at.saturating_sub(80));
            let hi = text.ceil_char_boundary((at + 80).min(text.len()));
            let head = &text[..text.ceil_char_boundary(160.min(text.len()))];
            eprintln!("SCANPROBE-NONASCII site={site} len={} first_nonascii_at={at} head={head:?} around={:?}", text.len(), &text[lo..hi]);
        }
    }
}
