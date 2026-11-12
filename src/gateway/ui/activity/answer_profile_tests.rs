// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Profiling only (M2): where a 10,000-row export's allocation goes,
//! by phase, measured with the existing alloc meter. Ignored: run with
//! `--ignored m2_profile --nocapture`; it asserts nothing.

use std::cell::RefCell;

use serde_json::json;

use super::answer_alloc_tests::over_caps;
use super::answer_export_tests::signer;
use super::export::{CAPS, collect, ndjson, ndjson_size};
use super::joiner::{Joiner, Seen};
use super::reader::{Limits, Look, read_page_joined};
use super::rows::{Check, Filter, kind_of};
use super::{Access, answer_fixture::Fixture};
use crate::gateway::alloc_meter::{Measured, measure};

fn report(name: &str, run: u32, m: Measured, rows: u64) {
    println!(
        "PROFILE {name} run {run}: {} B, {} calls, largest {} B, {} large; per row {} B, {} calls",
        m.bytes,
        m.calls,
        m.largest,
        m.large,
        m.bytes / rows,
        m.calls / rows
    );
}

/// The whole log read newest first, `keep` deciding nothing is a match.
pub(super) fn scan(fx: &Fixture, fold: bool) {
    let check = Check::bare(None);
    let joiner = RefCell::new(Joiner::new(&check));
    let limits = Limits {
        matches: 100,
        bytes: 512 << 20,
    };
    let seen = Seen {
        above: 0,
        head_covered: true,
    };
    let keep = |line: &super::reader::Line, seen: Seen| {
        if fold {
            let mut j = joiner.borrow_mut();
            if !j.observe(line) && kind_of(line).is_some() {
                let answer = j.join(line, seen);
                j.count(&answer);
            }
        }
        false
    };
    read_page_joined(&fx.path, None, None, limits, Look::Carried(seen), keep).unwrap();
}

#[test]
#[ignore = "profiling, not an assertion"]
fn m2_profile_phases_of_a_ten_thousand_row_export() {
    let fx = over_caps(10_000, false);
    let lines = std::fs::read_to_string(&fx.path).unwrap().lines().count() as u64;
    println!("PROFILE log: {lines} lines");
    for run in 1..=2 {
        report("scan only", run, measure(|| scan(&fx, false)).1, lines);
        report(
            "scan+observe+join",
            run,
            measure(|| scan(&fx, true)).1,
            lines,
        );
        let ((collected, rows), m) = measure(|| {
            let c = collect(
                &fx.path,
                None,
                &Filter::default(),
                &Access::All,
                &Check::bare(None),
                CAPS,
                ndjson_size,
            )
            .unwrap();
            let n = c.rows.len() as u64;
            (c, n)
        });
        report("collect (all phases to rows)", run, m, rows);
        println!(
            "PROFILE collect: {rows} rows, {} passes",
            rows.div_ceil(100)
        );
        let (bytes, m) = measure(|| ndjson(&collected, json!({}), &signer()));
        report("ndjson serialise+sign", run, m, rows);
        println!("PROFILE output: {} bytes", bytes.len());
    }
}

/// The passes of an export read as `collect` reads them, without building a
/// row: per-pass cost, then `row()` and the size function over the rows.
#[test]
#[ignore = "profiling, not an assertion"]
fn m2_profile_passes_and_row_build() {
    use super::answer::Joined;
    let fx = over_caps(10_000, false);
    let check = Check::bare(None);
    let joiner = RefCell::new(Joiner::new(&check));
    let mut carried = Seen {
        above: 0,
        head_covered: true,
    };
    let (mut cursor, mut per_pass, mut kept) = (None, Vec::new(), Vec::new());
    let mut examined: Vec<u64> = Vec::new();
    loop {
        let answers = RefCell::new(Vec::<Joined>::new());
        let limits = Limits {
            matches: 100,
            bytes: 512 << 20,
        };
        let keep = |line: &super::reader::Line, seen: Seen| {
            let mut j = joiner.borrow_mut();
            if j.observe(line) || kind_of(line).is_none() {
                return false;
            }
            let this = j.join(line, seen);
            j.count(&this);
            answers.borrow_mut().push(this);
            true
        };
        let (page, m) = measure(|| {
            read_page_joined(
                &fx.path,
                None,
                cursor.as_ref(),
                limits,
                Look::Carried(carried),
                keep,
            )
            .unwrap()
        });
        per_pass.push(m);
        examined.push(page.bytes_examined);
        carried = page.above_end;
        kept.extend(page.lines.iter().cloned().zip(answers.into_inner()));
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    let total: u64 = per_pass.iter().map(|m| m.bytes).sum();
    let calls: u64 = per_pass.iter().map(|m| m.calls).sum();
    let mut sorted: Vec<u64> = per_pass.iter().map(|m| m.bytes).collect();
    sorted.sort_unstable();
    println!(
        "PROFILE passes: {} passes, {total} B, {calls} calls; first {} B, median {} B, max {} B, last {} B",
        per_pass.len(),
        per_pass[0].bytes,
        sorted[sorted.len() / 2],
        sorted[sorted.len() - 1],
        per_pass[per_pass.len() - 1].bytes
    );
    let log_bytes = std::fs::metadata(&fx.path).unwrap().len();
    let mut sorted_examined = examined.clone();
    sorted_examined.sort_unstable();
    println!(
        "PROFILE examined: log {log_bytes} B; per pass first {}, median {}, max {}, last {}; sum {}",
        examined[0],
        sorted_examined[sorted_examined.len() / 2],
        sorted_examined[sorted_examined.len() - 1],
        examined[examined.len() - 1],
        examined.iter().sum::<u64>()
    );
    let rows = kept.len() as u64;
    let ((), m) = measure(|| {
        for (line, answer) in &kept {
            drop(super::rows::row(line, &check, answer));
        }
    });
    report("row() over the kept lines", 1, m, rows);
    let built: Vec<_> = kept
        .iter()
        .filter_map(|(l, j)| super::rows::row(l, &check, j))
        .collect();
    let ((), m) = measure(|| {
        for r in &built {
            let _ = ndjson_size(r);
        }
    });
    report("ndjson_size over the rows", 1, m, rows);
}

/// What opening a log for one page costs on its own, before any window is read.
#[test]
#[ignore = "profiling, not an assertion"]
fn m2_profile_open_cost_of_one_page() {
    use crate::security::transparency_log::pager::{open_segment, position};
    let fx = over_caps(10_000, false);
    for run in 1..=2 {
        let (at, m) = measure(|| position(&fx.path, None).unwrap());
        report("pager::position", run, m, 1);
        let segment = at.segment;
        let (file, m) = measure(|| open_segment(&fx.path, segment, || {}).unwrap());
        report("pager::open_segment", run, m, 1);
        drop(file);
    }
}

/// M1's fixture, read as a list page: cumulative allocation and the bytes the
/// page examined, for the ratchet rows.
#[test]
#[ignore = "profiling, not an assertion"]
fn m1_profile_one_list_page() {
    let fx = over_caps(200, true);
    let log_bytes = std::fs::metadata(&fx.path).unwrap().len();
    let lines = std::fs::read_to_string(&fx.path).unwrap().lines().count() as u64;
    let query = super::ListQuery {
        limit: Some("200".into()),
        ..super::ListQuery::default()
    };
    for run in 1..=2 {
        report("m1 scan only", run, measure(|| scan(&fx, false)).1, lines);
        report(
            "m1 scan+observe+join",
            run,
            measure(|| scan(&fx, true)).1,
            lines,
        );
        let (response, m) = measure(|| super::list_page(&fx.logs(), &fx.access(), &query));
        drop(response);
        report("m1 list page", run, m, 200);
        println!("PROFILE m1 log: {log_bytes} B, {lines} lines");
    }
}
