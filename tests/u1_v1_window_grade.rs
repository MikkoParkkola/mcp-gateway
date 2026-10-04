// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grades the U1 production window that started on 2026-10-02 under the v1
//! method (MIK-7211.PARENT.1 and PARENT.5). The window is graded by the method
//! it started under, so this reads the v1 inputs directly: two token-scraped
//! `/metrics` files from the live gateway and the durable stdio `window.json`.
//!
//! Only `Snapshot`, `retire_revisions` and `distribution_table` are used, so
//! the harness survives the v2 window (#2469) removing the v1 entry points.
//! The alignment check and the stdio-and-HTTP intersection mirror
//! `production_retirement_decision_at` at release-line 8d5e0a9cc.
//!
//! Run on the window's end (2026-10-09 18:49:39 CEST or later):
//!
//! ```text
//! U1_BASELINE=u1-baseline-20261002T164939Z.prom U1_BASELINE_TS=1790959779 \
//! U1_FINAL=u1-final.prom U1_FINAL_TS=<scrape unix second> \
//! U1_DATA_DIR=<copy of ~/.mcp-gateway taken with the final scrape> \
//! U1_PID_LOG=u1-pid-watch.log U1_PID=53431 \
//! cargo test --test u1_v1_window_grade -- --ignored --nocapture
//! ```
//!
//! Provenance: keep the final scrape and the window.json copy on the
//! maintainer's machine, never in the repository and never deleted, beside a
//! `.meta` file in `.git/lead-decisions/` recording the sha256 and byte size
//! of every input (baseline scrape, final scrape, window.json copy, PID watch
//! log), the scrape second, the gateway PID and start time, and this
//! harness's commit, checked out to run it. The public record cites shares,
//! the decision, the input sha256 values and the harness commit; it carries
//! no raw request counts.
//!
//! The grade refuses inputs that cannot support it: a scrape missing any
//! zero-registered series, a counter that went down, a stdio window written
//! after the final scrape, or a PID watch log showing another process or a
//! gap after the window's process started (a restart that caught back up to
//! the baseline counts is invisible in the counters alone).

use std::collections::BTreeMap;
use std::time::Duration;

use mcp_gateway::protocol_revision_telemetry::{
    MEASURED_REVISIONS, OTHER_REVISION, Snapshot, distribution_table, retire_revisions,
};
use serde_json::Value;

const OBSERVED: &str = "mcp_protocol_revision_observations_total";
const UNATTRIBUTED: &str = "mcp_protocol_revision_unattributed_observations_total";
/// `register_metrics` at release-line 8d5e0a9cc zero-registers (6 measured
/// revisions + other) x 7 client families x 3 transports observed series and
/// 7 x 3 unattributed ones. A scrape with fewer is not the live exporter's.
const REGISTERED_SERIES: usize = 7 * 7 * 3 + 7 * 3;

/// `(metric, sorted labels)` to value, for the two U1 counter families.
type Series = BTreeMap<(String, Vec<(String, String)>), u64>;

fn parse(text: &str) -> Series {
    let mut series = Series::new();
    for line in text.lines() {
        let Some((head, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let Some((name, labels)) = head.split_once('{') else {
            continue;
        };
        if name != OBSERVED && name != UNATTRIBUTED {
            continue;
        }
        let mut pairs: Vec<(String, String)> = labels
            .trim_end_matches('}')
            .split(',')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (k.to_string(), v.trim_matches('"').to_string()))
            .collect();
        pairs.sort();
        // The exporter writes counters as integers; anything else fails loudly.
        let value: u64 = value
            .parse()
            .unwrap_or_else(|_| panic!("a whole counter value: {line}"));
        series.insert((name.to_string(), pairs), value);
    }
    series
}

fn label<'a>(pairs: &'a [(String, String)], key: &str) -> &'a str {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map_or("", |(_, v)| v.as_str())
}

/// The counts recorded between the two scrapes, shaped like
/// `Registry::snapshot`. A counter that went down means a restart, which
/// voids the window.
/// The scrape carries every series `register_metrics` creates.
fn assert_registered(baseline: &Series) {
    assert_eq!(
        baseline.len(),
        REGISTERED_SERIES,
        "the baseline scrape does not carry every registered U1 series"
    );
    for revision in MEASURED_REVISIONS.iter().copied().chain([OTHER_REVISION]) {
        assert!(
            baseline
                .keys()
                .any(|(_, pairs)| label(pairs, "requested_revision") == revision),
            "no series for revision {revision}"
        );
    }
}

fn delta_snapshot(baseline: &Series, last: &Series) -> Snapshot {
    // Every series is registered at zero at startup, so both scrapes carry
    // the same set; a missing one means a truncated or foreign scrape.
    let missing: Vec<_> = baseline.keys().filter(|k| !last.contains_key(*k)).collect();
    let extra: Vec<_> = last.keys().filter(|k| !baseline.contains_key(*k)).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "the scrapes carry different series: missing {missing:?}, extra {extra:?}"
    );
    let mut snapshot = Snapshot::default();
    for (key, now) in last {
        let before = baseline.get(key).copied().unwrap_or(0);
        assert!(*now >= before, "counter went down (restart): {key:?}");
        let n = now - before;
        if n == 0 {
            continue;
        }
        let (name, pairs) = key;
        snapshot.total += n;
        *snapshot
            .by_client
            .entry(label(pairs, "client").to_string())
            .or_default() += n;
        *snapshot
            .by_transport
            .entry(label(pairs, "transport").to_string())
            .or_default() += n;
        if name == OBSERVED {
            *snapshot
                .by_revision
                .entry(label(pairs, "requested_revision").to_string())
                .or_default() += n;
        } else {
            snapshot.unattributed += n;
        }
    }
    snapshot
}

/// Unix seconds of a `2026-10-02T18:49:47+0200` stamp; `None` otherwise.
fn stamp(line: &str) -> Option<i64> {
    let t = line.get(..24)?;
    let num = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let sign = match t.get(19..20)? {
        "+" => 1,
        "-" => -1,
        _ => return None,
    };
    let offset = sign * (num(20..22)? * 3600 + num(22..24)? * 60);
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss - offset)
}

/// The PID watch log, from `restart done pid=<pid>` on, names only `pid` and
/// one start time, with a timestamped check within 15 minutes of each end of
/// the window.
fn assert_one_process(log: &str, pid: u32, from: u64, to: u64) {
    const MAX_GAP: i64 = 900;
    let marker = format!("restart done pid={pid}");
    let lines: Vec<&str> = log.lines().collect();
    let start = lines
        .iter()
        .rposition(|line| line.contains(&marker))
        .unwrap_or_else(|| panic!("no '{marker}' line in the PID watch log"));
    let want = pid.to_string();
    let mut lstarts = std::collections::BTreeSet::new();
    let mut stamps = Vec::new();
    for line in &lines[start + 1..] {
        // Every `pid=<digits>` on the line must name the window's process.
        let named: Vec<&str> = line
            .split("pid=")
            .skip(1)
            .map(|rest| {
                rest.split(|c: char| !c.is_ascii_digit())
                    .next()
                    .unwrap_or("")
            })
            .collect();
        if named.is_empty() {
            continue;
        }
        assert!(
            named.iter().all(|n| *n == want),
            "another process in the window: {line}"
        );
        if let Some((_, lstart)) = line.split_once("lstart=") {
            lstarts.insert(lstart.trim().to_string());
            stamps.push(stamp(line).unwrap_or_else(|| panic!("no timestamp: {line}")));
        }
    }
    assert_eq!(lstarts.len(), 1, "start times in the window: {lstarts:?}");
    let (from, to) = (i64::try_from(from).unwrap(), i64::try_from(to).unwrap());
    let inside: Vec<i64> = stamps
        .into_iter()
        .filter(|t| (from..=to).contains(t))
        .collect();
    // A restart anywhere in the window shows a new PID or start time at the
    // next check, so interior gaps (a sleeping host) cannot hide one. Only the
    // edges need a check close by: the first after the baseline, and the last
    // before the final scrape.
    let (Some(first), Some(last)) = (inside.first(), inside.last()) else {
        panic!("no PID check inside the window");
    };
    assert!(
        first - from <= MAX_GAP,
        "first PID check {} s after the baseline",
        first - from
    );
    assert!(
        to - last <= MAX_GAP,
        "last PID check {} s before the final scrape",
        to - last
    );
}

/// Mirrors `production_retirement_decision_at`: misalignment blocks, then the
/// stdio half, then the HTTP half, then their intersection.
fn joint(
    aligned: bool,
    stdio: Result<Vec<String>, impl std::fmt::Debug>,
    http: Result<Vec<String>, impl std::fmt::Debug>,
) -> Result<Vec<String>, String> {
    if !aligned {
        return Err("WindowMisaligned".to_string());
    }
    match (stdio, http) {
        (Err(blocked), _) => Err(format!("{blocked:?}")),
        (Ok(_), Err(blocked)) => Err(format!("{blocked:?}")),
        (Ok(stdio), Ok(http)) => Ok(stdio.into_iter().filter(|r| http.contains(r)).collect()),
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

#[test]
#[ignore = "grades the live U1 window; needs the scrapes and the data directory"]
fn u1_v1_window_grade() {
    let baseline_ts: u64 = env("U1_BASELINE_TS").parse().expect("unix seconds");
    let final_ts: u64 = env("U1_FINAL_TS").parse().expect("unix seconds");
    let read = |var| std::fs::read_to_string(env(var)).expect("a readable scrape");
    let (baseline, last) = (parse(&read("U1_BASELINE")), parse(&read("U1_FINAL")));
    assert_registered(&baseline);
    let http = delta_snapshot(&baseline, &last);

    let window_path = std::path::Path::new(&env("U1_DATA_DIR"))
        .join("protocol-revision-telemetry")
        .join("window.json");
    let window: Value =
        serde_json::from_str(&std::fs::read_to_string(&window_path).expect("window.json"))
            .expect("window.json is JSON");
    assert_eq!(
        window["schema_version"], "mcp_protocol_revision_window.v1",
        "this harness grades the v1 window only"
    );
    let stdio: Snapshot =
        serde_json::from_value(window["snapshot"].clone()).expect("a v1 snapshot");
    let aligned = window["started_at_unix_seconds"].as_u64() == Some(baseline_ts);
    let elapsed = Duration::from_secs(final_ts.saturating_sub(baseline_ts));

    let updated = window["updated_at_unix_seconds"]
        .as_u64()
        .expect("updated_at");
    assert!(
        updated <= final_ts,
        "window.json was written after the final scrape ({updated} > {final_ts}); copy it with the scrape"
    );
    let pid: u32 = env("U1_PID").parse().expect("a PID");
    let log = std::fs::read_to_string(env("U1_PID_LOG")).expect("a readable PID watch log");
    assert_one_process(&log, pid, baseline_ts, final_ts);

    let http_decision = retire_revisions(&http, elapsed);
    let stdio_decision = retire_revisions(&stdio, elapsed);
    println!(
        "U1 v1 window: {baseline_ts} .. {final_ts} ({} s)",
        elapsed.as_secs()
    );
    println!("aligned (durable start == baseline scrape): {aligned}");
    println!("\nHTTP process, by transport: {:?}", http.by_transport);
    println!("HTTP process, by client: {:?}", http.by_client);
    println!("{}", distribution_table(&http));
    println!("HTTP decision: {http_decision:?}");
    println!("\nstdio durable window:\n{}", distribution_table(&stdio));
    println!("stdio decision: {stdio_decision:?}");
    // Mirrors production_retirement_decision_at: misalignment blocks, then
    // the stdio half, then the HTTP half, then the intersection.
    let joint = joint(aligned, stdio_decision, http_decision);
    println!("\nJOINT DECISION (retire): {joint:?}");
}

/// The parser and the delta, on a scrape shaped like the live one.
#[test]
fn a_scrape_pair_becomes_the_counts_between_them() {
    let baseline = parse(concat!(
        "# TYPE mcp_protocol_revision_observations_total counter\n",
        "mcp_protocol_revision_observations_total{requested_revision=\"2025-06-18\",client=\"unattributed\",transport=\"http\"} 4\n",
        "mcp_protocol_revision_observations_total{requested_revision=\"2025-11-25\",client=\"claude\",transport=\"http\"} 0\n",
        "mcp_protocol_revision_unattributed_observations_total{client=\"claude\",transport=\"http\"} 0\n",
        "other_metric{a=\"b\"} 9\n",
    ));
    let last = parse(concat!(
        "mcp_protocol_revision_observations_total{requested_revision=\"2025-06-18\",client=\"unattributed\",transport=\"http\"} 10\n",
        "mcp_protocol_revision_observations_total{client=\"claude\",requested_revision=\"2025-11-25\",transport=\"http\"} 3\n",
        "mcp_protocol_revision_unattributed_observations_total{client=\"claude\",transport=\"http\"} 1\n",
    ));
    let snapshot = delta_snapshot(&baseline, &last);
    assert_eq!(snapshot.total, 10);
    assert_eq!(snapshot.unattributed, 1);
    assert_eq!(snapshot.by_revision["2025-06-18"], 6);
    assert_eq!(snapshot.by_revision["2025-11-25"], 3);
    assert_eq!(snapshot.by_client["claude"], 4);
    assert_eq!(snapshot.by_transport["http"], 10);
}

/// A final scrape missing a zero-registered series is refused, not read as zero.
#[test]
#[should_panic(expected = "different series")]
fn a_scrape_missing_a_series_is_refused() {
    let line = "mcp_protocol_revision_unattributed_observations_total{client=\"claude\",transport=\"http\"} 0\n";
    delta_snapshot(&parse(line), &parse(""));
}

/// The joint decision: misalignment first, then stdio, then HTTP, then the
/// intersection.
#[test]
fn the_joint_decision_keeps_the_v1_precedence() {
    let ok = |v: &[&str]| Ok::<Vec<String>, &str>(v.iter().map(ToString::to_string).collect());
    assert_eq!(
        joint(false, ok(&["a"]), ok(&["a"])),
        Err("WindowMisaligned".to_string())
    );
    assert_eq!(
        joint(true, Err("NoObservations"), Err("AttributionBelowFloor")),
        Err("\"NoObservations\"".to_string())
    );
    assert_eq!(
        joint(true, ok(&["a"]), Err("AttributionBelowFloor")),
        Err("\"AttributionBelowFloor\"".to_string())
    );
    assert_eq!(
        joint(true, ok(&["a", "b"]), ok(&["b", "c"])),
        ok(&["b"]).map_err(String::from)
    );
}

/// One process across the window passes; another PID, a second start time or
/// no check near the window's end is refused.
#[test]
fn the_pid_watch_must_show_one_unbroken_process() {
    let t0 = stamp("2026-10-02T18:50:00+0200").expect("a stamp");
    assert_eq!(t0, 1_790_959_800);
    let mut log = String::from("x pid=1 lstart=old\nrestart done pid=7 lstart=t\n");
    log.extend(
        ["18:50", "18:55", "19:00"].map(|at| format!("2026-10-02T{at}:00+0200 pid=7 lstart=t\n")),
    );
    let (from, to) = (u64::try_from(t0).unwrap(), u64::try_from(t0).unwrap() + 600);
    assert_one_process(&log, 7, from, to);
    let other = format!("{log}2026-10-02T19:00:00+0200 pid=8 lstart=u\n");
    assert!(std::panic::catch_unwind(|| assert_one_process(&other, 7, from, to)).is_err());
    let restarted = format!("{log}2026-10-02T19:00:00+0200 pid=7 lstart=u\n");
    assert!(std::panic::catch_unwind(|| assert_one_process(&restarted, 7, from, to)).is_err());
    assert!(std::panic::catch_unwind(|| assert_one_process(&log, 7, from, to + 3600)).is_err());
}

/// A scrape short of the registered series set is refused even when both
/// scrapes are short in the same way.
#[test]
#[should_panic(expected = "every registered U1 series")]
fn a_scrape_short_of_the_registered_set_is_refused() {
    let line = "mcp_protocol_revision_unattributed_observations_total{client=\"claude\",transport=\"http\"} 0\n";
    assert_registered(&parse(line));
}
