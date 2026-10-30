// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Series parameters (test plan T36-T38): every bad value or
//! unsupported combination is refused with what is allowed, never answered
//! with a default or a broader aggregate.

use super::{SeriesParams, latency_of, parse};
use crate::counters::{Dim, Filter, Metric, Window};

fn params(pairs: &[(&str, &str)]) -> SeriesParams {
    let query: String = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    serde_urlencoded::from_str(&query).expect("well-formed test query")
}

#[test]
fn t37_each_supported_filter_names_its_series() {
    let cases: [(&[(&str, &str)], Filter<'_>); 6] = [
        (&[], Filter::All),
        (&[("server", "s")], Filter::Server("s")),
        (&[("server", "s"), ("tool", "t")], Filter::Tool("s", "t")),
        (&[("caller", "key:a")], Filter::Caller("key:a")),
        (
            &[("caller", "key:a"), ("server", "s")],
            Filter::CallerServer("key:a", "s"),
        ),
        (&[("overflow", "tool")], Filter::Overflow(Dim::Tool)),
    ];
    for (pairs, want) in cases {
        let p = params(pairs);
        assert_eq!(parse(&p).expect("supported").filter, want, "{pairs:?}");
    }
}

#[test]
fn t37_unsupported_combinations_are_refused_with_the_supported_sets() {
    for pairs in [
        &[("tool", "t")][..],
        &[("caller", "c"), ("tool", "t")][..],
        &[("server", "s"), ("tool", "t"), ("caller", "c")][..],
        &[("overflow", "tool"), ("server", "s")][..],
        &[("overflow", "nope")][..],
    ] {
        let p = params(pairs);
        let refusal = parse(&p).expect_err("unsupported");
        assert!(
            refusal.contains("supported filters"),
            "{pairs:?}: {refusal}"
        );
    }
}

#[test]
fn t36_compare_is_for_the_24_hour_window_only() {
    let p = params(&[("window", "24h"), ("compare", "prev")]);
    assert!(parse(&p).expect("24h compares").compare);
    for window in ["48h", "30d"] {
        let p = params(&[("window", window), ("compare", "prev")]);
        let refusal = parse(&p).expect_err("no compare");
        assert!(refusal.contains("24h only"), "{window}: {refusal}");
    }
    let p = params(&[("compare", "yesterday")]);
    assert!(parse(&p).expect_err("bad compare").contains("must be prev"));
}

#[test]
fn t38_a_bad_metric_or_window_names_the_allowed_values() {
    let p = params(&[("metric", "latency")]);
    let refusal = parse(&p).expect_err("bad metric");
    assert!(
        refusal.contains("calls, blocks, errors, firewall, cache_hits"),
        "{refusal}"
    );
    let p = params(&[("window", "7d")]);
    let refusal = parse(&p).expect_err("bad window");
    assert!(refusal.contains("24h, 48h, 30d"), "{refusal}");
    let p = params(&[("metric", "blocks"), ("window", "30d")]);
    let query = parse(&p).expect("valid");
    assert_eq!(
        (query.metric, query.window),
        (Metric::Blocks, Window::Month)
    );
}

/// Latency row 33: `metric=latency_p95` reads all servers or one; a tool,
/// caller, caller-server pair or overflow filter is refused.
#[test]
fn latency_refuses_every_other_filter() {
    let refused: [&[(&str, &str)]; 4] = [
        &[("server", "s"), ("tool", "t")],
        &[("caller", "key:a")],
        &[("caller", "key:a"), ("server", "s")],
        &[("overflow", "server")],
    ];
    for pairs in refused {
        let mut all = vec![("metric", "latency_p95")];
        all.extend_from_slice(pairs);
        let refusal = latency_of(&params(&all)).expect_err("refused");
        assert!(refusal.contains("server="), "{pairs:?}: {refusal}");
    }
    let p = params(&[("metric", "latency_p95"), ("server", "s"), ("window", "48h")]);
    assert_eq!(latency_of(&p), Ok((Some("s"), Window::TwoDays, false)));
}
