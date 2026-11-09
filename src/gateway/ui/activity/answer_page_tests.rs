// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 rows R4, R28, R29, R30: the join across page edges and the
//! `effect=` filter.

use std::collections::BTreeSet;

use axum::http::StatusCode;
use serde_json::{Map, Value, json};

use super::answer_fixture::{Dl, Fixture};
use super::answer_list_tests::{get, row_of, traces};
use crate::security::audit::{AuditEnvelope, AuditWho};

fn cursor(page: &Value) -> Option<String> {
    page["next_cursor"].as_str().map(str::to_string)
}

/// Every page of `pairs`, following cursors: the pages.
async fn drain(fx: &Fixture, pairs: &[(&str, &str)]) -> Vec<Value> {
    let mut pages = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let mut q: Vec<(&str, &str)> = pairs.to_vec();
        if let Some(c) = next.as_deref() {
            q.push(("cursor", c));
        }
        let (status, page) = get(fx, &q).await;
        assert_eq!(status, StatusCode::OK);
        next = cursor(&page);
        pages.push(page);
        if next.is_none() || pages.len() > 400 {
            return pages;
        }
    }
}

#[tokio::test]
async fn r4_the_join_survives_the_page_edge() {
    let fx = Fixture::new(None);
    fx.call("gw-1");
    fx.call("gw-2");
    fx.delivery("gw-2", &Dl::effect("refused"));
    fx.delivery("gw-1", &Dl::effect("annotated"));
    let (_, first) = get(&fx, &[("limit", "1")]).await;
    assert_eq!(row_of(&first, "gw-2")["effect"], "refused");
    let c = cursor(&first).unwrap();
    let (_, second) = get(&fx, &[("limit", "1"), ("cursor", &c)]).await;
    assert_eq!(row_of(&second, "gw-1")["effect"], "annotated");
}

#[tokio::test]
async fn r28_cleaned_pages_chain_by_cursor() {
    let fx = Fixture::new(None);
    for i in 0..120 {
        let t = format!("gw-{i}");
        fx.call(&t);
        fx.delivery(
            &t,
            &Dl::effect(if i % 3 == 0 { "rewritten" } else { "delivered" }),
        );
    }
    let pages = drain(&fx, &[("outcome", "cleaned"), ("limit", "10")]).await;
    let all: Vec<String> = pages.iter().flat_map(traces).collect();
    let unique: BTreeSet<&String> = all.iter().collect();
    assert_eq!(all.len(), 40);
    assert_eq!(unique.len(), 40);
}

#[tokio::test]
async fn r29_sixty_four_concurrent_calls_join_across_pages() {
    let fx = Fixture::new(None);
    for i in 0..64 {
        fx.call(&format!("gw-{i}"));
    }
    for k in 0..64 {
        let i: usize = (k * 37) % 64;
        let e = if i.is_multiple_of(2) {
            "delivered"
        } else {
            "refused"
        };
        fx.delivery(&format!("gw-{i}"), &Dl::effect(e));
    }
    let pages = drain(&fx, &[("limit", "10")]).await;
    assert_eq!(pages.len(), 7);
    for page in &pages {
        assert_eq!(page["join_incomplete"], 0);
        for r in page["rows"].as_array().unwrap() {
            let i: usize = r["trace_id"].as_str().unwrap()[3..].parse().unwrap();
            assert_eq!(
                r["effect"],
                if i.is_multiple_of(2) {
                    "delivered"
                } else {
                    "refused"
                }
            );
        }
    }
}

#[tokio::test]
async fn r30_the_effect_filter_takes_each_value() {
    let fx = Fixture::new(None);
    for (t, e) in [
        ("gw-delivered", "delivered"),
        ("gw-annotated", "annotated"),
        ("gw-rewritten", "rewritten"),
        ("gw-refused", "refused"),
    ] {
        fx.call(t);
        fx.delivery(t, &Dl::effect(e));
    }
    fx.call("gw-unknown");
    fx.delivery("gw-unknown", &Dl::omitted());
    fx.call("gw-no_record");
    let mut admin = Map::new();
    admin.insert("event".into(), "admin_action".into());
    let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("c"));
    fx.logger.append_event(admin, &envelope).unwrap();
    for v in [
        "delivered",
        "annotated",
        "rewritten",
        "refused",
        "unknown",
        "no_record",
    ] {
        let (status, page) = get(&fx, &[("effect", v)]).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(traces(&page), [format!("gw-{v}")], "{v}");
    }
    let (status, bad) = get(&fx, &[("effect", "bogus")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        bad["supported"],
        json!([
            "delivered",
            "annotated",
            "rewritten",
            "refused",
            "unknown",
            "no_record"
        ])
    );
}
