// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 rows R17, R19, R26, R27, R31-R34, R39, R40, R42: the map's bounds
//! and the trust rule.

use serde_json::json;

use super::answer_fixture::{Dl, Fixture, SECRET, forge};
use super::answer_list_tests::{get, row_of, traces};

#[tokio::test]
async fn r17_eviction_names_the_call_and_spares_the_rest() {
    let fx = Fixture::new(None);
    fx.call_on("only", "gw-t0");
    for i in 1..=256 {
        fx.call(&format!("gw-t{i}"));
    }
    for i in 1..=256 {
        fx.delivery(&format!("gw-t{i}"), &Dl::effect("refused"));
    }
    fx.delivery("gw-t0", &Dl::effect("refused"));
    let (_, page) = get(&fx, &[("server", "only")]).await;
    let r = row_of(&page, "gw-t0");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(page["join_incomplete"], 1);
    let (_, rest) = get(&fx, &[("server", "srv"), ("limit", "200")]).await;
    assert!(
        rest["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["effect"] == "refused")
    );
}

#[tokio::test]
async fn r19_a_settlement_row_shares_the_delivery() {
    let fx = Fixture::new(None);
    fx.call("gw-t1");
    fx.call("gw-t1");
    fx.delivery("gw-t1", &Dl::effect("annotated"));
    let (_, page) = get(&fx, &[]).await;
    let rows = page["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r["effect"] == "annotated"));
    assert_eq!(page["answer_integrity_failed"], 0);
}

#[tokio::test]
async fn r26_a_duplicate_survives_eviction() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    for i in 0..256 {
        fx.delivery(&format!("gw-o{i}"), &Dl::effect("delivered"));
    }
    fx.delivery("gw-t", &Dl::effect("delivered"));
    let (_, page) = get(&fx, &[]).await;
    assert_eq!(row_of(&page, "gw-t")["effect"], "unknown");
}

#[tokio::test]
async fn r27_a_tampered_delivery_record_poisons_its_trace() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-t");
    fx.edit(at, |e| e["response_effect"] = json!("delivered"));
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer_integrity"], "invalid");
    assert_eq!(page["answer_integrity_failed"], 1);
}

#[tokio::test]
async fn r31_a_bad_hmac_with_a_valid_hash_is_invalid() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-t");
    fx.edit(at, |e| {
        e["sig"] = json!(format!("hmac-sha256:{}", "0".repeat(64)));
    });
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t");
    assert_eq!(r["answer_integrity"], "invalid");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(page["answer_integrity_failed"], 1);
}

#[tokio::test]
async fn r32_a_stripped_signature_under_a_secret_never_delivers() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-t");
    fx.edit(at, |e| {
        forge(e, "response_effect", json!("delivered"), true);
    });
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer_integrity"], "unsigned");
    assert_eq!(page["answer_integrity_failed"], 1);
}

/// A delivery record written before signing began (the log had no secret)
/// reads Unsigned by position, but a gateway that now holds a secret still
/// cannot believe it: the effect stays at its fail-closed value, never delivered.
#[tokio::test]
async fn r32b_a_legacy_unsigned_delivery_under_a_secret_is_not_believed() {
    let legacy = Fixture::new(None);
    legacy.call("gw-t");
    legacy.delivery("gw-t", &Dl::effect("delivered"));
    let mut logs = legacy.logs();
    logs.secret = Some(SECRET.as_bytes().to_vec());
    let response = super::list_page(&logs, &legacy.access(), &super::ListQuery::default());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let r = row_of(&page, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer_integrity"], "unsigned");
    assert_eq!(page["answer_integrity_failed"], 1);
}

#[tokio::test]
async fn r33_no_secret_cannot_vouch() {
    let signed = Fixture::new(Some(SECRET));
    signed.call("gw-t");
    signed.delivery("gw-t", &Dl::effect("delivered"));
    let mut logs = signed.logs();
    logs.secret = None;
    let response = super::list_page(&logs, &signed.access(), &super::ListQuery::default());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let r = row_of(&page, "gw-t");
    assert_eq!(r["effect"], "delivered");
    assert_eq!(r["answer_integrity"], "unverifiable");
    let _ = traces(&page);
}
