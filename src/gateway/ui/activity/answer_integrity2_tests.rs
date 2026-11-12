// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 rows R34, R39, R40, R42: tampered routing fields, tombstone
//! overflow, the integrity reason across eviction, and counting after access.

use serde_json::{Value, json};

use super::access::Access;
use super::answer_fixture::{Dl, Fixture, SECRET, forge};
use super::answer_list_tests::{get, row_of};
use super::{ListQuery, list_page};

async fn scoped(fx: &Fixture, access: &Access) -> Value {
    let response = list_page(&fx.logs(), access, &ListQuery::default());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn r34_a_tampered_stage_cannot_escape_the_join() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    fx.delivery("gw-t", &Dl::effect("delivered"));
    let at = fx.delivery_index("gw-t");
    fx.edit(at, |e| {
        forge(e, "response_stage", json!("notification_delivered"), false);
    });
    let (_, page) = get(&fx, &[]).await;
    assert_eq!(row_of(&page, "gw-t")["effect"], "unknown");
    assert_eq!(page["answer_integrity_failed"], 1);
}

#[tokio::test]
async fn r39_tombstone_overflow_never_restores_a_record() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("delivered"));
    for i in 0..4_400 {
        fx.delivery(&format!("gw-o{i}"), &Dl::effect("delivered"));
    }
    let (_, page) = get(&fx, &[]).await;
    assert_eq!(row_of(&page, "gw-t")["effect"], "unknown");
    assert_eq!(page["join_incomplete"], 1);
}

#[tokio::test]
async fn r40_the_integrity_reason_survives_eviction() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("delivered"));
    for i in 0..260 {
        fx.delivery(&format!("gw-o{i}"), &Dl::effect("delivered"));
    }
    fx.delivery("gw-t", &Dl::effect("delivered"));
    let last = fx.lines().len() - 1;
    fx.edit(last, |e| e["response_effect"] = json!("refused"));
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer_integrity"], "invalid");
    assert_eq!(page["answer_integrity_failed"], 1);
}

#[tokio::test]
async fn r42_counts_are_taken_after_authorisation() {
    let fx = Fixture::new(Some(SECRET));
    fx.call_on("B", "gw-b0");
    fx.call_on("B", "gw-b1");
    fx.call_on("A", "gw-a0");
    fx.delivery("gw-a0", &Dl::effect("delivered"));
    fx.delivery("gw-b1", &Dl::effect("delivered"));
    let poisoned = fx.delivery_index("gw-b1");
    fx.edit(poisoned, |e| e["response_effect"] = json!("refused"));
    for i in 0..256 {
        fx.delivery(&format!("gw-o{i}"), &Dl::effect("delivered"));
    }
    fx.delivery("gw-b0", &Dl::effect("delivered"));
    let admin = scoped(&fx, &Access::All).await;
    assert_eq!(admin["join_incomplete"], 2);
    assert_eq!(admin["answer_integrity_failed"], 1);
    let dev = scoped(
        &fx,
        &Access::Scoped {
            owner: None,
            backends: vec!["A".into()],
        },
    )
    .await;
    assert_eq!(dev["join_incomplete"], 0);
    assert_eq!(dev["answer_integrity_failed"], 0);
}
