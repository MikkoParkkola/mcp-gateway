// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A line that fails its integrity check and names no usable trace cannot be
//! tied to a call: every call older than it, left without a delivery, reads an
//! unknown effect with `answer_integrity: "indeterminate"`, never `no_record`.

use serde_json::{Value, json};

use super::answer_export_tests::{export_for, ndjson};
use super::answer_fixture::{Dl, Fixture, SECRET};
use super::answer_list_tests::{get, row_of};
use crate::security::audit::{AuditEnvelope, AuditWho, InvocationTarget};
use crate::security::transparency_log::{CorrelationKey, CorrelationSource};

/// A valid, correctly signed call that carries no trace id.
fn traceless_call(fx: &Fixture) {
    let envelope = AuditEnvelope {
        trace_id: None,
        ..AuditEnvelope::ok(AuditWho::from_actor_id("c"))
    };
    fx.logger
        .log_invocation_correlated(
            CorrelationKey {
                id: "s",
                source: CorrelationSource::SessionId,
            },
            &envelope,
            InvocationTarget::meta("srv", "tool"),
            "sha256:aa",
            Some("sha256:bb"),
        )
        .unwrap();
}

/// Two calls, then a delivery whose `trace_id` an attacker removed (which
/// breaks its hash), then a later call.
fn laundered() -> Fixture {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-a");
    fx.call("gw-b");
    fx.delivery("gw-b", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-b");
    fx.call("gw-c");
    fx.edit(at, |e| {
        e.as_object_mut().unwrap().remove("trace_id");
    });
    fx
}

#[tokio::test]
async fn r56_an_untraceable_failure_marks_older_unresolved_calls_indeterminate() {
    let fx = laundered();
    let (_, page) = get(&fx, &[]).await;
    for trace in ["gw-a", "gw-b"] {
        let r = row_of(&page, trace);
        assert_eq!(r["effect"], "unknown", "{trace}: {r}");
        assert_eq!(r["answer_integrity"], "indeterminate", "{trace}: {r}");
    }
    // A call written after the failing line cannot be its delivery's call.
    let c = row_of(&page, "gw-c");
    assert_eq!(c["effect"], "no_record");
    assert!(c.get("answer_integrity").is_none(), "{c}");
    assert_eq!(page["answer_integrity_failed"], 2);
    let at = &page["answer_integrity_unattributed"];
    assert_eq!(at["log"], "invocation", "{page}");
    assert!(at["offset"].is_u64() && at["segment"].is_u64(), "{at}");
}

#[tokio::test]
async fn r57_a_failure_with_a_usable_trace_or_no_failure_changes_nothing_else() {
    // A tampered delivery that keeps its trace poisons only that trace.
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-a");
    fx.call("gw-b");
    fx.delivery("gw-b", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-b");
    fx.edit(at, |e| e["response_effect"] = json!("delivered"));
    let (_, page) = get(&fx, &[]).await;
    assert_eq!(row_of(&page, "gw-b")["answer_integrity"], "invalid");
    let a = row_of(&page, "gw-a");
    assert_eq!(a["effect"], "no_record");
    assert!(a.get("answer_integrity").is_none(), "{a}");
    assert!(page["answer_integrity_unattributed"].is_null(), "{page}");
    assert_eq!(page["answer_integrity_failed"], 1);

    // A clean log keeps today's answers and never sets the flag, even with a
    // valid line that names no trace.
    let clean = Fixture::new(Some(SECRET));
    clean.call("gw-a");
    traceless_call(&clean);
    clean.call("gw-b");
    clean.delivery("gw-b", &Dl::effect("refused"));
    let (_, page) = get(&clean, &[]).await;
    assert_eq!(row_of(&page, "gw-a")["effect"], "no_record");
    assert_eq!(row_of(&page, "gw-b")["effect"], "refused");
    assert!(page["answer_integrity_unattributed"].is_null());
    assert_eq!(page["answer_integrity_failed"], 0);
}

#[tokio::test]
async fn r58_the_export_and_the_list_give_the_same_answers_and_position() {
    let fx = laundered();
    let (_, page) = get(&fx, &[]).await;
    let (rows, manifest) = ndjson(&export_for(&fx, "ndjson", &[]).await);
    for trace in ["gw-a", "gw-b", "gw-c"] {
        let listed = row_of(&page, trace);
        let exported: &Value = rows.iter().find(|r| r["trace_id"] == trace).unwrap();
        for field in ["effect", "answer_integrity"] {
            assert_eq!(listed.get(field), exported.get(field), "{trace} {field}");
        }
    }
    assert_eq!(manifest["answer_integrity_failed"], 2);
    assert_eq!(
        manifest["answer_integrity_unattributed"],
        page["answer_integrity_unattributed"]
    );
}

/// A listed row (a call) that lost its trace and failed its hash is the same
/// failure: it names no trace, so older calls cannot rule it out.
#[tokio::test]
async fn r59_an_edited_listed_row_without_a_trace_marks_older_calls() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-a");
    fx.call("gw-x");
    let at = fx
        .lines()
        .iter()
        .position(|l| l["trace_id"] == "gw-x")
        .unwrap();
    fx.edit(at, |e| {
        e.as_object_mut().unwrap().remove("trace_id");
    });
    let (_, page) = get(&fx, &[]).await;
    let a = row_of(&page, "gw-a");
    assert_eq!(a["effect"], "unknown", "{a}");
    assert_eq!(a["answer_integrity"], "indeterminate", "{a}");
    assert!(page["answer_integrity_unattributed"]["offset"].is_u64());
}

/// The receipt reads the same answer as the list for a call the failure covers.
#[tokio::test]
async fn r60_the_receipt_agrees_with_the_list() {
    let fx = laundered();
    for trace in ["gw-a", "gw-b"] {
        let receipt = super::answer_receipt_tests::rcpt(&fx, trace);
        assert_eq!(receipt["effect"], "unknown", "{trace}");
        assert_eq!(receipt["answer_integrity"], "indeterminate", "{trace}");
    }
}
