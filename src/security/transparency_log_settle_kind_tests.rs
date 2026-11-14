// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settle records live in the `settle.` kind namespace (delta S2, S2'):
//! settle refuses any other kind as Invalid, and no other append may write
//! one.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::rotation_tests::{cfg, log_path};
#[cfg(feature = "webui")]
use super::settle::IntentKind;
use super::settle::{InvalidPayload, Role, Unsettled};
use super::settle_tests::{on_disk, payload, records_of};
use super::*;
use crate::security::audit::InvocationTarget;

/// The settle kind of a save: the prefix (delta S2') before II.3's kind.
const SETTLE_SAVE: &str = "settle.save";

fn opened(dir: &tempfile::TempDir) -> (std::path::PathBuf, Arc<TransparencyLogger>) {
    let path = log_path(dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    (path, l)
}

/// The payload with `kind` set to `kind`, or removed for `None`.
fn kinded(kind: Option<Value>) -> Map<String, Value> {
    let mut given = payload();
    given.remove("kind");
    if let Some(kind) = kind {
        given.insert("kind".into(), kind);
    }
    given
}

#[tokio::test]
async fn settle_refuses_every_payload_outside_its_namespace_as_invalid() {
    let huge = json!("x".repeat(super::rotation::MAX_RECORD_BYTES));
    let cases = [
        ("missing", kinded(None), InvalidPayload::KindMissing),
        (
            "null",
            kinded(Some(Value::Null)),
            InvalidPayload::KindMissing,
        ),
        (
            "number",
            kinded(Some(json!(7))),
            InvalidPayload::KindNotString,
        ),
        (
            "plain",
            kinded(Some(json!("save"))),
            InvalidPayload::KindNotPrefixed,
        ),
        (
            "bare prefix",
            kinded(Some(json!("settle."))),
            InvalidPayload::KindNotPrefixed,
        ),
        (
            "oversize",
            {
                let mut p = payload();
                p.insert("bulk".into(), huge);
                p
            },
            InvalidPayload::Oversized,
        ),
    ];
    for (case, given, want) in cases {
        // GIVEN: a live logger, between two prefixed settles that land
        let dir = crate::test_dir_keep::kept_tempdir();
        let (path, l) = opened(&dir);
        let own = l.log_id();
        assert!(
            l.settle(&own, "w-0", Role::Outcome, payload())
                .await
                .is_ok()
        );
        let before = on_disk(&path);

        // WHEN: it is settled
        let got = l.settle(&own, "w-1", Role::Outcome, given).await;

        // THEN: Invalid by the rule that refused it, nothing appended, and
        // the next prefixed settle lands
        assert!(
            matches!(got, Err(Unsettled::Invalid(r)) if r == want),
            "{case}: {got:?}"
        );
        assert!(on_disk(&path) == before, "{case}");
        assert!(
            l.settle(&own, "w-2", Role::Outcome, payload())
                .await
                .is_ok(),
            "{case}"
        );
        assert_eq!(records_of(&path, "w-2").len(), 1, "{case}");
    }
}

// Readers subscribe only in a build with the web UI.
#[cfg(feature = "webui")]
#[tokio::test]
async fn a_settle_record_reaches_only_readers_of_its_settle_kind() {
    // GIVEN: readers of a plain kind, of "save", of `settle.save` and of
    // another plain kind
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_, l) = opened(&dir);
    let told: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    for kind in ["config_note", "save", SETTLE_SAVE, "restore"] {
        let (sink, name) = (Arc::clone(&told), kind.to_string());
        let reader = move |_: &Map<String, Value>, _: &str, _: u64| {
            sink.lock().unwrap().push(name.clone());
        };
        l.subscribe(kind, Arc::new(reader));
    }

    // WHEN: a save intent is settled
    let role = Role::Intent(IntentKind::Save);
    // An intent's row (step 3 section 2): `kind`, and no `intent_counter`.
    let mut intent = payload();
    intent.retain(|k, _| k == "kind");
    let got = l.settle(&l.log_id(), "w-1", role, intent).await;

    // THEN: only the `settle.save` reader is told, once
    assert!(got.is_ok(), "{got:?}");
    assert_eq!(*told.lock().unwrap(), [SETTLE_SAVE]);
}

#[test]
fn no_plain_append_may_write_a_settle_kind() {
    for entry in ["append_event", "append_event_synced", "attributed"] {
        // GIVEN: a log, and a plain-kind append through the same entry
        // before and after
        let dir = crate::test_dir_keep::kept_tempdir();
        let (path, l) = opened(&dir);
        let append = |kind: &str| {
            let mut fields = Map::new();
            fields.insert("kind".into(), kind.into());
            let envelope = AuditEnvelope::gateway();
            match entry {
                "append_event" => l.append_event(fields, &envelope).map(drop),
                "append_event_synced" => l.append_event_synced(fields, &envelope).map(drop),
                _ => l.log_invocation_attributed(
                    CorrelationKey {
                        id: "t",
                        source: CorrelationSource::TraceId,
                    },
                    &envelope,
                    InvocationTarget::meta("alpha", "read"),
                    "sha256:req",
                    Some("sha256:resp"),
                    fields,
                    None,
                ),
            }
        };
        assert!(append("save").is_ok(), "{entry}");
        let before = on_disk(&path);

        // WHEN: the record names a settle kind
        let refused = append(SETTLE_SAVE);

        // THEN: refused, nothing appended; the next plain append lands
        assert!(refused.is_err(), "{entry}");
        assert!(on_disk(&path) == before, "{entry}");
        assert!(append("save").is_ok(), "{entry}");
    }
}
