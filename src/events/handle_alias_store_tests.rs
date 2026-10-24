// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 slice 3, store binding (design §13.6, §14.3): the events store
//! records the identity of the key it was written under in
//! `<store_dir>/record-key.id`. An empty store adopts the current key
//! silently. A non-empty store without the file, or naming another key,
//! adopts the current key with exactly one warning, and delivery continues:
//! nothing refuses the start.
//!
//! Contract with the implementation (test plan C1/C2): binding happens inside
//! `EventsHub::start`, before it returns, from `Services.record_key`; each
//! warning is one WARN record, searched whole, so its wording is free.

#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "test code reads the host clock (MIK-8202 AC.14)"
    )
)]
use super::*;

const SIDECAR: &str = "record-key.id";

fn sidecar(dir: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(dir.join(SIDECAR))
        .ok()
        .map(|t| t.trim_end().to_owned())
}

/// Start `hub` with `key` on a current-thread runtime inside a log capture,
/// then run `after` on the same runtime; the WARN records it logged.
fn start_capturing(
    hub: &Arc<EventsHub>,
    key: RecordPrincipalKey,
    after: impl std::future::Future<Output = ()>,
) -> Vec<Value> {
    let records = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            hub.start(services_with(key));
            after.await;
        });
    });
    records
        .into_iter()
        .filter(|r| r["level"] == "WARN")
        .collect()
}

/// WARN records whose whole JSON contains every needle.
fn warnings_naming(warnings: &[Value], needles: &[&str]) -> usize {
    warnings
        .iter()
        .filter(|r| {
            // The field values, not the JSON text: JSON doubles a Windows
            // path's backslashes.
            let text = r["fields"]
                .as_object()
                .map(|fields| {
                    fields
                        .values()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            needles.iter().all(|n| text.contains(n))
        })
        .count()
}

fn store_path(dir: &std::path::Path) -> String {
    dir.to_string_lossy().into_owned()
}

/// A non-empty store: one subscription row (the verified seed).
fn non_empty_hub(dir: &std::path::Path) -> Arc<EventsHub> {
    let config = crate::config::EventsConfig::default();
    hub_at(dir, &config, "p", &url("p"))
}

// S1: an empty store adopts the current key silently.
#[test]
fn s1_an_empty_store_adopts_the_key_without_a_warning() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let warnings = start_capturing(&hub, test_record_key(), async {});
    assert_eq!(
        sidecar(dir.path()),
        Some(test_record_key().identity()),
        "the store records the key"
    );
    assert_eq!(
        warnings_naming(&warnings, &[&store_path(dir.path())]),
        0,
        "silent: {warnings:?}"
    );
}

// S2: a non-empty store without the sidecar (the beta.3 upgrade, or a deleted
// sidecar) adopts the key with exactly one warning naming the store.
#[test]
fn s2_a_non_empty_store_without_the_sidecar_adopts_with_one_warning() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = non_empty_hub(dir.path());
    let warnings = start_capturing(&hub, test_record_key(), async {});
    assert_eq!(sidecar(dir.path()), Some(test_record_key().identity()));
    assert_eq!(
        warnings_naming(&warnings, &[&store_path(dir.path())]),
        1,
        "{warnings:?}"
    );
}

// S3: a non-empty store bound to another key starts anyway, rewrites the
// sidecar to the current key, warns once naming both identities (first 8
// hex) and the store, and delivery continues.
#[test]
fn s3_a_key_mismatch_adopts_the_new_key_with_one_warning_and_delivery_continues() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let hub = non_empty_hub(dir.path());
        hub.runtime
            .services
            .set(Arc::new(services_with(other_key())))
            .ok();
        runtime.block_on(subscribe_at(&hub, "p", &url("p")));
    }
    crate::gateway::test_helpers::write_owner_only(
        dir.path().join(SIDECAR),
        format!("{}\n", other_key().identity()),
    )
    .expect("bind to B");
    let hub = EventsHub::open(&config, dir.path()).expect("reopen");
    hub.register_source(Arc::new(Probe));
    let (current, previous) = (test_record_key().identity(), other_key().identity());
    let fan = Arc::clone(&hub);
    let warnings = start_capturing(&hub, test_record_key(), async move {
        fan.fan_out(&services(), &event("after-rotation")).await;
    });
    assert_eq!(
        sidecar(dir.path()),
        Some(current.clone()),
        "the sidecar names the current key"
    );
    assert_eq!(
        warnings_naming(
            &warnings,
            &[&current[..8], &previous[..8], &store_path(dir.path())]
        ),
        1,
        "one warning naming both identities and the store: {warnings:?}"
    );
    assert_eq!(
        outbox(dir.path()).len(),
        1,
        "delivery continues for the existing subscription"
    );
    let new_alias = alias(&test_record_key(), "p", &url("p"));
    assert_eq!(
        outbox(dir.path())[0]["event_id"],
        json!(fanout::event_id(
            SourceKind::RestWatch,
            "after-rotation",
            &new_alias
        )),
        "the new event is named under the adopted key's alias"
    );
}

// S6 (§14.3): "empty" means no durable events state at all. A store holding
// only verification records, only an outbox record, or only a dead letter is
// non-empty: it adopts with exactly one warning naming the store.
#[test]
fn s6_a_store_with_only_verification_outbox_or_dead_state_is_non_empty() {
    fn clear(dir: &std::path::Path, sub: &str) {
        if let Ok(entries) = std::fs::read_dir(dir.join(sub)) {
            for entry in entries {
                std::fs::remove_file(entry.expect("entry").path()).expect("remove");
            }
        }
    }
    fn files(dir: &std::path::Path, sub: &str) -> usize {
        std::fs::read_dir(dir.join(sub)).map_or(0, |e| {
            e.filter_map(Result::ok)
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .count()
        })
    }
    // Build and check all three stores first, so every setup runs (and is
    // proven) before the first adoption assertion can fail.
    let config = crate::config::EventsConfig::default();
    let mut built = Vec::new();
    for case in ["verified", "outbox", "dead"] {
        let dir = tempfile::tempdir().expect("dir");
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let hub = non_empty_hub(dir.path());
            hub.runtime.services.set(Arc::new(services())).ok();
            if case != "verified" {
                runtime.block_on(async {
                    subscribe_at(&hub, "p", &url("p")).await;
                    hub.fan_out(&services(), &event("only-one-kind")).await;
                });
                assert_eq!(outbox(dir.path()).len(), 1, "{case}: one outbox record");
            }
            if case == "dead" {
                let record: super::outbox::OutboxRecord =
                    serde_json::from_value(outbox(dir.path()).remove(0)).expect("record");
                hub.store
                    .dead_letter(
                        record,
                        super::outbox::DeadReason::Exhausted,
                        chrono::Utc::now(),
                        hub.dead_policy(),
                    )
                    .expect("dead-lettered");
            }
        }
        // Leave only the state the case names.
        clear(dir.path(), "subs");
        if case != "verified" {
            clear(dir.path(), "verified");
        }
        if case == "dead" {
            clear(dir.path(), "outbox");
        }
        let held: Vec<(&str, usize)> = ["subs", "verified", "outbox", "dead"]
            .into_iter()
            .map(|s| (s, files(dir.path(), s)))
            .collect();
        let only = held
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(s, _)| *s)
            .collect::<Vec<_>>();
        assert_eq!(
            only,
            [case],
            "{case}: the store holds only that state: {held:?}"
        );
        built.push((case, dir));
    }
    for (case, dir) in built {
        let hub = EventsHub::open(&config, dir.path()).expect("reopen");
        let warnings = start_capturing(&hub, test_record_key(), async {});
        assert_eq!(
            sidecar(dir.path()),
            Some(test_record_key().identity()),
            "{case}"
        );
        assert_eq!(
            warnings_naming(&warnings, &[&store_path(dir.path())]),
            1,
            "{case}: non-empty, so one warning: {warnings:?}"
        );
    }
}

// S4 (characterization): a matching sidecar is left alone and nothing warns,
// so a normal start is quiet.
#[test]
fn s4_a_matching_sidecar_is_kept_and_nothing_warns() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = non_empty_hub(dir.path());
    let bytes = format!("{}\n", test_record_key().identity());
    crate::gateway::test_helpers::write_owner_only(dir.path().join(SIDECAR), &bytes)
        .expect("bound to A");
    let warnings = start_capturing(&hub, test_record_key(), async {});
    assert_eq!(
        std::fs::read_to_string(dir.path().join(SIDECAR)).expect("kept"),
        bytes
    );
    assert_eq!(
        warnings_naming(&warnings, &[&store_path(dir.path())]),
        0,
        "{warnings:?}"
    );
}

// S5: the adoption warning is one-time; a restart with the same key is quiet.
#[test]
fn s5_the_adoption_warning_is_not_repeated_on_restart() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = non_empty_hub(dir.path());
    let first = start_capturing(&hub, test_record_key(), async {});
    assert_eq!(
        warnings_naming(&first, &[&store_path(dir.path())]),
        1,
        "{first:?}"
    );
    drop(hub);
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("reopen");
    let second = start_capturing(&hub, test_record_key(), async {});
    assert_eq!(
        warnings_naming(&second, &[&store_path(dir.path())]),
        0,
        "{second:?}"
    );
}

// S7 (lead condition 3): the adoption warning names key fingerprints, the
// identity prefix, and never key material: neither key's text, the hex of
// its bytes, nor a full identity.
#[test]
fn s7_the_adoption_warning_names_fingerprints_never_key_material() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    {
        let hub = non_empty_hub(dir.path());
        hub.runtime
            .services
            .set(Arc::new(services_with(other_key())))
            .ok();
    }
    crate::gateway::test_helpers::write_owner_only(
        dir.path().join(SIDECAR),
        format!("{}\n", other_key().identity()),
    )
    .expect("bind to B");
    let hub = EventsHub::open(&config, dir.path()).expect("reopen");
    let warnings = start_capturing(&hub, test_record_key(), async {});
    let (current, previous) = (test_record_key().identity(), other_key().identity());
    assert_eq!(
        warnings_naming(&warnings, &[&current[..8], &previous[..8]]),
        1,
        "premise: the adoption warned: {warnings:?}"
    );
    let text: String = warnings.iter().map(Value::to_string).collect();
    for material in [
        crate::gateway::record_principal::TEST_RECORD_KEY.to_owned(),
        OTHER_KEY.to_owned(),
        hex::encode(crate::gateway::record_principal::TEST_RECORD_KEY),
        hex::encode(OTHER_KEY),
        current,
        previous,
    ] {
        assert!(!text.contains(&material), "key material in {text}");
    }
}
