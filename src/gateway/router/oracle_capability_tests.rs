// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 rows on the capability backend (test plan v3, reasons admin rule
//! and grant): a capability the caller may not reach answers exactly as the
//! same name where the capability backend defines no such capability, on
//! `/mcp` `gateway_invoke` and `gateway_execute`, clean or tripping.
//!
//! The same name across two fixtures (v3 item 2): the withheld twin's
//! capability backend defines it (admin rule: it registers an external
//! callback and the caller is not admin; grant: it is personal and no grant
//! names the caller); the absent twin's capability backend defines nothing.
//! The caller is `k-std` in both.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture_firewalled_built, send};
use crate::capability::{CapabilityBackend, CapabilityExecutor};

/// The capability backend's name, and the capability every row calls.
const CAPS: &str = "caps";
const CAP: &str = "hook_or_day";

/// Why the withheld twin's caller may not reach [`CAP`].
#[derive(Clone, Copy, Debug)]
enum Reason {
    /// It registers a caller-supplied address with a third party: admin only.
    Admin,
    /// It is personal and no grant names the caller.
    Grant,
}

/// [`CAP`]'s definition for `reason`. Its endpoint is never reached: every
/// row asserts the withheld call is not sent.
fn definition(reason: Reason) -> String {
    let metadata = match reason {
        Reason::Admin => {
            "  exposure: public\n  read_only: false\n  registers_external_callback: true\n"
        }
        Reason::Grant => {
            "  exposure: personal\n  read_only: true\n  identity_owner:\n    authority: api_key\n    subject: alice\n"
        }
    };
    format!(
        "name: {CAP}\n\
         description: A fixture capability\n\
         metadata:\n{metadata}\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: http://127.0.0.1:9\n\
         \x20     path: /x\n\
         \x20     method: POST\n"
    )
}

/// A capability backend defining [`CAP`] (withheld twin) or nothing.
fn capabilities(reason: Reason, defines: bool) -> Arc<CapabilityBackend> {
    let backend = Arc::new(CapabilityBackend::new(
        CAPS,
        Arc::new(CapabilityExecutor::new()),
    ));
    if defines {
        let parsed = crate::capability::parse_capability(&definition(reason))
            .expect("the fixture capability parses");
        backend
            .register_capability(parsed)
            .expect("the fixture capability registers");
    }
    backend
}

/// Build one twin: firewalled, an empty grant store, the capability backend.
async fn twin(reason: Reason, withheld: bool) -> Fx {
    let caps = capabilities(reason, withheld);
    let fx = fixture_firewalled_built(Answer::Ok, move |meta| {
        let meta = meta.with_identity_grants(
            crate::identity_grants::LocalIdentityGrantStore::from_grants(Vec::new()),
        );
        meta.set_capabilities(caps);
        meta
    })
    .await;
    // Premise (v3 item 2): the withheld twin defines the capability, the
    // absent twin does not.
    let defined = fx
        .state
        .meta_mcp
        .get_capabilities()
        .is_some_and(|cap| cap.has_capability(CAP));
    assert_eq!(defined, withheld, "premise ({reason:?}): defined={defined}");
    fx
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Invoke,
    Execute,
}

async fn call(fx: &Fx, entry: Entry, args: Value) -> (StatusCode, Value) {
    let params = match entry {
        Entry::Invoke => json!({"name": "gateway_invoke",
            "arguments": {"server": CAPS, "tool": CAP, "arguments": args}}),
        Entry::Execute => json!({"name": "gateway_execute", "arguments": {"chain": [
            {"tool": format!("{CAPS}:{CAP}"), "arguments": args}
        ]}}),
    };
    let (status, mut body) = send(fx, "/mcp", "k-std", "tools/call", params, None).await;
    if let Some(obj) = body.as_object_mut() {
        obj.remove("id");
    }
    (status, body)
}

/// ORACLE.2, admin rule and grant: the withheld capability answers exactly as
/// the undefined one, clean or tripping. RED on base (403 admin refusal /
/// -32004 grant refusal vs `ToolNotFound`).
#[tokio::test]
async fn oracle2_capability_reasons_answer_as_the_undefined_name() {
    let cmd = [";", " rm", " -rf", " / "].concat();
    let tripping = json!({ "cmd": cmd });
    let mut cells = Vec::new();
    for reason in [Reason::Admin, Reason::Grant] {
        for entry in [Entry::Invoke, Entry::Execute] {
            for (label, args) in [("clean", json!({})), ("tripping", tripping.clone())] {
                let withheld = call(&twin(reason, true).await, entry, args.clone()).await;
                let absent = call(&twin(reason, false).await, entry, args).await;
                if withheld != absent {
                    cells.push(format!(
                        "{reason:?} {entry:?}/{label}: withheld {} {} vs absent {} {}",
                        withheld.0, withheld.1, absent.0, absent.1
                    ));
                }
            }
        }
    }
    assert!(
        cells.is_empty(),
        "ORACLE.2 capability:\n{}",
        cells.join("\n")
    );
}

/// MIK-8361 A5 ruling C, as measured (2026-10-12): a withheld capability
/// writes exactly as many invocation records as its undefined twin, which is
/// none, as a `ToolNotFound` result is not an invocation record; its refusal
/// stays in the grant decision record. Pins the parity both ways.
#[tokio::test]
async fn c_a_withheld_capability_writes_one_invocation_record_as_the_undefined_one() {
    let mut cells = Vec::new();
    for reason in [Reason::Admin, Reason::Grant] {
        let mut counts = Vec::new();
        for withheld in [true, false] {
            let audit = tempfile::NamedTempFile::new().expect("tempfile");
            let log = super::r2_identity_keys_tests::transparency_logger(&audit);
            let caps = capabilities(reason, withheld);
            let fx = fixture_firewalled_built(Answer::Ok, move |meta| {
                let mut meta = meta.with_identity_grants(
                    crate::identity_grants::LocalIdentityGrantStore::from_grants(Vec::new()),
                );
                meta.set_capabilities(caps);
                meta.enable_transparency_log(log);
                meta
            })
            .await;
            call(&fx, Entry::Invoke, json!({})).await;
            let records = std::fs::read_to_string(audit.path())
                .unwrap_or_default()
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|entry| entry.get("request_hash").is_some())
                .count();
            counts.push(records);
        }
        if counts[0] != counts[1] {
            cells.push(format!(
                "{reason:?}: invocation records withheld {} vs undefined {}",
                counts[0], counts[1]
            ));
        }
    }
    assert!(cells.is_empty(), "C:\n{}", cells.join("\n"));
}

/// MIK-8361 review (gpt F4, disputed by the second seat): during an audit
/// outage under fail-closed, a capability withheld by its grant answers as
/// the undefined one does, so the grant decision's write cannot tell them
/// apart.
#[tokio::test]
async fn f4_an_audit_outage_answers_a_withheld_capability_as_the_undefined_one() {
    let mut answers = Vec::new();
    for withheld in [true, false] {
        let audit = tempfile::NamedTempFile::new().expect("tempfile");
        let log = Arc::new(
            crate::security::TransparencyLogger::open(Arc::new(
                crate::security::TransparencyLogConfig {
                    enabled: true,
                    path: audit.path().to_string_lossy().to_string(),
                    key_id: "f4".to_string(),
                    ..crate::security::TransparencyLogConfig::default()
                },
            ))
            .expect("open log")
            .with_failure_policy(crate::security::audit::AuditFailurePolicy::FailClosed),
        );
        log.set_append_failure_for_test(true);
        let caps = capabilities(Reason::Grant, withheld);
        let meta_log = Arc::clone(&log);
        let fx = fixture_firewalled_built(Answer::Ok, move |meta| {
            let mut meta = meta.with_identity_grants(
                crate::identity_grants::LocalIdentityGrantStore::from_grants(Vec::new()),
            );
            meta.set_capabilities(caps);
            meta.enable_transparency_log(meta_log);
            meta
        })
        .await;
        answers.push(call(&fx, Entry::Invoke, json!({})).await);
    }
    assert_eq!(
        answers[0], answers[1],
        "an audit outage tells the withheld capability from the undefined one"
    );
}
