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

use crate::security::transparency_log::temp::TempLog;
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
    /// The calling key's own scope denies it by name (`k-deny-cap`).
    Scope,
    /// The active routing profile denies it by name.
    Profile,
}

/// [`CAP`]'s definition for `reason`. Its endpoint is a closed local port: a
/// withheld call that were sent would answer a transport error, never the
/// undefined twin's `ToolNotFound`, so every twin row fails on a send.
fn definition(reason: Reason) -> String {
    let metadata = match reason {
        Reason::Admin => {
            "  exposure: public\n  read_only: false\n  registers_external_callback: true\n"
        }
        Reason::Grant => {
            "  exposure: personal\n  read_only: true\n  identity_owner:\n    authority: api_key\n    subject: alice\n"
        }
        // Reachable by definition: only the key or the profile excludes it.
        Reason::Scope | Reason::Profile => "  exposure: public\n  read_only: true\n",
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
        if matches!(reason, Reason::Profile) {
            let mut profiles = std::collections::HashMap::new();
            profiles.insert(
                "restricted".to_string(),
                crate::routing_profile::RoutingProfileConfig {
                    description: "MIK-8361 capability profile twin".to_string(),
                    deny_tools: Some(vec![CAP.to_string()]),
                    ..Default::default()
                },
            );
            let registry =
                crate::routing_profile::ProfileRegistry::from_config(&profiles, "restricted");
            return meta.with_profile_registry(registry);
        }
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
    call_as(fx, "k-std", entry, args).await
}

async fn call_as(fx: &Fx, key: &str, entry: Entry, args: Value) -> (StatusCode, Value) {
    let params = match entry {
        Entry::Invoke => json!({"name": "gateway_invoke",
            "arguments": {"server": CAPS, "tool": CAP, "arguments": args}}),
        Entry::Execute => json!({"name": "gateway_execute", "arguments": {"chain": [
            {"tool": format!("{CAPS}:{CAP}"), "arguments": args}
        ]}}),
    };
    let (status, mut body) = send(fx, "/mcp", key, "tools/call", params, None).await;
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

/// ORACLE.2, key scope and routing profile (lead, 2026-10-15): a defined
/// capability the caller's own key scope, or the active profile, excludes by
/// name answers byte for byte as the undefined capability under the same key.
/// Both are answered at the route stage, as the undefined capability is: a
/// key-scope refusal by the route authorize (any route refusal of a
/// capability answers `ToolNotFound`), a profile refusal by
/// `profile_withheld_capability`.
#[tokio::test]
async fn oracle2_capability_scope_and_profile_answer_as_the_undefined_name() {
    let mut cells = Vec::new();
    for (reason, key) in [(Reason::Scope, "k-deny-cap"), (Reason::Profile, "k-std")] {
        for entry in [Entry::Invoke, Entry::Execute] {
            let defined = call_as(&twin(reason, true).await, key, entry, json!({})).await;
            let undefined = call_as(&twin(reason, false).await, key, entry, json!({})).await;
            if defined.1.get("error").is_none() && defined.1.pointer("/result/isError").is_none() {
                cells.push(format!(
                    "{reason:?} {entry:?}: premise: not refused: {}",
                    defined.1
                ));
            }
            if defined != undefined {
                cells.push(format!(
                    "{reason:?} {entry:?}: defined {} {} vs undefined {} {}",
                    defined.0, defined.1, undefined.0, undefined.1
                ));
            }
        }
    }
    assert!(
        cells.is_empty(),
        "ORACLE.2 capability scope/profile:\n{}",
        cells.join("\n")
    );
}

/// MIK-8361 A5 ruling C, as measured (2026-10-12): a withheld capability
/// writes exactly as many invocation records as its undefined twin, which is
/// none, as a `ToolNotFound` result is not an invocation record; its refusal
/// stays in the grant decision record. Pins the parity both ways.
#[tokio::test]
async fn c_a_withheld_capability_writes_the_undefined_ones_invocation_records() {
    let mut cells = Vec::new();
    for reason in [Reason::Admin, Reason::Grant] {
        let mut counts = Vec::new();
        for withheld in [true, false] {
            let audit = TempLog::new();
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
            let records = invocation_records(&audit);
            assert_the_log_records_a_dispatch(&fx, &audit, records).await;
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

/// MIK-8361, profile twin (condition 2): a defined capability the active
/// profile excludes answers as the undefined one, and its audit trail is
/// exactly what it was before the answer was mapped: the profile refusal
/// (then a 400 from admission) wrote no invocation record, so none is written
/// now. Measured on the unmapped code, 2026-10-15.
#[tokio::test]
async fn a_profile_refused_capability_keeps_its_audit_trail() {
    let audit = TempLog::new();
    let log = super::r2_identity_keys_tests::transparency_logger(&audit);
    let caps = capabilities(Reason::Profile, true);
    let fx = fixture_firewalled_built(Answer::Ok, move |meta| {
        let mut meta = meta.with_identity_grants(
            crate::identity_grants::LocalIdentityGrantStore::from_grants(Vec::new()),
        );
        meta.set_capabilities(caps);
        meta.enable_transparency_log(log);
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "restricted".to_string(),
            crate::routing_profile::RoutingProfileConfig {
                description: "MIK-8361 capability profile record".to_string(),
                deny_tools: Some(vec![CAP.to_string()]),
                ..Default::default()
            },
        );
        meta.with_profile_registry(crate::routing_profile::ProfileRegistry::from_config(
            &profiles,
            "restricted",
        ))
    })
    .await;
    call(&fx, Entry::Invoke, json!({})).await;
    let records = invocation_records(&audit);
    assert_eq!(records, 0, "no invocation record, as before");
    assert_the_log_records_a_dispatch(&fx, &audit, records).await;
}

/// The invocation records in `audit`. A log that cannot be read fails the
/// row; it never reads as none.
fn invocation_records(audit: &TempLog) -> usize {
    std::fs::read_to_string(audit.path())
        .expect("the audit log is readable")
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry.get("request_hash").is_some())
        .count()
}

/// #3872 review (FIX 3), the positive control: in the same fixture, a
/// visible backend tool that is dispatched writes at least one invocation
/// record, so the counts above are measured on a log that records.
async fn assert_the_log_records_a_dispatch(fx: &Fx, audit: &TempLog, before: usize) {
    let visible = json!({"name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}}});
    send(fx, "/mcp", "k-std", "tools/call", visible, None).await;
    assert!(
        invocation_records(audit) > before,
        "control: a dispatched visible call writes an invocation record"
    );
}

/// The cells where the defined and the undefined capability of `reason`
/// answer apart, or where their shared answer does not contain `expect`,
/// on both entries, with the capability server killed or not.
async fn kill_twin_cells(reason: Reason, killed: bool, expect: &str) -> Vec<String> {
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Execute] {
        let (defined, undefined) = (twin(reason, true).await, twin(reason, false).await);
        if killed {
            defined.state.meta_mcp.kill_switch().kill(CAPS);
            undefined.state.meta_mcp.kill_switch().kill(CAPS);
        }
        let (d, u) = (
            call(&defined, entry, json!({})).await,
            call(&undefined, entry, json!({})).await,
        );
        if d != u || !d.1.to_string().contains(expect) {
            cells.push(format!(
                "{reason:?} {entry:?} killed={killed}: defined {} {} vs undefined {} {}",
                d.0, d.1, u.0, u.1
            ));
        }
    }
    cells
}

const KILLED: &str = "currently disabled by operator kill switch";

/// Kill switch, entitled caller: a documentation row, not an oracle (lead
/// ruling 2026-10-15). A caller the definition admits already knows the
/// capability exists, so the defined name meeting the kill switch while the
/// undefined one answers not found reveals nothing; backends differ the same
/// way. Making them match would move the answer and drop an audit record
/// for no gain. Pins today's answers, so a change to either is deliberate.
#[tokio::test]
async fn a_killed_capability_server_answers_an_entitled_caller_as_today() {
    for entry in [Entry::Invoke, Entry::Execute] {
        let (defined, undefined) = (
            twin(Reason::Scope, true).await,
            twin(Reason::Scope, false).await,
        );
        defined.state.meta_mcp.kill_switch().kill(CAPS);
        undefined.state.meta_mcp.kill_switch().kill(CAPS);
        let (d, u) = (
            call(&defined, entry, json!({})).await,
            call(&undefined, entry, json!({})).await,
        );
        assert!(
            d.1.to_string().contains(KILLED),
            "{entry:?}: the defined capability meets the kill switch: {} {}",
            d.0,
            d.1
        );
        assert_eq!(
            u,
            (
                StatusCode::OK,
                json!({"error": {"code": -32001, "message": format!("Tool not found: '{CAP}'")},
                    "jsonrpc": "2.0"})
            ),
            "{entry:?}: the undefined capability answers not found"
        );
    }
}

/// Kill switch, caller not entitled: the oracle. The admin rule or the
/// grant refuses the defined name before the kill check and answers it as
/// the undefined one, so a caller who may not reach the capability cannot
/// tell the two apart, the server killed or not.
#[tokio::test]
async fn a_killed_capability_server_answers_unentitled_twins_alike() {
    let mut cells = Vec::new();
    for reason in [Reason::Admin, Reason::Grant] {
        for killed in [true, false] {
            cells.extend(kill_twin_cells(reason, killed, "Tool not found").await);
        }
    }
    assert!(
        cells.is_empty(),
        "kill switch, unentitled:\n{}",
        cells.join("\n")
    );
}

/// MIK-8361 review (gpt F4, disputed by the second seat): during an audit
/// outage under fail-closed, a capability withheld by its grant answers as
/// the undefined one does, so the grant decision's write cannot tell them
/// apart.
#[tokio::test]
async fn f4_an_audit_outage_answers_a_withheld_capability_as_the_undefined_one() {
    let mut answers = Vec::new();
    for withheld in [true, false] {
        let audit = TempLog::new();
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

/// Profile × capability, condition 1 (lead ruling 2026-10-15): the mapping
/// is the defined capability's alone. A backend tool the profile excludes
/// keeps the answer it had before (measured on the unmapped code,
/// 2026-10-15): the absent-name answer the backend gate gives, as a tool
/// result on `gateway_invoke` and as a failed chain step on `gateway_execute`.
#[tokio::test]
async fn a_profile_refused_backend_tool_keeps_its_answer() {
    let fx = fixture_firewalled_built(Answer::Ok, |meta| {
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "restricted".to_string(),
            crate::routing_profile::RoutingProfileConfig {
                description: "MIK-8361 backend profile row".to_string(),
                deny_tools: Some(vec!["read".to_string()]),
                ..Default::default()
            },
        );
        meta.with_profile_registry(crate::routing_profile::ProfileRegistry::from_config(
            &profiles,
            "restricted",
        ))
    })
    .await;
    let absent = "the backend does not list a tool named `read`";
    let invoke = json!({"name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}}});
    let (status, body) = send(&fx, "/mcp", "k-std", "tools/call", invoke, None).await;
    let text = body["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "invoke: {body}");
    assert!(
        body["result"]["isError"] == json!(true) && text.contains(absent),
        "invoke keeps its answer: {body}"
    );
    let execute = json!({"name": "gateway_execute", "arguments": {"chain": [
        {"tool": "alpha:read", "arguments": {}}
    ]}});
    let (status, body) = send(&fx, "/mcp", "k-std", "tools/call", execute, None).await;
    assert_eq!(status, StatusCode::OK, "execute: {body}");
    assert_eq!(
        body["error"],
        json!({"code": -32603, "message": format!(
            "JSON-RPC error -32603: Chain step 0 (alpha:read) failed: {absent}"
        )}),
        "execute keeps its answer: {body}"
    );
}

/// MIK-8387 PR-B C2, a guard (test plan v2 §5): a key whose scope excludes
/// the capability backend, calling a tool it does not define there, gets the
/// answer it gets for a server no registry knows, on `/mcp` `gateway_invoke`.
/// Green on the tip: S3 answers the out-of-scope name as absent
/// (`gate.rs` `gate_answer`) before the capability arm. Mutant C2-m: S3 moved
/// below the capability arm exposes the scope refusal instead.
#[tokio::test]
async fn c2_an_out_of_scope_capability_backend_answers_as_an_unregistered_server() {
    const NOWHERE: &str = "no_such_server_8387";
    let fx = twin(Reason::Admin, true).await;
    // One cell per tool: the capability backend's defined tool and an
    // undefined one (Gemini review: a defined tool would reach the
    // capability arm if the scope check ever stopped running first).
    for tool in [CAP, "nosuch_8387"] {
        let mut answers = Vec::new();
        for server in [CAPS, NOWHERE] {
            let call = json!({"name": "gateway_invoke",
                "arguments": {"server": server, "tool": tool, "arguments": {}}});
            let (status, mut body) =
                send(&fx, "/mcp", "k-alpha-ghost", "tools/call", call, None).await;
            if let Some(obj) = body.as_object_mut() {
                obj.remove("id");
            }
            answers.push((status, body.to_string().replace(server, "SERVER")));
        }
        assert_eq!(
            answers[0], answers[1],
            "C2 answer changed for `{tool}`: out-of-scope capability backend vs unregistered server"
        );
        // The pinned answer itself: the absent miss naming the tool.
        let (status, body) = &answers[1];
        assert!(
            *status == axum::http::StatusCode::OK
                && body.contains(tool)
                && (body.contains("\"isError\":true") || body.contains("\"error\"")),
            "C2: the answer for `{tool}` is not the absent miss: {status} {body}"
        );
    }
}

/// MIK-8387 PR-B T4 router cell (test plan v2 §5): the router choke point's
/// view answers `absence` exactly as `MetaMcp::scoped` does, for every grant
/// and name, the capability provider included: a grant naming it sees it as
/// registered. Mutant M35: `view_for` passes no capability name.
#[tokio::test]
async fn t4_router_cell_the_choke_point_view_matches_the_meta_view() {
    use crate::gateway::authz::BackendGrant;
    let fx = twin(Reason::Admin, true).await;
    let alpha_caps = ["alpha".to_string(), CAPS.to_string()];
    let alpha_ghost = ["alpha".to_string(), "ghost".to_string()];
    let grants = [
        BackendGrant::Scoped(&alpha_caps),
        BackendGrant::Scoped(&alpha_ghost),
        BackendGrant::Empty,
        BackendGrant::Unscoped,
    ];
    for grant in grants {
        for name in ["alpha", "alpha-pt", "ghost", "nosuch", CAPS] {
            assert_eq!(
                super::backend_choke::view_for(&fx.state, grant).absence(name),
                fx.state.meta_mcp.scoped(grant).absence(name),
                "router cell {name} under {grant:?}"
            );
        }
    }
    assert_eq!(
        super::backend_choke::view_for(&fx.state, BackendGrant::Scoped(&alpha_caps)).absence(CAPS),
        None,
        "router cell {CAPS}: a grant naming the capability provider sees it"
    );
}
