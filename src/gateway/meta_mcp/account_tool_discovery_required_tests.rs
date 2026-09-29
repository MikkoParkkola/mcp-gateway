// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2326: tool discovery applies the catalogue's `required` rule. A caller
//! whose fetch would not carry its identity gets nothing from a `required`
//! backend: no request, no tool, no shared snapshot.

use serde_json::{Value, json};

use super::direct_bridge::operator_key;
use super::{
    Bind, Descriptors, Dispatches, SEEDED_REVISION, WORK, caller_as, custody_with,
    expected_identity_key_for, external_cfg, gateway_in, grant,
};
use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::server::account_bindings::ServeMode;
use std::sync::Arc;

const REQUIRED: &str = "work-mail";
const OPTIONAL: &str = "open-notes";
const OPERATOR_TOKEN: &str = "synthetic-operator-work-access-5d0c11";

/// One key and `single_user`: the deployment asserts its sole operator.
fn single_user() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(api_key_digest_spec(b"sole-operator-key")),
            expires_at: None,
            name: "operator".to_string(),
            rate_limit: 0,
            backends: Vec::new(),
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        }],
        single_user: true,
        ..AuthConfig::default()
    }
}

/// A single-user gateway with an account-bound (`required`) backend whose
/// operator holds a grant, and with `optional`, a non-required propagation
/// backend beside it.
fn gateway(optional: bool) -> (MetaMcp, Arc<Dispatches>, super::Custody) {
    let custody = custody_with(&[(operator_key(), grant(OPERATOR_TOKEN, u64::MAX))]);
    let mut binds = vec![(REQUIRED, Bind::Account(WORK))];
    if optional {
        let cfg = crate::identity_propagation::IdentityPropagationConfig {
            required: false,
            ..external_cfg()
        };
        binds.push((OPTIONAL, Bind::Propagation(cfg)));
    }
    let (meta, dispatches) = gateway_in(
        &binds,
        &Descriptors::same(&[WORK]),
        &custody.installed(),
        &[expected_identity_key_for(&operator_key(), SEEDED_REVISION)],
        ServeMode::Http,
        single_user(),
    );
    (meta, dispatches, custody)
}

/// Every request that reached a backend (the `required` one is the only one).
fn requests(dispatches: &Dispatches) -> Vec<String> {
    dispatches.all().into_iter().map(|d| d.method).collect()
}

/// Code-mode search for the `required` backend's tools, by server prefix.
async fn code_mode(meta: &MetaMcp, caller: &super::super::MetaMcpCallerContext<'_>) -> Value {
    meta.code_mode_search(&json!({"query": format!("{REQUIRED}:read")}), None, caller)
        .await
        .expect("code-mode search answers")
}

/// The three aggregate tool-discovery answers for `caller`: listing, search
/// and code-mode search. Each test checks the named listing on its own.
async fn discover(
    meta: &MetaMcp,
    caller: &super::super::MetaMcpCallerContext<'_>,
) -> [(&'static str, Value); 3] {
    let listed = meta
        .list_tools(&json!({}), None, caller)
        .await
        .expect("listing answers");
    let found = meta
        .search_tools(&json!({"query": "read"}), None, caller)
        .await
        .expect("search answers");
    [
        ("listed", listed),
        ("search", found),
        ("code mode", code_mode(meta, caller).await),
    ]
}

fn names_backend(listing: &Value, backend: &str) -> bool {
    // A server name as a value (`"work-mail"`) or as a tool prefix (`"work-mail:read"`),
    // anywhere but the echoed request: code mode repeats its `query` back.
    let mut answer = listing.clone();
    if let Some(fields) = answer.as_object_mut() {
        fields.remove("query");
    }
    let text = answer.to_string();
    text.contains(&format!("\"{backend}\"")) || text.contains(&format!("\"{backend}:"))
}

/// THE FAIL-FAST CASE. An anonymous caller on a single-user gateway lists
/// and searches: the `required` backend is absent from every tool-discovery
/// path, naming it answers "not found", and nothing reaches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_caller_gets_no_tools_from_a_required_backend() {
    let (meta, dispatches, _custody) = gateway(false);
    let anonymous = caller_as(None, Some(""));

    let named = meta
        .list_tools(&json!({"server": REQUIRED}), None, &anonymous)
        .await;
    assert!(
        matches!(named, Err(crate::Error::BackendNotFound(ref s)) if s == REQUIRED),
        "a named listing of a required backend must answer not found: {named:?}"
    );
    for (path, answer) in discover(&meta, &anonymous).await {
        assert!(
            !names_backend(&answer, REQUIRED),
            "anonymous {path}: {answer}"
        );
    }
    assert_eq!(
        requests(&dispatches),
        Vec::<String>::new(),
        "nothing may reach it"
    );
}

/// A shared snapshot of the `required` backend, however it got there, is
/// never served to a caller whose fetch would not carry its identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_caller_is_not_served_a_required_backends_shared_snapshot() {
    let (meta, dispatches, _custody) = gateway(false);
    let backend = meta.backends.get(REQUIRED).expect("registered");
    let seeded = backend
        .get_tools_for_binding(None, &[])
        .await
        .expect("the shared slot fills");
    assert!(
        !seeded.is_empty(),
        "premise: the shared snapshot holds the tool"
    );
    let seeding = requests(&dispatches);
    let anonymous = caller_as(None, Some(""));
    for (path, answer) in discover(&meta, &anonymous).await {
        assert!(
            !names_backend(&answer, REQUIRED),
            "anonymous {path}: {answer}"
        );
    }
    assert_eq!(
        requests(&dispatches),
        seeding,
        "discovery must not contact the backend beyond the seeding fetch"
    );
}

/// No regression: a non-required backend keeps its shared-catalogue view for
/// the same anonymous caller, and the sole operator still sees the required
/// backend on every tool-discovery path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn optional_backend_and_operator_views_are_unchanged() {
    let (meta, _dispatches, _custody) = gateway(true);
    let anonymous = caller_as(None, Some(""));
    let listed = meta
        .list_tools(&json!({"server": OPTIONAL}), None, &anonymous)
        .await
        .expect("a non-required backend lists for an anonymous caller");
    assert!(names_backend(&listed, OPTIONAL), "listed: {listed}");

    let operator = caller_as(None, Some("operator"));
    let named = meta
        .list_tools(&json!({"server": REQUIRED}), None, &operator)
        .await
        .expect("the sole operator lists the account backend");
    assert!(names_backend(&named, REQUIRED), "operator named: {named}");
    for (path, answer) in discover(&meta, &operator).await {
        assert!(
            names_backend(&answer, REQUIRED),
            "operator {path}: {answer}"
        );
    }
}
