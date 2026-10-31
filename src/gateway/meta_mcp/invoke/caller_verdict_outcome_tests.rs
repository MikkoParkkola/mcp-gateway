// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 rows O3, O5, O6, E5a and E5b (s2-t0 section E, s2-d3 E5): the
//! account-outcome pre-pass reads custody at most once per account per
//! request, never outside a request, never for an external account, and not
//! at all when this request already carries a clean resolution. Custody is
//! real; only its reads are counted.

use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::account_resolver_fixture::custody_with;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};
use crate::gateway::meta_mcp::account_rest_fixture::{external, installed_gateway};
use crate::gateway::meta_mcp::visible::{self, memo::AccountOutcome, memo::Carried};
use crate::identity_propagation::{CallerProof, CallerProvenance};

const TOOL: &str = "read";

/// The sole operator, as the router fixtures configure it.
fn sole_operator() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(api_key_digest_spec(b"sole-operator-key")),
            expires_at: None,
            name: "operator".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        single_user: true,
        ..AuthConfig::default()
    }
}

/// The operator's proof: a validated credential on a single-user gateway.
fn operator() -> CallerProof<'static> {
    CallerProof::new(None, CallerProvenance::Credential)
}

fn connected() -> (DirectAccountGateway, MetaMcp) {
    let mut gateway = DirectAccountGateway::new(sole_operator(), &Binding::Connected);
    let meta = gateway.take_meta();
    (gateway, meta)
}

/// Run `body` inside one request's memo.
async fn in_request<F: std::future::Future>(body: F) -> F::Output {
    visible::memo::with_visibility_memo(body).await
}

/// Carry a real resolution for `(BACKEND, TOOL)`, as the caller verdict
/// does, with `fill_error` as given.
async fn carry(meta: &MetaMcp, fill_error: Option<crate::Error>) {
    let backend = meta.backends.for_test().get(BACKEND).expect("the backend");
    let resolved = meta
        .resolve_dispatch((BACKEND, TOOL), Some(&backend), operator(), None)
        .await
        .expect("premise: the operator's live grant resolves");
    visible::memo::carry_dispatch(
        BACKEND,
        TOOL,
        Carried {
            backend,
            resolved,
            fill_error,
        },
    );
}

/// O3: two fills in one request read custody once (M23).
#[tokio::test]
async fn o3_two_fills_in_one_request_read_custody_once() {
    let (gateway, meta) = connected();
    let account = meta
        .target_account(&meta.unscoped_for_test(), BACKEND, TOOL)
        .expect("a managed account");
    in_request(async {
        let before = gateway.resolves();
        meta.fill_account_outcomes(
            &meta.unscoped_for_test(),
            &[(BACKEND, TOOL)],
            operator(),
            crate::gateway::meta_mcp::account_outcome::AccountWrites::All,
        )
        .await;
        meta.fill_account_outcomes(
            &meta.unscoped_for_test(),
            &[(BACKEND, TOOL), (BACKEND, TOOL)],
            operator(),
            crate::gateway::meta_mcp::account_outcome::AccountWrites::All,
        )
        .await;
        assert_eq!(gateway.resolves() - before, 1, "O3: one custody read");
        assert_eq!(
            visible::memo::account_outcome(BACKEND, &account),
            Some(AccountOutcome::Live)
        );
    })
    .await;
}

/// O6: with no request memo open, nothing is judged and nothing is kept
/// (M26: a fresh judgement outside a memo).
#[tokio::test]
async fn o6_outside_a_request_no_outcome_is_judged_or_kept() {
    let (gateway, meta) = connected();
    let account = meta
        .target_account(&meta.unscoped_for_test(), BACKEND, TOOL)
        .expect("a managed account");
    let before = gateway.resolves();
    assert_eq!(visible::memo::account_outcome(BACKEND, &account), None);
    assert_eq!(gateway.resolves(), before, "O6: no custody read");
}

/// O5: an external account has no vault, so its view is unjudged and
/// custody is never read (M25). Installed by the production installer.
#[tokio::test]
async fn o5_an_external_account_is_unjudged_with_no_custody_read() {
    let custody = custody_with(&[]);
    let (_log, _meta, registry) =
        installed_gateway(&[("partner", external("partner"))], &custody.installed());
    let view = registry
        .view_binding_classified("partner", operator())
        .await;
    assert!(
        view.is_none(),
        "O5: an external account is unjudged: {view:?}"
    );
    assert_eq!(custody.resolves(), 0, "O5: no custody read");
}

/// E5a: a clean resolution this request carries proves the account live; the
/// pre-pass reads custody no further (mutant: the carried proof ignored).
#[tokio::test]
async fn e5a_a_clean_carried_resolution_is_reused_as_live() {
    let (gateway, meta) = connected();
    let account = meta
        .target_account(&meta.unscoped_for_test(), BACKEND, TOOL)
        .expect("a managed account");
    in_request(async {
        carry(&meta, None).await;
        let before = gateway.resolves();
        meta.fill_account_outcomes(
            &meta.unscoped_for_test(),
            &[(BACKEND, TOOL)],
            operator(),
            crate::gateway::meta_mcp::account_outcome::AccountWrites::All,
        )
        .await;
        assert_eq!(gateway.resolves() - before, 0, "E5a: no second read");
        assert_eq!(
            visible::memo::account_outcome(BACKEND, &account),
            Some(AccountOutcome::Live)
        );
    })
    .await;
}

/// E5b: a carried resolution whose fill failed proves nothing (E4); the
/// account is judged by its own read (mutant: `fill_error` counted as proof).
#[tokio::test]
async fn e5b_a_carried_resolution_whose_fill_failed_is_read_again() {
    let (gateway, meta) = connected();
    let account = meta
        .target_account(&meta.unscoped_for_test(), BACKEND, TOOL)
        .expect("a managed account");
    in_request(async {
        carry(&meta, Some(crate::Error::json_rpc(-32603, "fill failed"))).await;
        let before = gateway.resolves();
        meta.fill_account_outcomes(
            &meta.unscoped_for_test(),
            &[(BACKEND, TOOL)],
            operator(),
            crate::gateway::meta_mcp::account_outcome::AccountWrites::All,
        )
        .await;
        assert_eq!(
            gateway.resolves() - before,
            1,
            "E5b: judged by its own read"
        );
        assert_eq!(
            visible::memo::account_outcome(BACKEND, &account),
            Some(AccountOutcome::Live)
        );
    })
    .await;
}

/// A resolution whose fill already failed in this request is answered by the
/// gateway itself, before the backend (the verdict's carried fill failure):
/// the invocation is marked refused before its backend, so a task never takes
/// that answer for the backend's, and the backend is never asked.
#[tokio::test]
async fn a_carried_fill_failure_is_refused_before_the_backend() {
    use crate::gateway::STDIO_CREDENTIAL_PRINCIPAL;
    use crate::gateway::meta_mcp::account_resolver_fixture::caller_as;
    use crate::gateway::meta_mcp::dispatch_log::PreSend;
    use crate::gateway::server::account_bindings::ServeMode;
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), &Binding::Connected);
    let meta = gateway.take_meta();
    let caller = caller_as(None, Some(STDIO_CREDENTIAL_PRINCIPAL));
    let args =
        serde_json::json!({"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}});
    // Boxed: the invocation future is large (clippy::large_futures).
    let invoked = Box::pin(in_request(async {
        carry(&meta, Some(crate::Error::json_rpc(-32603, "fill failed"))).await;
        meta.invoke_tool_sourced(&args, None, &caller, "trace-fill".to_owned())
            .await
    }))
    .await;
    // Premise: the carried fill failure is the answer, a result the gateway
    // wrote, not an earlier refusal's error.
    let answer = match &invoked.outcome {
        Ok(super::super::SourcedOutcome::Live((value, _, _))) => value.clone(),
        Ok(super::super::SourcedOutcome::Stored(_)) => panic!("premise: a stored answer"),
        Err(error) => panic!("premise: refused earlier, not by the carried fill: {error}"),
    };
    assert_eq!(
        answer.get("isError"),
        Some(&serde_json::json!(true)),
        "{answer}"
    );
    assert_eq!(
        invoked.pre_send,
        PreSend::Refused,
        "the gateway answered the failed fill"
    );
}
