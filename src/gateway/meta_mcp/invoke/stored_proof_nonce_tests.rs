// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8406 G1: a walk that minted keeps the signed nonce spent. The site-5
//! walk runs directly, as the route stage's refusal exit runs it, then that
//! exit's settle, over `[EXTERNAL_BACKEND, BACKEND]`: the external target is
//! the one the route stage never carries, so the walk mints it fresh (d4
//! §13.3), and that spends the witness; the managed `BACKEND` is then busy,
//! and its refund ask cannot give the nonce back. A managed target always
//! arrives carried on a real request, so it is not the fresh one here.

use serde_json::{Value, json};

use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, CapabilityAccount, DirectAccountGateway, EXTERNAL_BACKEND, Second,
};
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::gateway::meta_mcp::refund_witness::RefundWitness;
use crate::gateway::meta_mcp::signing::{NONCE_META, SigningInvocationContext, SigningScope};
use crate::identity_propagation::CallerProof;
use crate::protocol::RequestId;

const TOOL: &str = "read";

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
        }],
        single_user: true,
        ..AuthConfig::default()
    }
}

/// The managed `BACKEND` beside the external `EXTERNAL_BACKEND`, with
/// message signing armed.
fn signed_two_accounts() -> (DirectAccountGateway, MetaMcp) {
    let mut gateway =
        DirectAccountGateway::with_second(sole_operator(), &Binding::Connected, Second::External);
    let mut meta = gateway.take_meta();
    let tool: crate::protocol::Tool =
        serde_json::from_value(json!({"name": TOOL, "inputSchema": {"type": "object"}}))
            .expect("a tool");
    for server in [BACKEND, EXTERNAL_BACKEND] {
        meta.backends
            .for_test()
            .get(server)
            .expect("the backend")
            .store_shared_tools_for_test(vec![tool.clone()]);
    }
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"stored-proof-nonce-key-0123456789abc".to_vec(),
            None,
            "g1".into(),
        ),
        std::time::Duration::from_secs(300),
        true,
    );
    (gateway, meta)
}

/// A hardened `tools/call` of `name` under `nonce`, captured as the adapters
/// capture it.
fn captured(name: &str, nonce: &str) -> (SigningInvocationContext, Value) {
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": {}, "_meta": {(NONCE_META): nonce}}});
    let context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    let arguments = request["params"]["arguments"].clone();
    (context, arguments)
}

/// Whether `nonce` is still free: a later call presenting it is admitted.
fn nonce_is_free(meta: &MetaMcp, nonce: &str) -> bool {
    let caller = ctx(&AllowAll);
    let (mut later, arguments) = captured("gateway_list_servers", nonce);
    meta.prepare_signing_for_call(
        &mut later,
        "gateway_list_servers",
        &arguments,
        None,
        &caller,
    )
    .is_ok()
        && !later.awaits_admission()
}

/// Carry `caller`'s real resolution for `(server, TOOL)`, as a route stage
/// that judged it would leave it.
async fn carry(
    meta: &MetaMcp,
    server: &str,
    caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
) {
    let backend = meta.backends.for_test().get(server).expect("the backend");
    let resolved = meta
        .resolve_dispatch(
            (server, TOOL),
            Some(&backend),
            CallerProof::new(caller.verified_identity, caller.provenance()),
            caller.verified_identity,
        )
        .await
        .expect("premise: the external target resolves for the caller");
    crate::gateway::meta_mcp::visible::carry_dispatch(
        server,
        TOOL,
        crate::gateway::meta_mcp::visible::Carried {
            backend,
            resolved,
            fill_error: None,
        },
    );
}

/// How the walk meets the first account.
#[derive(Clone, Copy)]
enum First {
    /// Nothing carried: the walk resolves it fresh, and it mints.
    Fresh,
    /// The route stage's resolution carried into the walk (a control: a
    /// carried proof spends the witness on its own).
    Carried,
}

/// The plan walk over `[EXTERNAL_BACKEND, BACKEND]` for a verified caller
/// under `nonce`, admitted and holding the witness as admission leaves it,
/// with custody failing busy (the managed account only); then the refusal
/// exit's settle. Answers the walk's answer and whether the nonce came back.
async fn walk_then_settle(
    gateway: &DirectAccountGateway,
    meta: &MetaMcp,
    nonce: &str,
    first: First,
) -> (Option<crate::protocol::JsonRpcResponse>, bool) {
    let alice = CapabilityAccount::alice();
    let mut caller = ctx(&AllowAll);
    caller.verified_identity = Some(&alice);
    let (mut signing, arguments) = captured("gateway_execute", nonce);
    meta.prepare_signing_for_call(&mut signing, "gateway_execute", &arguments, None, &caller)
        .expect("the nonce is admitted");
    assert!(
        !signing.awaits_admission(),
        "premise: the nonce was admitted"
    );
    signing.keep_witness(RefundWitness::at_capture());
    caller.signing = Some(&signing);
    let answer = crate::gateway::meta_mcp::visible::with_visibility_memo(async {
        if matches!(first, First::Carried) {
            carry(meta, EXTERNAL_BACKEND, &caller).await;
        }
        // Only the managed account reads custody.
        gateway.fail_custody_for_test(true);
        let answer = meta
            .first_unproven(
                &RequestId::Number(7),
                "gateway_execute",
                &[(EXTERNAL_BACKEND, TOOL), (BACKEND, TOOL)],
                &caller,
            )
            .await;
        if answer.is_some() {
            meta.settle_nonce_refund(
                &signing,
                crate::gateway::meta_mcp::signing::nonce_principal(&caller),
            );
        }
        answer
    })
    .await;
    (answer, nonce_is_free(meta, nonce))
}

/// PG1 (MIK-8406 G1, mutant mProofKeep): the walk resolves the first account
/// FRESH (nothing carried) and it mints; the second account is busy, which
/// asks for the refund. The mint is an effect, so the nonce stays spent.
/// Without G1's spend (mProofKeep) the witness survives the mint and the busy
/// refusal gives the nonce back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg1_a_walk_that_minted_keeps_the_nonce_when_a_later_account_is_busy() {
    let (gateway, meta) = signed_two_accounts();
    let (answer, free) = walk_then_settle(&gateway, &meta, "pg1-n1", First::Fresh).await;
    let answer = serde_json::to_value(answer.expect("premise: the busy account refuses"))
        .expect("serialises");
    assert_eq!(
        answer.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "premise: the second account answered busy: {answer}"
    );
    assert!(
        !free,
        "PG1: the nonce came back after the walk minted the first account"
    );
}

/// `PG1c` (control): the same, with the first account's resolution carried
/// from the route stage, whose carried arm spends the witness: the nonce
/// stays spent with or without G1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg1c_a_carried_first_account_keeps_the_nonce_too() {
    let (gateway, meta) = signed_two_accounts();
    let (answer, free) = walk_then_settle(&gateway, &meta, "pg1c-n1", First::Carried).await;
    let answer = serde_json::to_value(answer.expect("premise: the busy account refuses"))
        .expect("serialises");
    assert_eq!(
        answer.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "premise: the second account answered busy: {answer}"
    );
    assert!(!free, "PG1c: the nonce came back after a carried proof");
}
