// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8195: `evict_slots` scope and its two evict-nothing branches.
//!
//! The happy path (the bound backend loses every generation of the revoked
//! account, another principal keeps theirs) is pinned end to end in
//! `tests/openwebui_adapter/revoke_route.rs`. These cells call `evict_slots`
//! directly for what that route cannot reach cheaply: a backend bound to a
//! DIFFERENT account, a key with no digest, and bindings that do not compile.

use std::sync::Arc;

use serde_json::{Value, json};

use super::evict_slots;
use crate::backend::{Backend, PoolKey};
use crate::config::{BackendConfig, Config, FailsafeConfig};
use crate::personal_accounts::AccountKey;
use crate::personal_accounts::revoke_fixture::{ISSUER, account_binding};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

const ACCOUNT: &str = "work";
const OTHER_ACCOUNT: &str = "home";
const RESOURCE: &str = "https://api.fixture.test/";
/// Bound to `ACCOUNT`: the backend a revoke of `ACCOUNT` must sweep.
const BOUND: &str = "ledger";
/// Bound to `OTHER_ACCOUNT`; sorts before `BOUND`, so the loop meets it first.
const OTHER: &str = "diary";

/// An upstream session that answers nothing interesting: only its presence
/// in the pool is under test.
struct Idle;

#[async_trait::async_trait]
impl Transport for Idle {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Alice's key for `ACCOUNT`, as `own_key` would build it.
fn key() -> AccountKey {
    AccountKey {
        principal_authority: "openwebui-adapter:20:fixture-installation".into(),
        principal_subject: "alice".into(),
        backend_id: ACCOUNT.into(),
        resource: RESOURCE.into(),
        oauth_issuer: ISSUER.into(),
    }
}

/// Two managed descriptors, `ledger` bound to `work` and `diary` to `home`,
/// plus any `extra` backend lines (already indented under `backends:`).
fn config(extra: &str) -> Config {
    serde_yaml::from_str(&format!(
        r"
backends:
  {BOUND}:
    http_url: https://ledger.fixture.test/mcp
    account: {ACCOUNT}
  {OTHER}:
    http_url: https://diary.fixture.test/mcp
    account: {OTHER_ACCOUNT}
{extra}
accounts:
  schema_version: accounts.v1
  enabled: false
  deployment: single_process
  instance_id: router-fixture
  store_dir: /unused/router-fixture-store
  authority_dir: /unused/router-fixture-authority
  current_key_id: primary
  keys:
    primary: env:OWUI_ROUTE_STORE
  descriptors:
    {ACCOUNT}:
      mode: personal_managed
      provider: fixture
      resource: {RESOURCE}
      issuer: {ISSUER}
    {OTHER_ACCOUNT}:
      mode: personal_managed
      provider: fixture
      resource: {RESOURCE}
      issuer: {ISSUER}
"
    ))
    .expect("fixture config parses")
}

/// A gateway state whose registry holds `BOUND` and `OTHER`.
async fn state() -> (
    Arc<crate::gateway::router::AppState>,
    tempfile::TempDir,
    [Arc<Backend>; 2],
) {
    let (state, dir) = crate::gateway::router::tests::test_router_app_state().await;
    let backends = [BOUND, OTHER].map(|name| {
        let backend = Arc::new(Backend::new(
            name,
            BackendConfig::default(),
            &FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        assert!(state.backends.register(Arc::clone(&backend)), "{name}");
        backend
    });
    (state, dir, backends)
}

/// Seed a live upstream session for `slot` on `backend`.
fn seed(backend: &Backend, slot: &PoolKey) {
    backend.set_pooled_transport_for_test(slot, Arc::new(Idle));
    assert!(backend.pool_has_slot_for_test(slot), "premise: {slot:?}");
}

/// Alice's `ACCOUNT` session, keyed exactly as dispatch keys it.
fn alice_slot() -> PoolKey {
    PoolKey::PerUser {
        binding: account_binding(&key(), "gen1"),
    }
}

/// A revoke sweeps only backends bound to the revoked account, never another's.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoke_leaves_another_accounts_backend_sessions() {
    // GIVEN: the same account-prefixed slot on both backends, so only the
    // descriptor check (the `continue`) can spare `diary`'s copy
    let (state, _dir, [bound, other]) = state().await;
    let bindings = crate::config::account_bindings::compile(&config("")).expect("premise");
    assert_eq!(bindings[OTHER].descriptor_id, OTHER_ACCOUNT, "premise");
    assert_eq!(bindings[BOUND].descriptor_id, ACCOUNT, "premise");
    let slot = alice_slot();
    seed(&bound, &slot);
    seed(&other, &slot);
    // WHEN
    evict_slots(&state, &config(""), &key(), ACCOUNT);
    // THEN
    assert!(!bound.pool_has_slot_for_test(&slot), "bound backend swept");
    assert!(
        other.pool_has_slot_for_test(&slot),
        "a backend bound to another account is never swept"
    );
}

/// A key with no digest evicts nothing, guesses no prefix, and does not panic.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoke_whose_key_has_no_digest_evicts_nothing() {
    // GIVEN: a real session and one an empty-digest prefix would match
    let (state, _dir, [bound, _other]) = state().await;
    let slot = alice_slot();
    let stray = PoolKey::PerUser {
        binding: "acct:v1::stray".into(),
    };
    seed(&bound, &slot);
    seed(&bound, &stray);
    let invalid = AccountKey {
        principal_subject: String::new(),
        ..key()
    };
    assert!(invalid.digest().is_err(), "premise: no digest");
    // WHEN
    evict_slots(&state, &config(""), &invalid, ACCOUNT);
    // THEN
    assert!(bound.pool_has_slot_for_test(&slot), "session kept");
    assert!(bound.pool_has_slot_for_test(&stray), "no guessed prefix");
}

/// Bindings that do not compile evict nothing, the bound backend included.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoke_under_uncompilable_bindings_evicts_nothing() {
    // GIVEN: a third backend naming a descriptor that does not exist
    let (state, _dir, [bound, _other]) = state().await;
    let slot = alice_slot();
    seed(&bound, &slot);
    let broken =
        config("  rogue:\n    http_url: https://rogue.fixture.test/mcp\n    account: ghost\n");
    assert!(
        crate::config::account_bindings::compile(&broken).is_err(),
        "premise: bindings do not compile"
    );
    // WHEN
    evict_slots(&state, &broken, &key(), ACCOUNT);
    // THEN
    assert!(bound.pool_has_slot_for_test(&slot), "session kept");
}
