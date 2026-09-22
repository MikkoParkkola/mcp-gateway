// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7334.CATALOGUE.1 — the other three catalogue families.
//!
//! `catalogue_per_caller_tests.rs` pins `tools/list`. Its fixture asserts the
//! method IS `tools/list`, so it cannot answer for resources, resource
//! templates or prompts — the three families whose fill passed a constant
//! `PoolKey::Shared` and was therefore answered to every caller from one slot.
//!
//! Own file because `catalogue_per_caller_tests.rs` would cross the 800-line
//! ceiling, and declared from it so the module is compiled: an undeclared
//! `*_tests.rs` is invisible to `cargo test`, to coverage and to grep, which
//! has bitten this criterion before.

use super::super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, OAuthConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// One recorded fetch: the method, and the headers it was handed.
type HeaderFill = (String, Vec<(String, String)>);

/// Catalogue item names the per-identity upstream serves.
const ALPHA_ITEM: &str = "alpha_private_entry";
const BETA_ITEM: &str = "beta_private_entry";
const STATIC_ITEM: &str = "gateway_static_entry";
/// The genuinely shared backend's item, which every caller must keep seeing.
const SHARED_ITEM: &str = "shared_status_entry";
/// The gateway-held-OAuth backend's item, which nobody may see multi-user.
const OAUTH_ITEM: &str = "oauth_private_entry";

const PER_USER_BACKEND: &str = "per_user_families";
const SHARED_BACKEND: &str = "shared_families";
const OAUTH_BACKEND: &str = "oauth_families";

/// The three families under test, as the method each is fetched with.
const FAMILIES: [&str; 3] = ["resources/list", "resources/templates/list", "prompts/list"];

/// A transport answering all three families with a catalogue chosen by the
/// `Authorization` header it was handed.
///
/// The fixture's whole point: the upstream really does serve different items to
/// different identities, so "beta did not see alpha's prompts" can only pass
/// because the fetch carried beta's credential — never because the upstream had
/// one answer all along.
struct PerIdentityFamilies {
    /// Item name served when no minted credential arrives.
    shared: String,
    /// Item name served to `Bearer minted-for-<subject>`, by subject.
    per_identity: HashMap<String, String>,
    /// `(method, identity_key)` for every fetch, in order.
    seen: parking_lot::Mutex<Vec<(String, Option<String>)>>,
    /// `(method, extra_headers)` for every fetch, in order.
    ///
    /// The WHOLE header list, never the subject parsed out of
    /// `Authorization`: a strategy that mints under some other header name
    /// would walk straight past a check that only reads one key.
    headers_seen: parking_lot::Mutex<Vec<HeaderFill>>,
    /// Total fetches, for the single-flight control.
    requests: AtomicUsize,
}

impl PerIdentityFamilies {
    fn new(shared: &str, per_identity: &[(&str, &str)]) -> Self {
        Self {
            shared: shared.to_string(),
            per_identity: per_identity
                .iter()
                .map(|(s, t)| ((*s).to_string(), (*t).to_string()))
                .collect(),
            seen: parking_lot::Mutex::new(Vec::new()),
            headers_seen: parking_lot::Mutex::new(Vec::new()),
            requests: AtomicUsize::new(0),
        }
    }

    /// Every upstream fill of `method`, in order, keyed or not.
    ///
    /// RAW ON PURPOSE — no `sort`, no `dedup`, no dropping of `None`. Each of
    /// those erases exactly the evidence these cases exist to capture: sorting
    /// and deduplicating hide a refetch, and discarding `None` hides a fetch
    /// that ran on the SHARED slot of a per-user backend, which is the bug
    /// under repair. The expected value is therefore a full transcript.
    fn fills_for(&self, method: &str) -> Vec<Option<String>> {
        self.seen
            .lock()
            .iter()
            .filter(|(m, _)| m == method)
            .map(|(_, key)| key.clone())
            .collect()
    }

    /// Every header list `method` was fetched with, in order.
    ///
    /// RAW, for the reason `fills_for` is raw. An empty list is a real entry
    /// and must stay visible: it is the evidence that a fill on the shared
    /// slot went upstream without the calling identity attached.
    fn headers_for(&self, method: &str) -> Vec<Vec<(String, String)>> {
        self.headers_seen
            .lock()
            .iter()
            .filter(|(m, _)| m == method)
            .map(|(_, headers)| headers.clone())
            .collect()
    }

    /// The one item body for `method`, named `item`.
    fn body(method: &str, item: &str) -> Value {
        match method {
            "resources/list" => json!({
                "resources": [{ "uri": format!("mem://{item}"), "name": item }]
            }),
            "resources/templates/list" => json!({
                "resourceTemplates": [
                    { "uriTemplate": format!("mem://{item}/{{id}}"), "name": item }
                ]
            }),
            "prompts/list" => json!({ "prompts": [{ "name": item }] }),
            // A warm-up `tools/list` must not poison the counts these cases
            // read, so it answers empty rather than erroring.
            _ => json!({ "tools": [] }),
        }
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for PerIdentityFamilies {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        self.request_with_headers(
            method,
            params,
            &[],
            None,
            crate::transport::ResendPermission::Permitted,
        )
        .await
    }

    async fn request_with_headers(
        &self,
        method: &str,
        _params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.seen
            .lock()
            .push((method.to_string(), identity_key.map(str::to_string)));
        self.headers_seen
            .lock()
            .push((method.to_string(), extra_headers.to_vec()));

        let item = extra_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, v)| v.strip_prefix("Bearer minted-for-"))
            .and_then(|s| self.per_identity.get(s).cloned())
            .unwrap_or_else(|| self.shared.clone());

        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            Self::body(method, &item),
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

/// A backend wired to `wire`, with per-user slots pre-opened on the SAME wire.
///
/// One wire for every slot is deliberate: it discriminates on the credential it
/// is handed, so a catalogue that came back per-identity did so because the
/// fetch carried that identity, not because the fixture handed each slot a
/// different answer.
fn backend_on(name: &str, config: BackendConfig, wire: &Arc<PerIdentityFamilies>) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let dynamic = || Arc::clone(wire) as Arc<dyn crate::transport::Transport>;
    backend.set_transport_for_test(dynamic());
    for binding in ["alpha@ledger", "beta@ledger"] {
        backend.set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser {
                binding: binding.to_string(),
            },
            dynamic(),
        );
    }
    backend
}

/// `session_mode = per_user`, propagation NOT required.
///
/// `required: false` is load-bearing and not an accident. `pool_key_for` mints a
/// `PerUser` slot on `session_mode` alone, but
/// `enforce_oauth_isolation_for`'s third arm refuses a `required` backend
/// outright whenever no per-user credential was resolved — so with `required:
/// true` the backend is omitted from these aggregations for EVERY caller, and
/// "beta did not see alpha's prompts" would pass on an empty answer whether or
/// not the key was ever wired. `required: false` is the shape where the leak is
/// observable: before the fix every caller is served the one static catalogue,
/// and after it each is served its own.
fn per_user_config() -> BackendConfig {
    BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "ledger".to_string(),
            required: false,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..Default::default()
    }
}

/// One gateway-held OAuth login, which is never per-caller (ADR-008 INV-2).
fn oauth_config() -> BackendConfig {
    BackendConfig {
        oauth: Some(OAuthConfig {
            enabled: true,
            shared_account: false,
            scopes: vec![],
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: 300,
        }),
        ..Default::default()
    }
}

fn identity(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@example.invalid"),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example.invalid".to_string(),
    }
}

/// A multi-user gateway with the per-user backend and the two controls.
fn families_gateway() -> (MetaMcp, Arc<PerIdentityFamilies>) {
    let per_identity_wire = Arc::new(PerIdentityFamilies::new(
        STATIC_ITEM,
        &[("alpha", ALPHA_ITEM), ("beta", BETA_ITEM)],
    ));
    let registry = Arc::new(BackendRegistry::new());
    assert!(
        registry.register(backend_on(
            PER_USER_BACKEND,
            per_user_config(),
            &per_identity_wire
        )),
        "fixture registration"
    );
    // The controls answer one item to everyone, so they cannot contribute a
    // per-identity difference of their own.
    for (name, item, config) in [
        (SHARED_BACKEND, SHARED_ITEM, BackendConfig::default()),
        (OAUTH_BACKEND, OAUTH_ITEM, oauth_config()),
    ] {
        let wire = Arc::new(PerIdentityFamilies::new(item, &[]));
        assert!(
            registry.register(backend_on(name, config, &wire)),
            "fixture registration"
        );
    }

    let mut configs: HashMap<String, RoutingProfileConfig> = HashMap::new();
    configs.insert(
        "open".to_string(),
        RoutingProfileConfig {
            description: "denies nothing, so authorization cannot decide these cases".to_string(),
            ..Default::default()
        },
    );
    let meta = MetaMcp::new(registry)
        .with_profile_registry(ProfileRegistry::from_config(&configs, "open"));
    meta.set_identity_propagation(Arc::new(super::PerIdentityMint));
    meta.set_multi_user(true);
    (meta, per_identity_wire)
}

/// Item names the family's list handler answers `who` with.
///
/// The three handlers are asked through their real protocol entry points, so a
/// key wired only on the `Backend` accessor and never reached from the route
/// would not pass.
async fn listed_for(meta: &MetaMcp, method: &str, who: Option<&VerifiedIdentity>) -> Vec<String> {
    let id = RequestId::Number(1);
    let (response, key) = match method {
        "resources/list" => (meta.handle_resources_list(id, None, who).await, "resources"),
        "resources/templates/list" => (
            meta.handle_resources_templates_list(id, None, who).await,
            "resourceTemplates",
        ),
        "prompts/list" => (meta.handle_prompts_list(id, None, who).await, "prompts"),
        other => panic!("unknown family {other}"),
    };
    assert!(
        response.error.is_none(),
        "{method} must answer, not error: {:?}",
        response.error
    );
    response
        .result
        .and_then(|result| {
            result.get(key).and_then(Value::as_array).map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["name"].as_str().map(str::to_string))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// Whether `names` contains `item`, namespaced or not.
///
/// `prompts/list` rewrites every backend prompt to `"backend_name/prompt_name"`
/// so `prompts/get` can route it, while `resources/list` and
/// `resources/templates/list` leave the name alone. Matching the suffix keeps
/// one assertion body honest across all three families rather than encoding a
/// per-family naming rule in the oracle.
fn serves(names: &[String], item: &str) -> bool {
    let suffix = format!("/{item}");
    names.iter().any(|n| n == item || n.ends_with(&suffix))
}

/// GIVEN a multi-user gateway whose `per_user` backend serves a different
/// catalogue to each identity
/// WHEN alpha, beta and an anonymous caller each list `method`
/// THEN each identity sees its own catalogue and neither the other's; the
/// anonymous caller still sees the static one and the genuinely shared backend;
/// and nobody sees the gateway-held-OAuth backend.
///
/// FOUR ROWS, AND ALL FOUR ARE NEEDED. Assert only that beta cannot see alpha's
/// items and an empty gateway passes. Assert only that alpha sees its own and a
/// gateway serving one catalogue to everyone passes. Row 3 is what keeps the
/// fix from being bought by blanking the identity-free path (IDP.5), and row 4
/// is what keeps it from becoming a blanket loosening of the isolation guard.
async fn each_identity_sees_its_own_family_catalogue(method: &str) {
    let (meta, wire) = families_gateway();
    let alpha_id = identity("alpha");
    let beta_id = identity("beta");

    let alpha = listed_for(&meta, method, Some(&alpha_id)).await;
    let beta = listed_for(&meta, method, Some(&beta_id)).await;
    let anonymous = listed_for(&meta, method, None).await;

    let has = |names: &[String], item: &str| serves(names, item);

    // ROW 1 — the mode being built: each identity is served its own catalogue.
    assert!(
        has(&alpha, ALPHA_ITEM),
        "{method}: alpha was not served its own catalogue: {alpha:?}"
    );
    assert!(
        has(&beta, BETA_ITEM),
        "{method}: beta was not served its own catalogue: {beta:?}"
    );

    // ROW 2 — isolation, meaningful only because each caller demonstrably
    // received something above.
    assert!(
        !has(&alpha, BETA_ITEM),
        "{method}: alpha was served beta's catalogue: {alpha:?}"
    );
    assert!(
        !has(&beta, ALPHA_ITEM),
        "{method}: beta was served alpha's catalogue: {beta:?}"
    );
    assert!(
        !has(&alpha, STATIC_ITEM) && !has(&beta, STATIC_ITEM),
        "{method}: an identified caller was served the gateway's \
         static-credential catalogue under its own identity: \
         alpha={alpha:?} beta={beta:?}"
    );

    // ROW 3 — IDP.5: a caller with no binding sees what it saw before, which is
    // the static catalogue. This is also the anti-vacuity guard: without it the
    // absence assertions above would pass against a gateway that answered
    // nobody at all.
    assert!(
        has(&anonymous, STATIC_ITEM),
        "{method}: the identity-free caller lost the static-credential \
         catalogue, so isolation was bought by blanking the shared path: \
         {anonymous:?}"
    );
    assert!(
        has(&anonymous, SHARED_ITEM) && has(&alpha, SHARED_ITEM) && has(&beta, SHARED_ITEM),
        "{method}: a caller lost the genuinely shared backend, so the \
         assertions above measure an empty answer rather than isolation: \
         anonymous={anonymous:?} alpha={alpha:?} beta={beta:?}"
    );

    // ROW 4 — one gateway-held OAuth login is never per-caller, whatever
    // identity the caller proves (ADR-008 INV-2).
    for (who, names) in [
        ("alpha", &alpha),
        ("beta", &beta),
        ("anonymous", &anonymous),
    ] {
        assert!(
            !has(names, OAUTH_ITEM),
            "{method}: {who} was served a backend behind ONE gateway-held OAuth \
             login on a multi-user gateway: {names:?}"
        );
    }

    // PROVENANCE, not just count: each identified fetch carried its own identity
    // key, so the two catalogues came from two slots rather than from one
    // upstream that happened to answer twice.
    // PROVENANCE, as a full transcript. Three reads in order produced exactly
    // three fills: alpha's on alpha's slot, beta's on beta's, and the
    // anonymous one on the shared slot. Compared unsorted and undeduplicated,
    // so an extra fetch, a missing one, or a per-user read that silently landed
    // on the shared slot all fail here rather than being normalised away.
    let expected_fills = vec![
        Some("alpha@ledger".to_string()),
        Some("beta@ledger".to_string()),
        None,
    ];
    assert_eq!(
        wire.fills_for(method),
        expected_fills,
        "{method}: the catalogue fills were not one per caller, on that \
         caller's own slot"
    );

    // THE CACHE MUST EXIST, AND IT MUST NOT BE ONE SLOT THE CALLERS TAKE TURNS
    // OVERWRITING. Re-reading the FIRST-filled caller is what discriminates
    // both. A never-cache implementation refetches and the transcript grows; a
    // single shared cache that each caller clobbers still answers beta (who
    // filled last) correctly, but has lost alpha's catalogue — so alpha is the
    // one who must be asked again, and beta's re-read would prove neither.
    let alpha_again = listed_for(&meta, method, Some(&alpha_id)).await;
    assert_eq!(
        wire.fills_for(method),
        expected_fills,
        "{method}: re-reading the first caller went upstream again, so the \
         catalogue is refetched per read rather than cached per caller"
    );
    assert!(
        has(&alpha_again, ALPHA_ITEM) && !has(&alpha_again, BETA_ITEM),
        "{method}: after another identity filled its own slot, the first \
         caller no longer sees its own catalogue — one cache is being \
         overwritten rather than one cache per caller: {alpha_again:?}"
    );
}

#[tokio::test]
async fn each_identity_sees_its_own_resources_and_no_one_elses() {
    each_identity_sees_its_own_family_catalogue("resources/list").await;
}

#[tokio::test]
async fn each_identity_sees_its_own_resource_templates_and_no_one_elses() {
    each_identity_sees_its_own_family_catalogue("resources/templates/list").await;
}

#[tokio::test]
async fn each_identity_sees_its_own_prompts_and_no_one_elses() {
    each_identity_sees_its_own_family_catalogue("prompts/list").await;
}

/// GIVEN a backend with no identity propagation at all
/// WHEN three different callers — two identified, one not — list every family
/// THEN each family is fetched upstream EXACTLY ONCE, with no identity key.
///
/// THE POSITIVE CONTROL. Isolation is trivially achievable by giving every
/// caller its own slot, which would multiply every fetch by the number of
/// callers and end the shared single-flight that IDP.5 promises is unchanged.
/// This is the row that fails if that is how it was bought: `pool_key_for`
/// collapses a non-`per_user` backend to `PoolKey::Shared` whatever binding is
/// handed to it, so one fetch backs all three callers and the cache answers the
/// rest. The sibling for `tools/list` is
/// `backend::tests::per_user_metadata_fetch_is_identity_free_and_shared`.
#[tokio::test]
async fn a_non_identity_backend_still_single_flights_to_one_fetch() {
    let wire = Arc::new(PerIdentityFamilies::new(
        SHARED_ITEM,
        &[("alpha", ALPHA_ITEM), ("beta", BETA_ITEM)],
    ));
    let registry = Arc::new(BackendRegistry::new());
    assert!(
        registry.register(backend_on(SHARED_BACKEND, BackendConfig::default(), &wire)),
        "fixture registration"
    );
    let meta = MetaMcp::new(registry);
    meta.set_identity_propagation(Arc::new(super::PerIdentityMint));
    meta.set_multi_user(true);

    let alpha_id = identity("alpha");
    let beta_id = identity("beta");
    for method in FAMILIES {
        for who in [Some(&alpha_id), Some(&beta_id), None] {
            let names = listed_for(&meta, method, who).await;
            assert!(
                serves(&names, SHARED_ITEM),
                "{method}: a shared backend must answer every caller: {names:?}"
            );
        }
    }

    assert_eq!(
        wire.requests.load(Ordering::SeqCst),
        FAMILIES.len(),
        "a backend with no identity propagation must still single-flight: one \
         upstream fetch per family backs all three callers, not one per caller"
    );
    for method in FAMILIES {
        assert_eq!(
            wire.fills_for(method),
            vec![None],
            "{method}: a non-`per_user` backend must fill once, unkeyed; \
             anything else means it was slotted per caller after all"
        );
    }
}

/// The backend whose `session_mode` is `stateless`, not `per_user`.
const STATELESS_BACKEND: &str = "stateless_families";

/// `session_mode = stateless`, identity propagation CONFIGURED.
///
/// The shape no other fixture in this file has, and the reason the suite was
/// blind to it. `pool_key_for` grants a private slot to `(per_user, binding)`
/// alone, so a `stateless` backend collapses to `PoolKey::Shared` however well
/// its caller identifies itself — while the resolver still mints that caller a
/// credential, because `cache_binding` is derived from subject and audience and
/// never consults the session mode. The two together are the whole defect:
/// minted headers arriving at a slot every caller reads.
///
/// `required: false` for the reason [`per_user_config`] gives: a `required`
/// backend with no per-user credential is omitted outright, and these cases
/// would then pass on an empty answer.
fn stateless_config() -> BackendConfig {
    BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "ledger".to_string(),
            required: false,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..Default::default()
    }
}

/// A multi-user gateway holding one `stateless` backend and nothing else.
///
/// One backend on purpose: every assertion below is about which catalogue that
/// backend's single shared slot holds, and a control backend contributing items
/// of its own would only dilute the answer.
fn stateless_gateway() -> (MetaMcp, Arc<PerIdentityFamilies>) {
    let wire = Arc::new(PerIdentityFamilies::new(
        STATIC_ITEM,
        &[("alpha", ALPHA_ITEM), ("beta", BETA_ITEM)],
    ));
    let registry = Arc::new(BackendRegistry::new());
    assert!(
        registry.register(backend_on(STATELESS_BACKEND, stateless_config(), &wire)),
        "fixture registration"
    );
    let meta = MetaMcp::new(registry);
    meta.set_identity_propagation(Arc::new(super::PerIdentityMint));
    meta.set_multi_user(true);
    (meta, wire)
}

/// The header list `PerIdentityMint` mints for `subject`.
fn minted(subject: &str) -> Vec<(String, String)> {
    vec![(
        "Authorization".to_string(),
        format!("Bearer minted-for-{subject}"),
    )]
}

/// GIVEN a `stateless` backend with identity propagation configured, whose
/// upstream serves a different catalogue per credential
/// WHEN alpha lists `method` and beta then lists it
/// THEN each fill ran on ITS OWN slot carrying ITS OWN minted credential, and
/// each caller is served its own catalogue and not the other's.
///
/// T-S1 — THE CROSS-TENANT CASE, which a `per_user` fixture cannot reach.
/// `pool_key_for` now grants a private slot to `(Some(_), Some(binding))`, so a
/// `stateless` backend's identified caller selects its own slot;
/// `get_cached_list_for` derives `identity_key` from that same `match`, which is
/// what carries the minted headers past #727's gate. Slot and credential move
/// together or not at all.
///
/// THIS CELL WAS INVERTED, NOT WRITTEN FRESH. It previously asserted the
/// transcript IS `vec![None]` with `vec![Vec::new()]` headers and said in its
/// own doc comment that it pinned the documented gap. That gap is now the
/// delivered mode. It is rewritten rather than deleted because it is the only
/// cell that would catch a regression back to the shared fill.
///
/// THE TRANSCRIPT IS THE ASSERTION AND IT IS FIRST. Two identities can
/// coincidentally be served one list; a minted `Authorization` recorded against
/// the slot its fill ran on cannot. An items assertion ahead of it would fail
/// first and the transcript check would never run.
async fn each_identity_sees_its_own_stateless_family_catalogue(method: &str) {
    let (meta, wire) = stateless_gateway();
    let alpha_id = identity("alpha");
    let beta_id = identity("beta");

    let alpha = listed_for(&meta, method, Some(&alpha_id)).await;
    let beta = listed_for(&meta, method, Some(&beta_id)).await;

    // PROVENANCE, as a full transcript, and FIRST. Two reads produced exactly
    // two fills, each on its own caller's slot, each carrying that caller's own
    // minted credential. Unsorted and undeduplicated: sorting hides a refetch
    // and dropping `None` would hide a read that landed on the shared slot.
    assert_eq!(
        wire.fills_for(method),
        vec![
            Some("alpha@ledger".to_string()),
            Some("beta@ledger".to_string()),
        ],
        "{method}: a `stateless` backend's identified callers were not each \
         filled on their own slot"
    );
    assert_eq!(
        wire.headers_for(method),
        vec![minted("alpha"), minted("beta")],
        "{method}: a `stateless` fill did not carry its own caller's minted \
         credential upstream, so the catalogue it cached is not that caller's"
    );

    // ROW 1 — the mode being built.
    assert!(
        serves(&alpha, ALPHA_ITEM),
        "{method}: alpha was not served its own catalogue: {alpha:?}"
    );
    assert!(
        serves(&beta, BETA_ITEM),
        "{method}: beta was not served its own catalogue: {beta:?}"
    );

    // ROW 2 — isolation, meaningful only because row 1 showed each caller was
    // served something of its own.
    assert!(
        !serves(&alpha, BETA_ITEM) && !serves(&beta, ALPHA_ITEM),
        "{method}: one `stateless` caller was served another's private \
         catalogue: alpha={alpha:?} beta={beta:?}"
    );
    assert!(
        !serves(&alpha, STATIC_ITEM) && !serves(&beta, STATIC_ITEM),
        "{method}: an identified caller on a `stateless` backend was served the \
         gateway's static-credential catalogue under its own identity: \
         alpha={alpha:?} beta={beta:?}"
    );
}

#[tokio::test]
async fn each_identity_sees_its_own_stateless_resources() {
    each_identity_sees_its_own_stateless_family_catalogue("resources/list").await;
}

#[tokio::test]
async fn each_identity_sees_its_own_stateless_resource_templates() {
    each_identity_sees_its_own_stateless_family_catalogue("resources/templates/list").await;
}

#[tokio::test]
async fn each_identity_sees_its_own_stateless_prompts() {
    each_identity_sees_its_own_stateless_family_catalogue("prompts/list").await;
}

/// The cells that need this file's `stateless` fixture but would push it over
/// the 800-line ceiling. Declared here rather than from `meta_mcp::mod` so
/// `super::` reaches `stateless_gateway`, `listed_for`, `serves` and `identity`.
#[path = "catalogue_stateless_families_tests.rs"]
mod catalogue_stateless_families_tests;
