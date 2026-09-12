// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-3274.RANKING.2 — the two ordering invariants of `gateway_search_tools`.
//!
//! A. Routing-profile authorization runs at *collection* time, so a denied
//!    backend's tools never enter the candidate set (they are not collected and
//!    then filtered out later).
//! B. Ranking runs *before* truncation, so the best match survives a `limit`
//!    smaller than the number of candidates regardless of collection order.
//!
//! Both are asserted through the public search entry points against a real
//! `CapabilityBackend`, not by inspecting intermediate state.
//!
//! Every guard site needs its own test. The two `tool_allowed` filters in
//! `search.rs` (`:254` Code Mode, `:341` classic) were each inverted in turn and
//! each inversion failed *exactly one* test — neither test covers the other's
//! site. So coverage here is per-call-site by necessity, and extracting the
//! guards into one shared helper would make both tests pass with either call
//! site removed, which is why that refactor was declined.
//!
//! What no test in this module can establish is the absence of a *forgotten*
//! guard site. That the in-scope sites are the ones covered rests on an
//! enumeration of `tool_allowed`/`backend_allowed` in `search.rs`, not on a
//! test. The remaining hits belong to `gateway_list_tools`, a different
//! meta-tool outside this criterion.

use super::MetaMcp;
use crate::backend::BackendRegistry;
use crate::capability::CapabilityBackend;
use crate::ranking::SearchRanker;
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

/// Backend name shared by every fixture in this module.
const CAP_BACKEND: &str = "ranked_caps";

/// A query token that appears in no real capability, no synonym group and no
/// keyword tag, so scores come only from this module's fixtures.
const QUERY: &str = "zebracorn";

/// Build a capability backend holding `caps` in a *deterministic* order.
///
/// `CapabilityLoader::load_directory` walks a directory with `read_dir`, whose
/// intra-directory order is unspecified. `IndexedCapabilities::upsert` appends,
/// so loading one capability per directory, sequentially, fixes the collection
/// order that invariant B has to survive: `caps[0]` is collected first.
async fn capability_backend(caps: &[(&str, &str)]) -> (Arc<CapabilityBackend>, Vec<TempDir>) {
    capability_backend_named(CAP_BACKEND, caps).await
}

/// As `capability_backend`, with the backend's own name under test control.
///
/// Code Mode admits a tool when `"{server}:{tool}"` contains the query
/// (`search.rs:186`), so the backend name decides whether zero-relevance tools
/// enter the candidate set at all.
async fn capability_backend_named(
    backend_name: &str,
    caps: &[(&str, &str)],
) -> (Arc<CapabilityBackend>, Vec<TempDir>) {
    let backend = Arc::new(CapabilityBackend::new(
        backend_name,
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    let mut dirs = Vec::new();
    for (name, description) in caps {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(format!("{name}.yaml")),
            format!(
                "name: {name}\ndescription: {description}\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.invalid\n      path: /{name}\n"
            ),
        )
        .unwrap();
        let admitted = backend
            .load_from_directory(dir.path().to_str().unwrap())
            .await
            .unwrap();
        // Guards the whole module: a malformed fixture admits zero capabilities,
        // which would make every "nothing leaked" assertion below pass vacuously.
        assert_eq!(admitted, 1, "fixture capability '{name}' failed to load");
        dirs.push(dir);
    }
    (backend, dirs)
}

/// A profile registry whose *default* profile is the one under test, so the
/// sessionless (`session_id: None`) search path resolves to it.
fn registry_with_default(name: &str, config: RoutingProfileConfig) -> ProfileRegistry {
    let mut configs: HashMap<String, RoutingProfileConfig> = HashMap::new();
    configs.insert(name.to_string(), config);
    ProfileRegistry::from_config(&configs, name)
}

/// A gateway with the ranker enabled, the fixture capabilities registered and
/// `profile` as the default routing profile.
async fn meta_with(caps: &[(&str, &str)], registry: ProfileRegistry) -> (MetaMcp, Vec<TempDir>) {
    let (cap_backend, dirs) = capability_backend(caps).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_profile_registry(registry);
    meta.set_capabilities(cap_backend);
    (meta, dirs)
}

/// The two fixtures for invariant B: the weak match is collected FIRST.
///
/// `zebracorn_helper` scores 2.0 (query appears only in its description);
/// `zebracorn` scores 10.0 (tool name equals the query) — see
/// `crate::ranking::scoring::score_text_relevance`.
const RANKING_FIXTURES: &[(&str, &str)] = &[
    ("weak_match", "a zebracorn adjacent helper"),
    (QUERY, "the exact name match"),
];

fn tool_names(response: &Value) -> Vec<String> {
    response["matches"]
        .as_array()
        .expect("matches array")
        .iter()
        .map(|m| m["tool"].as_str().expect("tool name").to_string())
        .collect()
}

/// INVARIANT A — `src/gateway/meta_mcp/search.rs:289`
/// (`collect_search_capability_matches`, the `profile.backend_allowed` conjunct).
///
/// A denied backend's tools are never *collected*, not merely hidden after the
/// fact. `total_available` is the pre-truncation candidate count, so asserting
/// it is zero distinguishes "never entered the candidate set" from "collected,
/// then dropped by a later filter".
#[tokio::test]
async fn denied_backend_never_enters_the_candidate_set() {
    let (meta, _dirs) = meta_with(
        RANKING_FIXTURES,
        registry_with_default(
            "locked",
            RoutingProfileConfig {
                description: "denies the capability backend wholesale".to_string(),
                deny_backends: Some(vec![CAP_BACKEND.to_string()]),
                ..Default::default()
            },
        ),
    )
    .await;

    let response = meta
        .search_tools(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        Vec::<String>::new(),
        "a denied backend must contribute no matches"
    );
    assert_eq!(
        response["total_available"], 0,
        "denied tools must not be counted as candidates, so the denial is not a \
         late filter over an already-counted set"
    );
}

/// INVARIANT A (control) — the same fixture, permitted.
///
/// Without this, a broken fixture and a working authorization guard are
/// indistinguishable: both yield an empty match list.
#[tokio::test]
async fn permissive_profile_sees_the_same_capabilities() {
    let (meta, _dirs) = meta_with(
        RANKING_FIXTURES,
        registry_with_default(
            "open",
            RoutingProfileConfig {
                description: "no backend or tool restrictions".to_string(),
                ..Default::default()
            },
        ),
    )
    .await;

    let response = meta
        .search_tools(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    let mut names = tool_names(&response);
    names.sort();
    assert_eq!(
        names,
        vec!["weak_match".to_string(), QUERY.to_string()],
        "both fixture capabilities must be discoverable when the profile allows them"
    );
    assert_eq!(
        response["total_available"], 2,
        "both fixtures must be counted as candidates"
    );
}

/// INVARIANT A on the Code Mode path — `src/gateway/meta_mcp/search.rs:199-200`
/// (`collect_code_mode_capability_matches`, the `profile.backend_allowed`
/// conjunct on line 200).
///
/// Code Mode collects candidates through its own function with its own copy of
/// the guard, so the classic path passing proves nothing about this one. Code
/// Mode finalises through `crate::gateway::search_disclosure::finalize_search_matches`,
/// which emits no pre-truncation count, so this test asserts only that nothing
/// leaks. The classic-path test's `total_available` carries the stronger claim:
/// denied tools are absent from the count, which rules out a filter applied
/// after counting but not a filter applied just before it.
#[tokio::test]
async fn code_mode_denied_backend_contributes_no_matches() {
    let (cap_backend, _dirs) = capability_backend(RANKING_FIXTURES).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(true)
    .with_profile_registry(registry_with_default(
        "locked",
        RoutingProfileConfig {
            description: "denies the capability backend wholesale".to_string(),
            deny_backends: Some(vec![CAP_BACKEND.to_string()]),
            ..Default::default()
        },
    ));
    meta.set_capabilities(cap_backend);

    let response = meta
        .code_mode_search(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        Vec::<String>::new(),
        "a denied backend must contribute no Code Mode matches"
    );
}

/// INVARIANT B — `src/gateway/meta_mcp/search.rs:766-767`
/// (`matches.truncate(limit)` on line 767, standing AFTER the ranker block).
///
/// The weak match is collected first, so truncating to one result before
/// ranking would keep it and discard the exact-name match entirely. Ranking
/// first means the score, not the collection order, decides who survives.
#[tokio::test]
async fn high_scoring_match_beyond_the_limit_survives_truncation() {
    let (meta, _dirs) = meta_with(
        RANKING_FIXTURES,
        registry_with_default(
            "open",
            RoutingProfileConfig {
                description: "no backend or tool restrictions".to_string(),
                ..Default::default()
            },
        ),
    )
    .await;

    let response = meta
        .search_tools(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        response["total_available"], 2,
        "both fixtures must be collected before the limit is applied"
    );
    assert_eq!(
        tool_names(&response),
        vec![QUERY.to_string()],
        "the single surviving match must be the highest scoring one, not the \
         first collected: ranking has to precede truncation"
    );
}

/// A capability sharing no token with `QUERY`, used as the "irrelevant" arm of
/// the usage-feedback clause.
const IRRELEVANT: &str = "unrelated_widget";

/// Fixtures for the usage-feedback clause: one irrelevant capability alongside
/// the two ranked ones.
const USAGE_FIXTURES: &[(&str, &str)] = &[
    ("weak_match", "a zebracorn adjacent helper"),
    (QUERY, "the exact name match"),
    (IRRELEVANT, "sorting sprockets by colour"),
];

/// Give `tool` an astronomically high usage count on the fixture backend.
///
/// `SearchRanker::load` is the only public route to a count this large;
/// `record_use` would need 10^12 calls. The count is chosen to exceed the
/// usage factor's reach: `log2(10^12) * 0.15` is about 6.0, so a multiplicative
/// boost of ~7x is applied to whatever relevance the tool scored.
fn ranker_with_heavy_usage(tool: &str) -> Arc<SearchRanker> {
    ranker_with_heavy_usage_on(CAP_BACKEND, tool)
}

/// As `ranker_with_heavy_usage`, for a backend other than `CAP_BACKEND`.
fn ranker_with_heavy_usage_on(server: &str, tool: &str) -> Arc<SearchRanker> {
    let ranker = Arc::new(SearchRanker::new());
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("usage.json");
    std::fs::write(
        &path,
        format!(r#"[{{"server":"{server}","tool":"{tool}","count":1000000000000}}]"#),
    )
    .unwrap();
    ranker.load(&path).unwrap();
    // Guards the two tests below: a load that silently parsed nothing would
    // leave the count at zero and make "usage did not promote it" vacuous.
    assert_eq!(
        ranker.usage_count(server, tool),
        1_000_000_000_000,
        "fixture usage count failed to load"
    );
    ranker
}

/// A gateway with a caller-supplied ranker, so a test can seed usage counts.
async fn meta_with_ranker(
    caps: &[(&str, &str)],
    registry: ProfileRegistry,
    ranker: Arc<SearchRanker>,
) -> (MetaMcp, Vec<TempDir>) {
    let (cap_backend, dirs) = capability_backend(caps).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(ranker),
        Duration::from_secs(60),
    )
    .with_profile_registry(registry);
    meta.set_capabilities(cap_backend);
    (meta, dirs)
}

/// USAGE CLAUSE, irrelevant arm — `src/gateway/meta_mcp/search.rs:304`
/// (`tool_matches_query`, which gates collection) and `ranking/mod.rs:371`
/// (the multiplicative usage factor).
///
/// The clause is narrow on purpose: usage *can* reorder two relevant matches,
/// because the factor is unbounded in the count. What it cannot do is surface a
/// tool the query does not match — that tool never enters the candidate set, so
/// no boost applies to it. Asserting the narrow claim keeps the test honest.
#[tokio::test]
async fn usage_feedback_cannot_surface_an_irrelevant_tool() {
    let ranker = ranker_with_heavy_usage(IRRELEVANT);
    let (meta, _dirs) = meta_with_ranker(
        USAGE_FIXTURES,
        registry_with_default(
            "open",
            RoutingProfileConfig {
                description: "no backend or tool restrictions".to_string(),
                ..Default::default()
            },
        ),
        ranker,
    )
    .await;

    let response = meta
        .search_tools(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    let names = tool_names(&response);
    assert!(
        !names.iter().any(|n| n == IRRELEVANT),
        "a tool the query does not match must not be surfaced by usage feedback, \
         however heavily used: got {names:?}"
    );
    assert_eq!(
        response["total_available"], 2,
        "only the two matching fixtures may be candidates"
    );
}

/// USAGE CLAUSE, forbidden arm — `src/gateway/meta_mcp/search.rs:289`.
///
/// Authorization runs at collection time, *upstream* of the ranker, so a denied
/// backend's tools are never scored at all. Without this test the clause rests
/// on reading the call order; with it, the strongest possible boost is applied
/// to a forbidden tool and it still never appears.
#[tokio::test]
async fn usage_feedback_cannot_promote_a_forbidden_tool() {
    let ranker = ranker_with_heavy_usage(QUERY);
    let (meta, _dirs) = meta_with_ranker(
        USAGE_FIXTURES,
        registry_with_default(
            "locked",
            RoutingProfileConfig {
                description: "denies the capability backend wholesale".to_string(),
                deny_backends: Some(vec![CAP_BACKEND.to_string()]),
                ..Default::default()
            },
        ),
        ranker,
    )
    .await;

    let response = meta
        .search_tools(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        Vec::<String>::new(),
        "a forbidden tool must stay hidden at any usage count"
    );
    assert_eq!(
        response["total_available"], 0,
        "a forbidden tool must not be scored: authorization precedes ranking"
    );
}

/// INVARIANT B on the Code Mode path — `src/gateway/meta_mcp/search.rs:412`
/// (the ranker block) standing before
/// `crate::gateway::search_disclosure::finalize_search_matches`, which applies
/// the limit.
///
/// Code Mode collects, ranks and truncates through its own code path; the
/// classic-route test proves nothing about this one.
#[tokio::test]
async fn code_mode_ranks_before_truncating() {
    let (cap_backend, _dirs) = capability_backend(RANKING_FIXTURES).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(true)
    .with_profile_registry(registry_with_default(
        "open",
        RoutingProfileConfig {
            description: "no backend or tool restrictions".to_string(),
            ..Default::default()
        },
    ));
    meta.set_capabilities(cap_backend);

    let response = meta
        .code_mode_search(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec![format!("{CAP_BACKEND}:{QUERY}")],
        "the single surviving Code Mode match must be the highest scoring one, \
         not the first collected (Code Mode qualifies names as server:tool)"
    );
}

/// A backend whose *name* contains `QUERY`, so Code Mode admits every tool on
/// it through the `server:tool` reference match at `search.rs:186`.
const QUERY_NAMED_BACKEND: &str = "zebracorn_hub";

/// Fixtures for the zero-relevance case: `sprocket_sorter` shares no token with
/// `QUERY`, so `score_text_relevance` gives it 0.0, yet Code Mode admits it
/// because the backend name matches.
const ZERO_RELEVANCE_FIXTURES: &[(&str, &str)] = &[
    ("sprocket_sorter", "sorting sprockets by colour"),
    ("weak_match", "a zebracorn adjacent helper"),
];

/// The poisoned-feedback pairing the criterion's test row specifies: a
/// heavily used tool competing against an allowed relevant one under a low
/// limit. `weak_match` carries 10^12 uses, which is enough to beat the exact
/// name match on score alone — the control below proves it.
fn poisoned_profile(deny_weak: bool) -> RoutingProfileConfig {
    RoutingProfileConfig {
        description: "allows the backend, denies one tool".to_string(),
        deny_tools: deny_weak.then(|| vec!["weak_match".to_string()]),
        ..Default::default()
    }
}

/// CONTROL for the two tests below — the poison has to actually work.
///
/// Without a denial, 10^12 uses lift `weak_match` (relevance 2.0) to
/// `2.0 * (1 + log2(10^12 + 1) * 0.15)`, about 13.9, above the exact-name
/// match's 10.0. If this test ever fails the usage boost has stopped being
/// potent enough to promote anything, and the two denial tests below would
/// pass whether or not authorization ran.
#[tokio::test]
async fn heavy_usage_outranks_the_exact_match_when_nothing_is_denied() {
    let (meta, _dirs) = meta_with_ranker(
        RANKING_FIXTURES,
        registry_with_default("open", poisoned_profile(false)),
        ranker_with_heavy_usage("weak_match"),
    )
    .await;

    let response = meta
        .search_tools(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec!["weak_match".to_string()],
        "the control has stopped controlling: usage feedback no longer promotes \
         a weaker match, so the denial tests below prove nothing"
    );
}

/// USAGE CLAUSE, the criterion's own pairing — classic route.
///
/// A forbidden heavily-used tool against an allowed relevant one, `limit` 1.
/// The control above shows the forbidden tool wins on score, so the allowed
/// tool can only survive because `profile.tool_allowed` (`search.rs:301`)
/// removed its competitor before ranking.
#[tokio::test]
async fn a_forbidden_heavily_used_tool_loses_to_an_allowed_relevant_one() {
    let (meta, _dirs) = meta_with_ranker(
        RANKING_FIXTURES,
        registry_with_default("locked", poisoned_profile(true)),
        ranker_with_heavy_usage("weak_match"),
    )
    .await;

    let response = meta
        .search_tools(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        response["total_available"], 1,
        "the forbidden tool must not be counted as a candidate"
    );
    assert_eq!(
        tool_names(&response),
        vec![QUERY.to_string()],
        "an allowed relevant tool must outlast a forbidden tool with 10^12 uses"
    );
}

/// USAGE CLAUSE, the criterion's own pairing — Code Mode route.
#[tokio::test]
async fn code_mode_forbidden_heavily_used_tool_loses_to_an_allowed_one() {
    let (cap_backend, _dirs) = capability_backend(RANKING_FIXTURES).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(ranker_with_heavy_usage("weak_match")),
        Duration::from_secs(60),
    )
    .with_code_mode(true)
    .with_profile_registry(registry_with_default("locked", poisoned_profile(true)));
    meta.set_capabilities(cap_backend);

    let response = meta
        .code_mode_search(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec![format!("{CAP_BACKEND}:{QUERY}")],
        "an allowed relevant tool must outlast a forbidden tool with 10^12 uses \
         on the Code Mode route too"
    );
}

/// USAGE CLAUSE, the form of the boost — `src/ranking/mod.rs:371`.
///
/// The three tests above would all stay green if the usage factor became
/// additive rather than multiplicative, because every tool they score has
/// non-zero relevance. This one does not: `sprocket_sorter` is admitted by the
/// Code Mode backend-name match while scoring 0.0 relevance, so
/// `0.0 * (1 + factor)` keeps it at zero and `weak_match` survives `limit` 1.
/// Under `relevance + factor` the zero-relevance tool would score about 6.0
/// against `weak_match`'s 2.0 and take the slot. This is the test that pins
/// "usage feedback cannot promote an irrelevant tool" to the construct that
/// makes it true.
#[tokio::test]
async fn a_zero_relevance_candidate_cannot_be_lifted_by_usage() {
    let (cap_backend, _dirs) =
        capability_backend_named(QUERY_NAMED_BACKEND, ZERO_RELEVANCE_FIXTURES).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(ranker_with_heavy_usage_on(
            QUERY_NAMED_BACKEND,
            "sprocket_sorter",
        )),
        Duration::from_secs(60),
    )
    .with_code_mode(true)
    .with_profile_registry(registry_with_default(
        "open",
        RoutingProfileConfig {
            description: "no backend or tool restrictions".to_string(),
            ..Default::default()
        },
    ));
    meta.set_capabilities(cap_backend);

    let all = meta
        .code_mode_search(&json!({ "query": QUERY }), None)
        .await
        .unwrap();
    // Guards the assertion below: if the backend-name match stopped admitting
    // the zero-relevance tool, the test would pass by absence rather than by
    // the multiplicative form holding it at zero.
    assert!(
        tool_names(&all)
            .iter()
            .any(|n| n == &format!("{QUERY_NAMED_BACKEND}:sprocket_sorter")),
        "fixture premise broken: the zero-relevance tool is no longer admitted, \
         so this test cannot observe what it claims: got {:?}",
        tool_names(&all)
    );

    let response = meta
        .code_mode_search(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec![format!("{QUERY_NAMED_BACKEND}:weak_match")],
        "a zero-relevance candidate must stay at zero however heavily used: the \
         usage factor is multiplicative, not additive"
    );
}

// ============================================================================
// INVARIANT A on the MCP-backend routes
//
// `collect_search_capability_matches` and `collect_code_mode_capability_matches`
// guard the *capability* backend. The MCP-backend collectors are separate code
// with their own copies of the guard, so everything above leaves them unpinned.
//
// The arrange never touches `CachedMetadata::store_shared` (`pub(super)`).
// `collect_search_backend_matches` reads the cache through
// `backend_tools_for_discovery(&backend, false)` — `allow_empty_cache_fetch` is
// false, so an empty cache yields nothing and the search would pass vacuously.
// Calling `Backend::get_tools_shared()` once in arrange fills `tools_cache` over
// the transport, through production code, exactly as a live backend would.
// ============================================================================

/// An MCP backend name containing `QUERY`, so Code Mode admits its tools: Code
/// Mode matches against the qualified `server:tool` (`search.rs:186`).
const MCP_BACKEND: &str = "zebracorn_hub";

/// Tools for the MCP-backend fixtures. `weak_match` is served FIRST, so a
/// collector that leaked would leak in this order.
const MCP_TOOLS: &[(&str, &str)] = &[
    ("weak_match", "a zebracorn adjacent helper"),
    (QUERY, "the exact name match"),
];

/// A transport that serves one canned `tools/list` and nothing else.
///
/// `Backend::set_transport_for_test` is an existing production test hook; this
/// is the `tools/list` counterpart of `ToolCallTestTransport` in `tests.rs`.
struct ToolsListTestTransport {
    tools: Value,
}

#[async_trait::async_trait]
impl crate::transport::Transport for ToolsListTestTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        assert_eq!(method, "tools/list", "fixture serves only tools/list");
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            crate::protocol::RequestId::Number(1),
            json!({ "tools": self.tools }),
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

/// A registered MCP backend whose tool cache is warm.
async fn mcp_backend(name: &str, tools: &[(&str, &str)]) -> Arc<crate::backend::Backend> {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};

    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let payload: Vec<Value> = tools
        .iter()
        .map(|(n, d)| json!({ "name": n, "description": d, "inputSchema": { "type": "object" } }))
        .collect();
    backend.set_transport_for_test(Arc::new(ToolsListTestTransport {
        tools: json!(payload),
    }));

    // Warms `tools_cache` through production code. Guards every assertion
    // below: a cold cache makes the search collect nothing and every
    // "nothing leaked" claim vacuous.
    let warmed = backend
        .get_tools_shared()
        .await
        .expect("fixture backend tools/list failed");
    assert_eq!(
        warmed.len(),
        tools.len(),
        "fixture backend cache did not warm"
    );
    backend
}

/// A gateway whose only backend is a warm MCP backend (no capabilities).
async fn meta_with_mcp_backend(registry: ProfileRegistry, code_mode: bool) -> MetaMcp {
    let backends = Arc::new(BackendRegistry::new());
    assert!(
        backends.register(mcp_backend(MCP_BACKEND, MCP_TOOLS).await),
        "fixture backend failed to register"
    );
    MetaMcp::with_features(
        backends,
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(code_mode)
    .with_profile_registry(registry)
}

/// CONTROL — the warm MCP backend is discoverable when the profile allows it.
///
/// Without this, a cold cache and a working guard are indistinguishable: both
/// yield an empty match list, and the two denial tests below would pass for the
/// wrong reason.
#[tokio::test]
async fn permissive_profile_sees_the_mcp_backend_tools() {
    let meta = meta_with_mcp_backend(
        registry_with_default(
            "open",
            RoutingProfileConfig {
                description: "no backend or tool restrictions".to_string(),
                ..Default::default()
            },
        ),
        false,
    )
    .await;

    let response = meta
        .search_tools(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    let mut names = tool_names(&response);
    names.sort();
    assert_eq!(
        names,
        vec!["weak_match".to_string(), QUERY.to_string()],
        "both MCP backend tools must be discoverable when the profile allows them"
    );
    assert_eq!(
        response["total_available"], 2,
        "both MCP backend tools must be counted as candidates"
    );
}

/// INVARIANT A on the classic MCP-backend route —
/// `src/gateway/meta_mcp/search.rs:329` (`collect_search_backend_matches`, the
/// `profile.backend_allowed(&backend.name)` guard).
///
/// `total_available` is the pre-truncation candidate count, so zero here means
/// the tools were never collected, not collected then filtered.
#[tokio::test]
async fn denied_mcp_backend_never_enters_the_candidate_set() {
    let meta = meta_with_mcp_backend(
        registry_with_default(
            "locked",
            RoutingProfileConfig {
                description: "denies the MCP backend wholesale".to_string(),
                deny_backends: Some(vec![MCP_BACKEND.to_string()]),
                ..Default::default()
            },
        ),
        false,
    )
    .await;

    let response = meta
        .search_tools(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        Vec::<String>::new(),
        "a denied MCP backend must contribute no matches"
    );
    assert_eq!(
        response["total_available"], 0,
        "denied MCP backend tools must not be counted as candidates, so the \
         denial is not a late filter over an already-counted set"
    );
}

/// INVARIANT A on the Code Mode MCP-backend route —
/// `src/gateway/meta_mcp/search.rs:238` (`collect_code_mode_backend_matches`).
///
/// Code Mode finalises through `finalize_search_matches`, which emits no
/// pre-truncation count, so this asserts survivor absence only.
#[tokio::test]
async fn code_mode_denied_mcp_backend_contributes_no_matches() {
    let meta = meta_with_mcp_backend(
        registry_with_default(
            "locked",
            RoutingProfileConfig {
                description: "denies the MCP backend wholesale".to_string(),
                deny_backends: Some(vec![MCP_BACKEND.to_string()]),
                ..Default::default()
            },
        ),
        true,
    )
    .await;

    let response = meta
        .code_mode_search(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        Vec::<String>::new(),
        "a denied MCP backend must contribute no Code Mode matches"
    );
}

/// INVARIANT A, mixed authorization on the MCP-backend route — the
/// `profile.tool_allowed(&t.name)` filter that follows the backend guard
/// (`src/gateway/meta_mcp/search.rs:341`).
///
/// The backend stays ALLOWED and one tool is denied, so a denied tool competes
/// against an allowed relevant one rather than against an empty result. The
/// permissive control above proves both are otherwise discoverable.
#[tokio::test]
async fn a_forbidden_mcp_tool_loses_to_an_allowed_one() {
    let meta = meta_with_mcp_backend(
        registry_with_default(
            "partial",
            RoutingProfileConfig {
                description: "allows the backend, denies one tool".to_string(),
                deny_tools: Some(vec![QUERY.to_string()]),
                ..Default::default()
            },
        ),
        false,
    )
    .await;

    let response = meta
        .search_tools(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec!["weak_match".to_string()],
        "the denied tool must be absent while its allowed sibling survives"
    );
    assert_eq!(
        response["total_available"], 1,
        "the denied tool must not be counted as a candidate"
    );
}

/// INVARIANT A, mixed authorization on the Code Mode MCP-backend route — the
/// `profile.tool_allowed(&t.name)` filter inside
/// `collect_code_mode_backend_matches` (`src/gateway/meta_mcp/search.rs:254`).
///
/// The sibling of the `search.rs:341` filter pinned above. Both collectors carry
/// their own copy, so pinning one leaves the other free to drop its filter.
///
/// `tool_allowed` is asked about the BARE name the backend served, while Code
/// Mode emits the qualified `server:tool`, so this also pins that the filter
/// reads the unqualified name.
///
/// Self-falsifying against a cold cache: the surviving sibling is asserted
/// present, so an empty collection fails the test rather than passing it. The
/// denial-only tests above need the permissive control for that; this one does
/// not.
#[tokio::test]
async fn code_mode_forbidden_mcp_tool_loses_to_an_allowed_one() {
    let meta = meta_with_mcp_backend(
        registry_with_default(
            "partial",
            RoutingProfileConfig {
                description: "allows the backend, denies one tool".to_string(),
                deny_tools: Some(vec![QUERY.to_string()]),
                ..Default::default()
            },
        ),
        true,
    )
    .await;

    let response = meta
        .code_mode_search(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec![format!("{MCP_BACKEND}:weak_match")],
        "the denied tool must be absent from Code Mode while its allowed \
         sibling survives"
    );
}
