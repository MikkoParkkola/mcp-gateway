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
        .search_tools_anon(&json!({ "query": QUERY }), None)
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
        .search_tools_anon(&json!({ "query": QUERY }), None)
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
/// Mode counts candidates at `src/gateway/meta_mcp/search.rs:409`, before the
/// ranker block and before `finalize_search_matches` truncates, and reports
/// that count as `total_available`. Asserting it is zero therefore carries the
/// same strength as the classic path: it distinguishes a backend that was
/// never collected from one collected and then filtered out of the survivors.
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
        .code_mode_search_anon(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        Vec::<String>::new(),
        "a denied backend must contribute no Code Mode matches"
    );
    assert_eq!(
        response["total_available"], 0,
        "denied capability tools must not be counted as Code Mode candidates, \
         so the denial is not a late filter over an already-counted set"
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
        .search_tools_anon(&json!({ "query": QUERY, "limit": 1 }), None)
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
        .search_tools_anon(&json!({ "query": QUERY }), None)
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
        .search_tools_anon(&json!({ "query": QUERY }), None)
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
        .code_mode_search_anon(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec![format!("{CAP_BACKEND}:{QUERY}")],
        "the single surviving Code Mode match must be the highest scoring one, \
         not the first collected (Code Mode qualifies names as server:tool)"
    );
}

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

/// As `RANKING_FIXTURES`, collected in the OPPOSITE order: the stronger text
/// match is collected first and the heavily-used `weak_match` second.
///
/// The order matters for the potency controls below. With `RANKING_FIXTURES`,
/// `weak_match` is collected first, so a `limit` of 1 keeps it whether ranking
/// promoted it or never ran at all — a control on those fixtures cannot tell
/// "the boost is potent" from "ranking was skipped". Here the two disagree:
/// only an applied boost puts `weak_match` ahead of the stronger match. Keep
/// `weak_match` SECOND; re-sorting this fixture silently guts that proof.
///
/// The first entry is `zebracorn_tool`, deliberately NOT a tool named exactly
/// `QUERY`. Design §3.4 (`docs/design/2026-09-12-mik-3274-ranking-abbreviations.md`)
/// retires score-only ordering as a premise: an exact identifier match is the
/// PRIMARY sort key, ahead of score, so no usage multiplier can promote
/// anything past a tool the caller named exactly. A potency control founded on
/// beating an exact-name match would assert the one outcome the ranker now
/// guarantees cannot happen. `zebracorn_tool` contains the query without
/// equalling it (`scoring.rs:280`, 5.0), so both candidates carry
/// `exact_identifier == false`, the primary key is inert here, and the usage
/// boost is once again the only thing that can decide first place.
const POTENCY_FIXTURES: &[(&str, &str)] = &[
    ("zebracorn_tool", "a near-name zebracorn tool"),
    ("weak_match", "a zebracorn adjacent helper"),
];

/// CONTROL for the two tests below — the poison has to actually work.
///
/// Without a denial, 10^12 uses lift `weak_match` (relevance 2.0) to
/// `2.0 * (1 + log2(10^12 + 1) * 0.15)`, about 13.9, above `zebracorn_tool`'s
/// 5.0 (`scoring.rs:280`, a name that contains the query without equalling
/// it). If this test ever fails the usage boost has stopped being potent
/// enough to promote anything, and the two denial tests below would pass
/// whether or not authorization ran.
///
/// The name says "the exact match" for the premise this control was FOUNDED on
/// and no longer uses: it once pinned `weak_match` above a tool named exactly
/// `QUERY`, which design §3.4's exact-identifier primary sort key forbids by
/// construction. The job is unchanged — prove the boost is potent — and it is
/// now proved against a stronger text match. Do not restore the old fixture:
/// it asserts the defect §3.4 fixed.
///
/// Uses `POTENCY_FIXTURES`, not `RANKING_FIXTURES`: see the note there. On
/// `RANKING_FIXTURES` this assertion also holds when ranking is skipped
/// entirely, which is the one failure mode a potency control exists to catch.
#[tokio::test]
async fn heavy_usage_outranks_the_exact_match_when_nothing_is_denied() {
    let (meta, _dirs) = meta_with_ranker(
        POTENCY_FIXTURES,
        registry_with_default("open", poisoned_profile(false)),
        ranker_with_heavy_usage("weak_match"),
    )
    .await;

    let response = meta
        .search_tools_anon(&json!({ "query": QUERY, "limit": 1 }), None)
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
        .search_tools_anon(&json!({ "query": QUERY, "limit": 1 }), None)
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
        .code_mode_search_anon(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        response["total_available"], 1,
        "the forbidden tool must not be counted as a candidate on the Code Mode \
         route either"
    );
    assert_eq!(
        tool_names(&response),
        vec![format!("{CAP_BACKEND}:{QUERY}")],
        "an allowed relevant tool must outlast a forbidden tool with 10^12 uses \
         on the Code Mode route too"
    );
}

// ============================================================================
// INVARIANT A on the MCP-backend routes
//
// `collect_search_capability_matches` and `collect_code_mode_capability_matches`
// guard the *capability* backend. The MCP-backend collectors are separate code
// with their own copies of the guard, so everything above leaves them unpinned.
//
// The arrange never seeds the cache directly; `CachedMetadata` has no setter
// outside its own fill path.
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

// ── MIK-7334.CATALOGUE.1 — a `per_user` backend must still be discoverable ──
//
// `Backend::get_cached_list_shared` short-circuits for `session_mode =
// per_user`, so the four metadata caches (tools, resources, resource
// templates, prompts) are never populated for such a backend. Discovery reads
// those caches — `search.rs:155` (`has_cached_tools`), `spec_preview.rs:1039`
// (`get_cached_tools_snapshot`), `surfaced.rs:111/150` (`get_cached_tool`) —
// so every meta discovery entry point answers with zero tools while the direct
// route (`router/backend_handlers.rs:649`) forwards the very same
// static-credential `tools/list` live to every caller.

#[path = "search_ranking_authz_tests/usage_limits.rs"]
mod usage_limits;

#[path = "search_ranking_authz_tests/mcp_routes.rs"]
mod mcp_routes;

#[path = "search_ranking_authz_tests/glob_ordering.rs"]
mod glob_ordering;

#[path = "search_ranking_authz_tests/per_user.rs"]
mod per_user;

#[path = "search_ranking_authz_tests/backend_name.rs"]
mod backend_name;

#[path = "search_ranking_authz_tests/cold_backend.rs"]
mod cold_backend;
