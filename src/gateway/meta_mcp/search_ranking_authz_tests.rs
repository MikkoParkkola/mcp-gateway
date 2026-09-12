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
    let backend = Arc::new(CapabilityBackend::new(
        CAP_BACKEND,
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
        "denied tools must not be counted as candidates: authorization has to run \
         at collection time, before the candidate set is built"
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
/// leaks; the collection-time claim is carried by the classic-path test's
/// `total_available`.
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
