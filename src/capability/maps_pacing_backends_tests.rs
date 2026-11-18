// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pacing rules across catalogues and backends, a child of `maps_pacing_tests`
//! using its helpers. The parent holds one host's bucket: admission, refusal,
//! attempts, redirects and reload. Here: GraphQL and JSON-RPC on a paced host
//! (RL15), `base_url` providers and the strictest of several backends (RL18,
//! RL19), the sweeps (RL15e-g), direct registration (LD8) and withdrawn
//! declarations (`RL19b`).

use super::*;

// ── RL15: GraphQL and JSON-RPC on a paced host ───────────────────────

/// A `service` (graphql or jsonrpc) capability on `url`, no `rate_limit`.
fn rpc_yaml(name: &str, service: &str, url: &str) -> String {
    format!(
        "fulcrum: \"1.0\"\nname: {name}\ndescription: d\nschema:\n  input:\n    type: object\n\
         providers:\n  primary:\n    service: {service}\n    config:\n      endpoint: {url}\n      \
         method: m\n      body: \"{{ q }}\"\n"
    )
}

/// An unpaced REST capability on `url`.
fn rest_yaml(name: &str, url: &str) -> String {
    cap_yaml(name, url, 1).replace("    rate_limit:\n      interval_ms: 1\n", "")
}

#[tokio::test]
async fn rl15a_a_graphql_provider_on_a_paced_host_is_refused_in_either_file_order() {
    // Names (and so file stems) chosen so each order is read first in one case.
    for (gql, rest, host) in [
        ("a_gql", "b_rest", "rl15a1.test"),
        ("b_gql", "a_rest", "rl15a2.test"),
    ] {
        let stub = Stub::start(Reply::json("{}")).await;
        let dir = tempfile::TempDir::new().expect("dir");
        let url = stub.url(host, "/g");
        std::fs::write(
            dir.path().join(format!("{gql}.yaml")),
            rpc_yaml(gql, "graphql", &url),
        )
        .expect("write");
        std::fs::write(
            dir.path().join(format!("{rest}.yaml")),
            cap_yaml(rest, &url, 30_000),
        )
        .expect("write");
        let (backend, _) = loaded(dir.path()).await;
        assert!(
            backend.has_capability(rest),
            "{rest}: the REST provider loads"
        );
        assert!(
            !backend.has_capability(gql),
            "{gql}: refused on a paced host"
        );
    }
}

/// RL15b-d: a reload that paces a GraphQL or JSON-RPC provider's host.
async fn rl15_reload_paces(service: &str, host: &str) {
    let stub = Stub::start(Reply::json("{}")).await;
    let dir = tempfile::TempDir::new().expect("dir");
    let url = stub.url(host, "/g");
    let rpc_name = format!("rl15_{service}");
    std::fs::write(
        dir.path().join(format!("{rpc_name}.yaml")),
        rpc_yaml(&rpc_name, service, &url),
    )
    .expect("write");
    let rest = dir.path().join("rl15_rest.yaml");
    std::fs::write(&rest, rest_yaml("rl15_rest", &url)).expect("write");
    let (backend, executor) = loaded(dir.path()).await;
    let retained =
        crate::capability::parse_capability(&rpc_yaml(&rpc_name, service, &url)).expect("cap");
    assert!(
        backend.has_capability(&rpc_name),
        "premise: loads while the host is unpaced"
    );
    // Control: before the reload the retained definition reaches the stub.
    let _ = executor.execute(&retained, json!({})).await;
    assert_eq!(stub.count(), 1, "control: one request before the reload");

    std::fs::write(&rest, cap_yaml("rl15_rest", &url, 30_000)).expect("rewrite");
    backend.reload().await.expect("reloaded");
    assert!(
        backend.has_capability("rl15_rest"),
        "the REST provider reloads"
    );
    assert!(
        !backend.has_capability(&rpc_name),
        "rl15b: the {service} file is refused"
    );

    // RL15c/d: the retained definition is refused at dispatch, naming the host.
    let err = executor
        .execute(&retained, json!({}))
        .await
        .expect_err("refused at dispatch");
    assert!(err.to_string().contains(host), "names the host: {err}");
    assert_eq!(stub.count(), 1, "nothing after the reload reached the stub");
}

#[tokio::test]
async fn rl15bc_a_reload_that_paces_a_graphql_host_refuses_it_at_load_and_dispatch() {
    rl15_reload_paces("graphql", "rl15g.test").await;
}

#[tokio::test]
async fn rl15d_a_reload_that_paces_a_jsonrpc_host_refuses_it_at_load_and_dispatch() {
    rl15_reload_paces("jsonrpc", "rl15j.test").await;
}

/// The delivery record of one `service` call to `url`: whether it failed,
/// and the effect the record names.
async fn dispatch_effect(service: &str, url: &str) -> (bool, Option<serde_json::Value>) {
    use crate::gateway::delivery_facts;
    let executor = executor(Names::default());
    let call =
        crate::capability::parse_capability(&rpc_yaml("rl15hcall", service, url)).expect("cap");
    let (outcome, facts) = Box::pin(delivery_facts::scope(async {
        let outcome = executor.execute(&call, json!({})).await;
        (outcome, delivery_facts::snapshot())
    }))
    .await;
    let mut fields = serde_json::Map::new();
    delivery_facts::record_fields(facts.as_ref(), false, &mut fields);
    (outcome.is_err(), fields.get("response_effect").cloned())
}

/// RL15h: a GraphQL or JSON-RPC call refused at a paced host is the call's
/// answer, and its delivery records `refused`; the same call to an unpaced
/// host reaches it and records no refusal.
#[tokio::test]
async fn rl15h_a_paced_host_refusal_records_refused_and_an_unpaced_call_does_not() {
    for service in ["graphql", "jsonrpc"] {
        let stub = Stub::start(Reply::json("{}")).await;
        let paced = stub.url(&format!("rl15h-{service}.test"), "/g");
        let open = stub.url(&format!("rl15h-open-{service}.test"), "/g");
        let pacing = CapabilityBackend::new("rl15h", Arc::new(executor(Names::default())));
        pacing
            .register_capability(cap(
                &format!("rl15hrest{service}"),
                &paced,
                Some(30_000),
                false,
            ))
            .expect("premise: the host is paced");
        let (failed, effect) = dispatch_effect(service, &paced).await;
        assert!(failed, "{service}: refused at the paced host");
        assert_eq!(
            effect,
            Some("refused".into()),
            "{service}: recorded as refused"
        );
        assert_eq!(stub.count(), 0, "{service}: nothing reached the paced host");
        let (_, effect) = dispatch_effect(service, &open).await;
        assert_eq!(
            stub.count(),
            1,
            "{service}: control: the unpaced call reached its host"
        );
        assert_ne!(
            effect,
            Some("refused".into()),
            "{service}: control: no refusal recorded"
        );
    }
}

// ── RL18, RL19: base_url providers; the strictest backend wins ───────

/// A paced provider configured as `base_url` plus `path` (as
/// `musicbrainz_search` is), not `endpoint`.
fn base_url_cap(name: &str, base: &str, interval_ms: u64) -> CapabilityDefinition {
    let yaml = format!(
        "fulcrum: \"1.0\"\nname: {name}\ndescription: d\nschema:\n  input:\n    type: object\n    \
         properties:\n      q:\n        type: string\nproviders:\n  primary:\n    service: rest\n    \
         rate_limit:\n      interval_ms: {interval_ms}\n    config:\n      base_url: {base}\n      \
         path: /ws/2/artist\n      method: GET\n      params:\n        q: \"{{q}}\"\n"
    );
    crate::capability::parse_capability(&yaml).expect("capability")
}

#[tokio::test]
async fn rl18_a_base_url_provider_is_paced() {
    let stub = Stub::start(Reply::json("{}")).await;
    let base = format!("http://rl18.test:{}", stub.port);
    let b = backend(Names::default(), vec![base_url_cap("rl18", &base, 30_000)]);
    call(&b, "rl18", "a").await.expect("admitted");
    let err = call(&b, "rl18", "b")
        .await
        .expect_err("paced by its base_url host");
    refusal_wait(&err, "rl18.test", 30_000);
    assert_eq!(stub.count(), 1);
    assert_eq!(
        stub.seen()[0].path,
        "/ws/2/artist",
        "premise: base_url plus path"
    );
}

#[tokio::test]
async fn rl19_a_weaker_backend_does_not_loosen_a_stricter_one() {
    let stub = Stub::start(Reply::json("{}")).await;
    let url = stub.url("rl19.test", "/s");
    let strict = CapabilityBackend::new("rl19-strict", Arc::new(executor(Names::default())));
    strict
        .register_capability(cap("rl19s", &url, Some(30_000), false))
        .expect("registered");
    let weak = CapabilityBackend::new("rl19-weak", Arc::new(executor(Names::default())));
    weak.register_capability(cap("rl19w", &url, Some(300), false))
        .expect("registered");
    call(&strict, "rl19s", "a").await.expect("admitted");
    // Past the weak interval, inside the strict one: only the strict rules.
    // timing-oracle: vs 300 ms rate_limit interval (why: past the weaker 300 ms interval; the refusal needs the call inside the stricter 30000 ms interval, which no stall reaches)
    tokio::time::sleep(Duration::from_millis(1800)).await;
    let err = call(&weak, "rl19w", "b")
        .await
        .expect_err("the strictest interval holds");
    refusal_wait(&err, "rl19.test", 30_000);
    assert_eq!(stub.count(), 1);
}

/// Two backends sharing a name keep separate declarations: the weaker one's
/// registration does not withdraw the stricter one's.
#[tokio::test]
async fn rl19c_a_same_named_weaker_backend_does_not_loosen_a_stricter_one() {
    let stub = Stub::start(Reply::json("{}")).await;
    let url = stub.url("rl19c.test", "/s");
    let strict = CapabilityBackend::new("rl19c", Arc::new(executor(Names::default())));
    strict
        .register_capability(cap("rl19cs", &url, Some(30_000), false))
        .expect("registered");
    let weak = CapabilityBackend::new("rl19c", Arc::new(executor(Names::default())));
    assert_eq!(strict.name, weak.name, "premise: one name");
    weak.register_capability(cap("rl19cw", &url, Some(300), false))
        .expect("registered");
    call(&strict, "rl19cs", "a").await.expect("admitted");
    // The refusal names the interval that rules: the strict one.
    let err = call(&weak, "rl19cw", "b")
        .await
        .expect_err("the strictest interval holds");
    refusal_wait(&err, "rl19c.test", 30_000);
    assert_eq!(stub.count(), 1);
}

/// A dropped backend's declarations are withdrawn: the surviving weaker
/// backend's interval then governs the host.
#[tokio::test]
async fn rl19d_a_dropped_stricter_backend_hands_the_host_to_the_survivor() {
    let stub = Stub::start(Reply::json("{}")).await;
    let url = stub.url("rl19d.test", "/s");
    let strict = CapabilityBackend::new("rl19d-strict", Arc::new(executor(Names::default())));
    strict
        .register_capability(cap("rl19ds", &url, Some(30_000), false))
        .expect("registered");
    let weak = CapabilityBackend::new("rl19d-weak", Arc::new(executor(Names::default())));
    weak.register_capability(cap("rl19dw", &url, Some(300), false))
        .expect("registered");
    call(&strict, "rl19ds", "a").await.expect("admitted");
    drop(strict);
    // timing-oracle: vs 300 ms rate_limit interval (why: a slow runner only lengthens the sleep, so the survivor's 300 ms interval has always passed)
    tokio::time::sleep(Duration::from_millis(1800)).await;
    call(&weak, "rl19dw", "b")
        .await
        .expect("the survivor's interval now governs");
    assert_eq!(stub.count(), 2);
}

// ── RL15e: directory order decides nothing ───────────────────────────

#[tokio::test]
async fn rl15e_a_graphql_directory_loaded_first_is_still_refused() {
    let stub = Stub::start(Reply::json("{}")).await;
    let url = stub.url("rl15e.test", "/g");
    let first = tempfile::TempDir::new().expect("dir");
    let second = tempfile::TempDir::new().expect("dir");
    std::fs::write(
        first.path().join("rl15egql.yaml"),
        rpc_yaml("rl15egql", "graphql", &url),
    )
    .expect("write");
    std::fs::write(
        second.path().join("rl15erest.yaml"),
        cap_yaml("rl15erest", &url, 30_000),
    )
    .expect("write");
    let backend = CapabilityBackend::new("rl15e", Arc::new(executor(Names::default())));
    backend
        .load_from_directory(first.path().to_str().expect("utf-8"))
        .await
        .expect("loaded");
    assert!(
        backend.has_capability("rl15egql"),
        "premise: loads while unpaced"
    );
    backend
        .load_from_directory(second.path().to_str().expect("utf-8"))
        .await
        .expect("loaded");
    assert!(backend.has_capability("rl15erest"));
    assert!(
        !backend.has_capability("rl15egql"),
        "unloaded once its host is paced"
    );
}

#[test]
fn rl15f_registering_a_paced_rest_provider_unloads_a_graphql_one_on_its_host() {
    let url = "http://rl15f.test:9/g";
    let backend = CapabilityBackend::new("rl15f", Arc::new(executor(Names::default())));
    let gql =
        crate::capability::parse_capability(&rpc_yaml("rl15fgql", "graphql", url)).expect("cap");
    backend
        .register_capability(gql)
        .expect("registers while unpaced");
    assert!(backend.has_capability("rl15fgql"), "premise: registered");
    backend
        .register_capability(cap("rl15frest", url, Some(30_000), false))
        .expect("the paced REST provider registers");
    assert!(backend.has_capability("rl15frest"));
    assert!(
        !backend.has_capability("rl15fgql"),
        "unloaded once its host is paced"
    );
}

/// The directory-load sweep reads process-wide pacing: a GraphQL provider
/// registered before another backend paced its host is unloaded at this
/// backend's next directory load, though the directory paces nothing.
#[tokio::test]
async fn rl15g_a_directory_load_unloads_a_graphql_provider_another_backend_now_paces() {
    let url = "http://rl15g.test:9/g";
    let backend = CapabilityBackend::new("rl15g", Arc::new(executor(Names::default())));
    let gql =
        crate::capability::parse_capability(&rpc_yaml("rl15ggql", "graphql", url)).expect("cap");
    backend
        .register_capability(gql)
        .expect("registers while unpaced");
    let other = CapabilityBackend::new("rl15g-rest", Arc::new(executor(Names::default())));
    other
        .register_capability(cap("rl15grest", url, Some(30_000), false))
        .expect("another backend paces the host");
    assert!(backend.has_capability("rl15ggql"), "premise: still listed");
    let empty = tempfile::TempDir::new().expect("dir");
    backend
        .load_from_directory(empty.path().to_str().expect("utf-8"))
        .await
        .expect("loaded");
    assert!(
        !backend.has_capability("rl15ggql"),
        "unloaded at the directory load"
    );
    drop(other);
}

// ── LD8: direct registration obeys the loader's rules ────────────────

#[test]
fn ld8_registering_a_zero_interval_directly_is_refused_and_changes_nothing() {
    // parse_capability applies no load rules; register_capability must.
    let definition = cap("ld8", "http://ld8.test:9/s", Some(0), false);
    let backend = CapabilityBackend::new("ld8", Arc::new(executor(Names::default())));
    let err = backend
        .register_capability(definition)
        .expect_err("refused before the catalogue changes");
    assert!(
        err.to_string().contains("rate_limit.interval_ms is 0"),
        "names the bound: {err}"
    );
    assert!(!backend.has_capability("ld8"));
    assert!(
        crate::capability::pacing::host_key("http://ld8.test:9/s").is_some_and(|key| {
            !crate::capability::pacing::pacers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&key)
        }),
        "no bucket was made for it"
    );
}

#[test]
fn ld8b_registering_a_graphql_provider_on_a_host_it_paces_is_refused() {
    let url = "http://ld8b.test:9/g";
    let backend = CapabilityBackend::new("ld8b", Arc::new(executor(Names::default())));
    backend
        .register_capability(cap("ld8brest", url, Some(30_000), false))
        .expect("premise: the paced REST provider registers");
    let gql =
        crate::capability::parse_capability(&rpc_yaml("ld8bgql", "graphql", url)).expect("cap");
    let err = backend.register_capability(gql).expect_err("refused");
    assert!(
        err.to_string()
            .contains("ld8b.test is paced by a rate_limit"),
        "names the host: {err}"
    );
    assert!(!backend.has_capability("ld8bgql"));
}

#[test]
fn ld8c_a_host_another_backend_paces_refuses_a_graphql_registration() {
    let url = "http://ld8c.test:9/g";
    let pacing = CapabilityBackend::new("ld8c-rest", Arc::new(executor(Names::default())));
    pacing
        .register_capability(cap("ld8crest", url, Some(30_000), false))
        .expect("premise: another backend paces the host");
    // This backend's own catalogue declares nothing on the host.
    let other = CapabilityBackend::new("ld8c-gql", Arc::new(executor(Names::default())));
    let gql =
        crate::capability::parse_capability(&rpc_yaml("ld8cgql", "graphql", url)).expect("cap");
    let err = other.register_capability(gql).expect_err("refused");
    assert!(
        err.to_string()
            .contains("ld8c.test is paced by a rate_limit"),
        "names the host: {err}"
    );
    assert!(!other.has_capability("ld8cgql"));
}

// ── RL19b: a withdrawn declaration ───────────────────────────────────

#[tokio::test]
async fn rl19b_a_withdrawn_strict_declaration_hands_the_host_to_the_weaker() {
    let stub = Stub::start(Reply::json("{}")).await;
    let url = stub.url("rl19b.test", "/s");
    let dir = tempfile::TempDir::new().expect("dir");
    let strict_file = dir.path().join("rl19bs.yaml");
    std::fs::write(&strict_file, cap_yaml("rl19bs", &url, 30_000)).expect("write");
    let (strict, _) = loaded(dir.path()).await;
    let weak = CapabilityBackend::new("rl19b-weak", Arc::new(executor(Names::default())));
    weak.register_capability(cap("rl19bw", &url, Some(300), false))
        .expect("registered");
    call(&strict, "rl19bs", "a").await.expect("admitted");
    // The strict backend's reload drops its declaration: 300 ms now rules.
    std::fs::remove_file(&strict_file).expect("remove");
    strict.reload().await.expect("reloaded");
    // timing-oracle: vs 300 ms rate_limit interval (why: a slow runner only lengthens the sleep, so the weaker 300 ms interval has always passed)
    tokio::time::sleep(Duration::from_millis(1800)).await;
    call(&weak, "rl19bw", "b")
        .await
        .expect("the weaker interval now governs");
    assert_eq!(stub.count(), 2);
}
