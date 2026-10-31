// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Existence reads on a call's path that answer by the caller's view of the
//! capability provider: a provider hidden from the caller answers as an
//! unregistered name does, never with what the provider holds.

use super::*;

/// The env key the keyed capability's credential is read from.
const KEY_VAR: &str = "HIDDEN_ORACLE_ROW_CAP_KEY";
/// Text only the keyed capability's stored result carries: its executor
/// refuses to send the key in cleartext to the fixture host, and that tool
/// result (`isError`, status completed) is what the task stores.
const MARKER: &str = "refusing to send a capability credential in cleartext";

/// The provider `caps` with `cap_keyed`, whose credential [`KEY_VAR`] is set
/// in the returned environment: the provider and the environment (the temp
/// dir holds its file).
fn keyed_caps() -> (
    Arc<crate::capability::CapabilityBackend>,
    Arc<crate::config::LiveEnv>,
    tempfile::TempDir,
) {
    let dir = tempfile::TempDir::new().expect("env dir");
    let file = dir.path().join("caps.env");
    std::fs::write(&file, format!("{KEY_VAR}=present\n")).expect("write env");
    // An env file is read only when its owner alone may read it.
    #[cfg(unix)]
    std::fs::set_permissions(
        &file,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .expect("owner-only env file");
    let env = Arc::new(crate::config::LiveEnv::new(
        Arc::new(crate::config::EnvOverlay::from_paths(&[file])),
        crate::config::ResolvedEnvFiles::default(),
    ));
    let base_url = crate::test_fixture_host::fixture_url(9);
    let definition = crate::capability::parse_capability(&format!(
        "name: cap_keyed\n\
         description: Read with a key\n\
         metadata:\n\
         \x20 read_only: true\n\
         auth:\n\
         \x20 required: true\n\
         \x20 type: api_key\n\
         \x20 key: env:{KEY_VAR}\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: {base_url}\n\
         \x20     path: /read\n\
         \x20     method: GET\n"
    ))
    .expect("the capability parses");
    let client = crate::test_fixture_host::fixture_client(std::time::Duration::from_secs(5));
    let executor = crate::capability::CapabilityExecutor::new()
        .with_test_http_client(client)
        .with_env(Arc::clone(&env));
    let backend = Arc::new(crate::capability::CapabilityBackend::new(
        "caps",
        Arc::new(executor),
    ));
    backend
        .register_capability(definition)
        .expect("the capability registers");
    (backend, env, dir)
}

/// How the provider stops being the caller's after the task completed.
#[derive(Clone, Copy)]
enum AfterRun {
    /// Its key is revoked: it lists no tool, so the caller's rule admits none
    /// of its tools and it is hidden, yet it still defines `cap_keyed`.
    Hide,
    /// Replaced by a provider of another name: `caps` is unregistered.
    Unregister,
}

/// A task of `cap_keyed` on `caps`, submitted and settled while the provider
/// is visible, then `after` applied and the task read again with
/// `tasks/get`: the settled read and the later one, task and trace ids
/// masked.
async fn stored_read(after: AfterRun) -> (String, String) {
    let (router, state) = with_mtls_state((&["*"], &["*"]), (&[], &[])).await;
    let (caps, env, _dir) = keyed_caps();
    assert_eq!(
        caps.get_tools().len(),
        1,
        "premise: the keyed capability is listed while its key is set"
    );
    state.meta_mcp.set_capabilities(caps);
    assert!(
        !judgment(&state, None, Some(&agent_cert())).hides("caps"),
        "premise: the provider is visible at submit"
    );
    let id = submit_task(&router, "caps", "cap_keyed", "stored-read").await;
    let settled = settle_task(&router, &id).await.to_string();
    match after {
        AfterRun::Hide => env.set(Arc::new(crate::config::EnvOverlay::none())),
        AfterRun::Unregister => {
            state
                .meta_mcp
                .set_capabilities(Arc::new(crate::capability::CapabilityBackend::new(
                    "other",
                    Arc::new(crate::capability::CapabilityExecutor::new()),
                )));
        }
    }
    let hidden = judgment(&state, None, Some(&agent_cert())).hides("caps");
    assert_eq!(
        hidden,
        matches!(after, AfterRun::Hide),
        "premise: hidden only after the key is revoked"
    );
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tasks/get"),
        ("mcp-name", id.as_str()),
    ];
    let params = json!({"taskId": id, "_meta": crate::gateway::router::tests::modern_meta()});
    let (_, later) = post_rpc_cert_headers(&router, "tasks/get", params, &headers).await;
    let trace = regex::Regex::new(r"gw-[0-9a-f-]{36}").expect("pattern");
    let mask = |body: &str| {
        trace
            .replace_all(&body.replace(id.as_str(), "TASK"), "gw-ID")
            .into_owned()
    };
    (mask(&settled), mask(&later))
}

/// Site 8 (`task_replay/judging.rs`, the removed-backend refusal): a stored
/// task result whose provider is hidden from the reader by the time it is
/// read answers byte for byte as one whose provider was removed, never with
/// the stored output. Tasks are modern-only and a modern request carries no
/// session, so the provider is hidden by a revoked key rather than a session
/// profile.
#[tokio::test]
async fn a_stored_result_of_a_provider_hidden_since_answers_as_one_removed() {
    let (settled, hidden) = stored_read(AfterRun::Hide).await;
    let (_, removed) = stored_read(AfterRun::Unregister).await;
    assert!(
        settled.contains(MARKER),
        "control: a visible provider's stored output is served: {settled}"
    );
    assert!(
        !hidden.contains(MARKER),
        "the hidden provider's stored output was served: {hidden}"
    );
    assert_eq!(
        hidden, removed,
        "a hidden provider's stored result answers unlike a removed one's"
    );
}

/// Playbook `pb`: `beta_tool` on `beta`, then `alpha_read` on `alpha`, under
/// a certificate rule that refuses `deny_tools` by name, with `alpha` and
/// `beta` swapped for recorders. Runs `pb` as a plain call with no API key:
/// the whole answer and every tool each backend was sent.
async fn run_two_step_playbook(deny_tools: &[&str]) -> (Value, Vec<String>) {
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0", "name": "pb", "description": "two steps",
        "steps": [
            {"name": "s0", "tool": "beta_tool", "server": "beta", "arguments": {}},
            {"name": "s1", "tool": "alpha_read", "server": "alpha", "arguments": {}},
        ]
    }))
    .expect("the playbook deserialises");
    let (router, state) = with_mtls_tuned(
        Auth::Off,
        move |meta| {
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        },
        (&["*"], &["*"]),
        (&[], deny_tools),
    )
    .await;
    let mut recorders = Vec::new();
    // In step order, so the sends read in the order they were made.
    for (name, tools) in [
        ("beta", vec!["beta_tool"]),
        ("alpha", vec!["alpha_read", "alpha_write"]),
    ] {
        let upstream = Arc::new(super::super::super::Upstream {
            tools,
            calls: parking_lot::Mutex::new(Vec::new()),
        });
        backend(&state, name)
            .set_transport_for_test(Arc::clone(&upstream) as Arc<dyn crate::transport::Transport>);
        recorders.push(upstream);
    }
    for name in ["alpha", "beta"] {
        assert!(
            !judgment(&state, None, Some(&agent_cert())).hides(name),
            "premise: {name} is visible"
        );
    }
    let (_, body) = post_cert_key(
        &router,
        "/mcp",
        None,
        json!({"name": "gateway_run_playbook", "arguments": {"name": "pb", "arguments": {}}}),
    )
    .await;
    let sent = recorders
        .iter()
        .flat_map(|upstream| upstream.calls.lock().clone())
        .collect();
    (serde_json::from_str(&body).expect("json"), sent)
}

/// An unkeyed caller's playbook whose second step the route stage refuses
/// (`alpha_read`, refused by name on a backend still visible through
/// `alpha_write`) is refused with the neutral step refusal before any step
/// runs: the first step's backend is sent nothing. Control: with nothing
/// refused, the same playbook sends both steps, so the zero is not vacuous.
#[tokio::test]
async fn an_unkeyed_playbook_with_a_refused_later_step_runs_no_step() {
    let (refused, sent) = run_two_step_playbook(&["alpha_read"]).await;
    assert_eq!(
        (
            refused.pointer("/error/code").cloned(),
            refused.pointer("/error/message").cloned(),
            sent,
        ),
        (
            Some(json!(-32003)),
            Some(json!("step not permitted for this caller")),
            Vec::<String>::new(),
        ),
        "a refused later step was not refused before step 1 ran: {refused}"
    );
    let (ran, sent) = run_two_step_playbook(&[]).await;
    assert_eq!(
        sent,
        ["beta_tool", "alpha_read"],
        "control: a permitted playbook did not send both steps: {ran}"
    );
}

use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    CAPABILITY_SERVER, CAPABILITY_TOOL, CapabilityAccount,
};

/// `account`'s capability provider (a REST capability on a managed account)
/// under a default profile that leaves the provider out, for a certificate
/// whose rule admits everything: the provider is hidden, and nothing refuses
/// it before the route stage. The router, the state and the store.
async fn account_provider_hidden(
    account: &CapabilityAccount,
) -> (
    axum::Router,
    Arc<crate::gateway::router::AppState>,
    crate::gateway::router::tests::FixtureDir,
) {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    let profiles = HashMap::from([(
        "noprovider".to_string(),
        RoutingProfileConfig {
            deny_backends: Some(vec![CAPABILITY_SERVER.to_string()]),
            ..Default::default()
        },
    )]);
    let (mut state, store) =
        crate::gateway::router::tests::meta_fixture::test_router_app_state_with_meta(
            &crate::config::AuthConfig::default(),
            None,
            |meta| {
                account
                    .install(meta)
                    .with_profile_registry(ProfileRegistry::from_config(&profiles, "noprovider"))
            },
        )
        .await;
    let everything = ToolScopeConfig {
        backends: vec!["*".to_string()],
        tools: vec!["*".to_string()],
    };
    Arc::get_mut(&mut state)
        .expect("state is unique")
        .mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(&MtlsConfig {
        enabled: true,
        policies: vec![PolicyRuleConfig {
            match_criteria: CertMatchConfig {
                cn: Some("agent".to_string()),
                ..Default::default()
            },
            allow: everything,
            deny: ToolScopeConfig {
                backends: Vec::new(),
                tools: Vec::new(),
            },
        }],
        ..Default::default()
    }));
    assert!(
        judgment(&state, None, Some(&agent_cert())).hides(CAPABILITY_SERVER),
        "premise: the profile hides the provider"
    );
    (
        crate::gateway::router::create_router(Arc::clone(&state)),
        state,
        store,
    )
}

/// A modern `method` on `/mcp` as the `agent` certificate, carrying the
/// verified `identity` when given: the status and the body.
async fn send_modern(
    router: &axum::Router,
    (method, name): (&str, &str),
    params: Value,
    identity: Option<crate::key_server::oidc::VerifiedIdentity>,
) -> (u16, String) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 5, "method": method, "params": params}).to_string(),
        ))
        .expect("request");
    request.extensions_mut().insert(agent_cert());
    if let Some(identity) = identity {
        request.extensions_mut().insert(identity);
    }
    let response = router.clone().oneshot(request).await.expect("answers");
    let status = response.status().as_u16();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// `gateway_invoke` of the account capability's tool on `server`, modern,
/// task-augmented under idempotency `key` when given.
fn account_invoke(server: &str, task_key: Option<&str>) -> Value {
    let mut meta = crate::gateway::router::tests::modern_meta();
    let mut params = json!({"name": "gateway_invoke",
        "arguments": {"server": server, "tool": CAPABILITY_TOOL, "arguments": {}}});
    if let Some(key) = task_key {
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
        params["task"] = json!({});
    }
    params["_meta"] = meta;
    params
}

/// Site 3 (`invoke/propagation.rs`, the capability account resolution): a
/// caller with no verified identity, so no account binding, calls the
/// hidden provider's account-backed tool. It answers as the unregistered
/// name does, never with the account's refusal or connect offer, and nothing
/// reaches the vendor.
#[tokio::test]
async fn an_unbound_callers_hidden_account_capability_answers_as_an_unregistered_name() {
    let account = CapabilityAccount::start(false).await;
    let (router, _state, _store) = account_provider_hidden(&account).await;
    let route = ("tools/call", "gateway_invoke");
    let hidden = send_modern(
        &router,
        route,
        account_invoke(CAPABILITY_SERVER, None),
        None,
    )
    .await;
    let unregistered = send_modern(&router, route, account_invoke(UNREGISTERED, None), None).await;
    assert_eq!(
        account.peer_requests(),
        0,
        "the hidden capability reached the vendor"
    );
    assert_alike(
        "unbound caller, account capability",
        CAPABILITY_SERVER,
        &hidden,
        &unregistered,
    );
}

/// What a task-augmented call on `server` shows the caller: the refusal at
/// intake, or the submit and the task's settled `tasks/get`, the task id and
/// the timestamps masked (`assert_alike` masks trace ids).
async fn account_task_answer(server: &str) -> (u16, String) {
    let account = CapabilityAccount::start(false).await;
    let (router, _state, _store) = account_provider_hidden(&account).await;
    account.fail_custody_for_test(true);
    let alice = Some(CapabilityAccount::alice());
    let submitted = send_modern(
        &router,
        ("tools/call", "gateway_invoke"),
        account_invoke(server, Some("acct-task")),
        alice.clone(),
    )
    .await;
    let made: Value = serde_json::from_str(&submitted.1).expect("json");
    let Some(id) = made.pointer("/result/taskId").and_then(Value::as_str) else {
        return submitted;
    };
    let get = json!({"taskId": id, "_meta": crate::gateway::router::tests::modern_meta()});
    let settled = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let read = send_modern(&router, ("tasks/get", id), get.clone(), alice.clone()).await;
            let body: Value = serde_json::from_str(&read.1).expect("json");
            if body.pointer("/result/status").and_then(Value::as_str) != Some("working") {
                return read;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the task never settled");
    assert_eq!(account.peer_requests(), 0, "{server}: the vendor was sent");
    // The two tasks are made at different instants.
    let instant = regex::Regex::new(r"\d{4}-\d{2}-\d{2}T[0-9:.]+Z").expect("pattern");
    let shown = format!("submitted {} settled {}", submitted.1, settled.1).replace(id, "TASK");
    (settled.0, instant.replace_all(&shown, "AT").into_owned())
}

/// Site 1 (`account_outcome.rs`, the capability account a task intake
/// judges): a task naming the hidden provider's account-backed tool, its
/// account's custody busy, answers at submit and at settle as one naming an
/// unregistered name: no account judgment, no retryable refusal naming it.
#[tokio::test]
async fn a_task_on_a_hidden_account_capability_with_busy_custody_answers_as_an_unregistered_name() {
    let hidden = account_task_answer(CAPABILITY_SERVER).await;
    let unregistered = account_task_answer(UNREGISTERED).await;
    assert_alike(
        "task, busy custody",
        CAPABILITY_SERVER,
        &hidden,
        &unregistered,
    );
}
