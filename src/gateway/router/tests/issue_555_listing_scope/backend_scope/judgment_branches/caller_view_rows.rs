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

/// How a keyed task names its capability.
#[cfg(feature = "firewall")]
#[derive(Clone, Copy)]
enum Called {
    /// `gateway_invoke` of `caps`' `cap_keyed`.
    Invoke,
    /// `cap_keyed` called by name, surfaced on `caps`: the run is pinned.
    Surfaced,
}

/// A task of `cap_keyed` on `caps`, `called` as given, submitted while its
/// key is set, with `after` landing as the worker starts its dispatch
/// (`None` changes nothing): the settled `tasks/get` (task id, trace ids and
/// instants masked), the capability executions the run made, and how many
/// operator warnings named the call a withheld surfaced tool.
#[cfg(feature = "firewall")]
async fn keyed_run(called: Called, after: Option<AfterRun>, key: &str) -> (String, usize, usize) {
    let surfaced = match called {
        Called::Invoke => Vec::new(),
        Called::Surfaced => vec![crate::config::SurfacedToolConfig {
            server: "caps".to_string(),
            tool: "cap_keyed".to_string(),
        }],
    };
    let (router, state) = with_mtls_tuned(
        Auth::Off,
        move |meta| meta.with_surfaced_tools(surfaced),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    let (caps, env, _dir) = keyed_caps();
    state.meta_mcp.set_capabilities(caps);
    assert!(
        !judgment(&state, None, Some(&agent_cert())).hides("caps"),
        "premise: the provider is visible at submit"
    );
    let hook_state = Arc::clone(&state);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || match after {
        Some(AfterRun::Hide) => env.set(Arc::new(crate::config::EnvOverlay::none())),
        Some(AfterRun::Unregister) => hook_state.meta_mcp.set_capabilities(Arc::new(
            crate::capability::CapabilityBackend::new(
                "other",
                Arc::new(crate::capability::CapabilityExecutor::new()),
            ),
        )),
        None => {}
    });
    let (_logs, logged) = warnings();
    let before = executed();
    let id = match called {
        Called::Invoke => submit_task(&router, "caps", "cap_keyed", key).await,
        Called::Surfaced => submit_surfaced(&router, "cap_keyed", key).await,
    };
    let settled = settle_task(&router, &id).await;
    // Settled: a terminal status, or the read's own refusal of a task whose
    // provider is gone from the reader's view (the removed-backend answer).
    let status = settled.pointer("/result/status").and_then(Value::as_str);
    assert!(
        matches!(status, Some("completed" | "failed" | "cancelled"))
            || settled.get("error").is_some(),
        "the run did not settle: {settled}"
    );
    let settled = settled.to_string();
    let ran = executed() - before;
    let trace = regex::Regex::new(r"gw-[0-9a-f-]{36}").expect("pattern");
    let instant = regex::Regex::new(r"\d{4}-\d{2}-\d{2}T[0-9:.]+Z").expect("pattern");
    let masked = trace
        .replace_all(&settled.replace(id.as_str(), "TASK"), "gw-ID")
        .into_owned();
    let withheld = String::from_utf8_lossy(&logged.lock().expect("log buffer"))
        .matches("Surfaced tool withheld from a call by its name")
        .count();
    (
        instant.replace_all(&masked, "AT").into_owned(),
        ran,
        withheld,
    )
}

/// The warnings written on this thread while the guard lives, as text.
/// Thread-local: the run's worker shares the test's current-thread runtime.
#[cfg(feature = "firewall")]
fn warnings() -> (
    tracing::subscriber::DefaultGuard,
    Arc<std::sync::Mutex<Vec<u8>>>,
) {
    struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    crate::test_log_capture::keep_interest_open();
    let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || Sink(Arc::clone(&writer)))
        .finish();
    (tracing::subscriber::set_default(subscriber), buffer)
}

/// The task worker judges hiding as its caller at run time: a provider whose
/// key is revoked between the submit and the run lists no tool, so it is
/// hidden from the caller, and the run settles byte for byte as one whose
/// provider was removed at the same point, with nothing executed. Control:
/// with nothing changed, the run executes the capability.
#[cfg(feature = "firewall")]
// Current-thread on purpose: the dispatch seam, the execution counter and
// the warning capture are thread-local.
#[tokio::test(flavor = "current_thread")]
async fn a_task_whose_provider_is_hidden_before_its_run_settles_as_one_removed() {
    assert_hidden_run_settles_as_removed(Called::Invoke, "keyed-run").await;
}

/// A surfaced pin on the capability provider is judged as its caller at run
/// time too: a surfaced capability whose key is revoked between the submit
/// and the run settles as one whose surfaced name no longer resolves (its
/// provider removed at the same point), executes nothing, and logs what the
/// removed one's run logs (the dispatch gate records the absence). Control:
/// with nothing changed, the pinned run executes the capability.
#[cfg(feature = "firewall")]
// Current-thread on purpose: the dispatch seam, the execution counter and
// the warning capture are thread-local.
#[tokio::test(flavor = "current_thread")]
async fn a_surfaced_task_whose_provider_is_hidden_before_its_run_settles_as_one_removed() {
    assert_hidden_run_settles_as_removed(Called::Surfaced, "keyed-pin").await;
}

/// [`keyed_run`] three times, `called` alike: unchanged (the control),
/// hidden and removed. The hidden run executes nothing, settles as the
/// removed one, and leaves the operator the removed one's record: a pinned
/// target recorded absent is never logged as a surfaced tool withheld for
/// lack of a listing.
#[cfg(feature = "firewall")]
async fn assert_hidden_run_settles_as_removed(called: Called, key: &str) {
    let (control, control_ran, _) = keyed_run(called, None, &format!("{key}-c")).await;
    assert!(
        control_ran > 0 && control.contains(MARKER),
        "control: the visible provider's run did not execute: {control}"
    );
    let (hidden, hidden_ran, hidden_logged) =
        keyed_run(called, Some(AfterRun::Hide), &format!("{key}-h")).await;
    let (removed, _, removed_logged) =
        keyed_run(called, Some(AfterRun::Unregister), &format!("{key}-r")).await;
    assert_eq!(hidden_ran, 0, "the hidden provider ran: {hidden}");
    assert_eq!(
        hidden, removed,
        "a task whose provider was hidden before its run settles unlike a removed one"
    );
    assert_eq!(
        hidden_logged, removed_logged,
        "the operator's record of a hidden run differs from a removed one's"
    );
}

/// A modern task submit of the surfaced tool `tool`, called by name, keyed
/// by `key`; returns the task id.
#[cfg(feature = "firewall")]
async fn submit_surfaced(router: &axum::Router, tool: &str, key: &str) -> String {
    let mut meta = crate::gateway::router::tests::modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let params = json!({"name": tool, "arguments": {}, "task": {}, "_meta": meta});
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", tool),
    ];
    let (_, body) = post_cert_headers(router, "/mcp", None, params, &headers).await;
    let body: Value = serde_json::from_str(&body).expect("json");
    body.pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the surfaced submit was refused: {body}"))
        .to_owned()
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

/// `account`'s capability provider (a REST capability on a per-caller
/// managed account, so its tool stays listed) under no routing profile, for a
/// certificate whose rule refuses every tool on the provider and on the
/// unregistered twin by name: the provider is hidden by policy, and the twin
/// meets the same rule. The router, the state and the store.
async fn account_provider_hidden(
    account: &CapabilityAccount,
) -> (
    axum::Router,
    Arc<crate::gateway::router::AppState>,
    crate::gateway::router::tests::FixtureDir,
) {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    let (mut state, store) =
        crate::gateway::router::tests::meta_fixture::test_router_app_state_with_meta(
            &crate::config::AuthConfig::default(),
            None,
            |meta| account.install(meta),
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
            // The provider and the unregistered twin alike: the rule refuses
            // every tool on either by name, so the provider is hidden.
            deny: ToolScopeConfig {
                backends: vec![CAPABILITY_SERVER.to_string(), UNREGISTERED.to_string()],
                tools: Vec::new(),
            },
        }],
        ..Default::default()
    }));
    assert!(
        judgment(&state, None, Some(&agent_cert())).hides(CAPABILITY_SERVER),
        "premise: the certificate's rule hides the provider"
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

/// An admin's unconfirmed web UI call of `server`'s `cap_keyed`, the
/// provider `caps` hidden from the admin's certificate since its key was
/// revoked (it lists nothing, yet still defines `cap_keyed`, declared
/// read-only): the status and the body.
async fn ui_call_of(server: &str) -> (u16, String) {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    let admin = crate::config::ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(b"ui-admin")),
        name: "ui-admin".to_string(),
        backends: vec!["*".to_string()],
        admin: true,
        ..Default::default()
    };
    let auth = crate::config::AuthConfig {
        enabled: true,
        api_keys: vec![admin],
        ..Default::default()
    };
    let (mut state, _store) =
        crate::gateway::router::tests::test_router_app_state_with_auth_and_config(
            &auth,
            crate::config::Config::default(),
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
    let (caps, env, _dir) = keyed_caps();
    state.meta_mcp.set_capabilities(caps);
    env.set(Arc::new(crate::config::EnvOverlay::none()));
    assert!(
        judgment(&state, None, Some(&agent_cert())).hides("caps"),
        "premise: the provider is hidden"
    );
    let body = json!({"server": server, "tool": "cap_keyed", "arguments": {},
                      "confirm_write": false});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/ui/api/tools/call")
        .header("authorization", "Bearer ui-admin")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    request.extensions_mut().insert(agent_cert());
    let response = crate::gateway::router::create_router(Arc::clone(&state))
        .oneshot(request)
        .await
        .expect("answers");
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Site 2 (`invoke/pre_dispatch.rs`, the read-only declaration the web UI
/// gate and the response cache read): an admin's web UI call of a hidden
/// provider's read-only capability, without `confirm_write`, answers as the
/// same call on an unregistered name: the hidden definition's `read_only`
/// does not let it past the confirmation gate.
#[tokio::test]
async fn a_web_ui_call_on_a_hidden_provider_answers_as_an_unregistered_name() {
    let hidden = ui_call_of("caps").await;
    let unregistered = ui_call_of(UNREGISTERED).await;
    assert_alike("web UI call", "caps", &hidden, &unregistered);
}
