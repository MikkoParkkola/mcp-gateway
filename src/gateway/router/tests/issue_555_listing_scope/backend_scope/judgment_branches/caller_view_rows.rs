// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Existence reads on a call's path that answer by the caller's view of the
//! capability provider: a provider hidden from the caller answers as an
//! unregistered name does, never with what the provider holds.

use super::*;

/// The env key the keyed capability's credential is read from.
const KEY_VAR: &str = "HIDDEN_ORACLE_ROW_CAP_KEY";
/// A value only the provider's stored output carries.
const MARKER: &str = "stored-output-marker-7f3c";

/// A loopback endpoint answering every GET on `/read` with [`MARKER`].
async fn marker_endpoint() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("address").port();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/read",
            axum::routing::get(|| async { axum::Json(json!({ "marker": MARKER })) }),
        );
        axum::serve(listener, app).await.expect("serve");
    });
    port
}

/// The provider `caps` with `cap_keyed`, whose credential [`KEY_VAR`] is set
/// in the returned environment, served by `port`: the provider and the
/// environment (the temp dir holds its file).
fn keyed_caps(
    port: u16,
) -> (
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
    let base_url = crate::test_fixture_host::fixture_url(port);
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
    let (caps, env, _dir) = keyed_caps(marker_endpoint().await);
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

/// Playbook `pb`: `beta_tool` on `beta`, then `alpha_write` on `alpha`, under
/// a certificate rule that refuses `deny_tools` by name, with `alpha` and
/// `beta` swapped for recorders. Runs `pb` as a plain call with no API key:
/// the whole answer and every tool each backend was sent.
async fn run_two_step_playbook(deny_tools: &[&str]) -> (Value, Vec<String>) {
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0", "name": "pb", "description": "two steps",
        "steps": [
            {"name": "s0", "tool": "beta_tool", "server": "beta", "arguments": {}},
            {"name": "s1", "tool": "alpha_write", "server": "alpha", "arguments": {}},
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
    for (name, tools) in [
        ("alpha", vec!["alpha_read", "alpha_write"]),
        ("beta", vec!["beta_tool"]),
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
/// (`alpha_write`, refused by name on a backend still visible through
/// `alpha_read`) is refused with the neutral step refusal before any step
/// runs: the first step's backend is sent nothing. Control: with nothing
/// refused, the same playbook sends both steps, so the zero is not vacuous.
#[tokio::test]
async fn an_unkeyed_playbook_with_a_refused_later_step_runs_no_step() {
    let (refused, sent) = run_two_step_playbook(&["alpha_write"]).await;
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
        ["beta_tool", "alpha_write"],
        "control: a permitted playbook did not send both steps: {ran}"
    );
}
