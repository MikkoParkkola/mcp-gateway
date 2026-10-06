// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A reload must not enter the state startup refuses.

use super::*;

// -------------------------------------------------------------------------
// Posture refusal — a reload must not enter the state startup refuses
//
// The gateway refuses to start when it is reachable by name and its tools are
// invocable without a credential (`network_bind_refusal`). `server.public_url`
// is re-read per request, so adding one to a running gateway reaches that state
// without passing the startup check. These cases pin the refusal that closes it.
//
// The three masking cases are the ones that matter. A refusal judged against the
// FILE passes them by reading fields the reload never applies: the file may say
// authentication is on while the router is still running the startup snapshot.
// They fail against that version and pass against one judged on the config that
// will be in force. See docs/design/unauthenticated-network-posture.md,
// Decision C.
// -------------------------------------------------------------------------

/// A running config that startup would not have refused: loopback, no declared
/// public URL. Every posture case starts here, because the refusal only fires on
/// a reload that would ENTER the refusable state.
fn clean_running() -> Config {
    Config::default()
}

/// The reload context of [`test_reload_context`], with the running config named
/// rather than defaulted, so a case can start from a gateway whose tools are
/// already closed.
fn posture_context(config_path: &std::path::Path, running: Config) -> ReloadContext {
    ReloadContext::new(
        config_path.to_path_buf(),
        Arc::new(LiveConfig::new(running)),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
}

#[tokio::test]
async fn a_reload_publishing_the_gateway_over_open_tools_is_refused() {
    // GIVEN: a gateway running on loopback with no declared public URL
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: the file declares a public URL, leaving the tools reachable
    write_owner_only(&path, "server:\n  public_url: \"https://gw.example.com\"\n").unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx
        .reload_outcome()
        .await
        .expect_err("a reload that opens the tool surface to the network was applied");

    // THEN: it is refused, under the shared literal every consumer keys on
    assert!(
        err.starts_with(POSTURE_REFUSED_PREFIX),
        "refusal did not carry the shared prefix: {err}"
    );
    // AND: the message carries the remedy, not merely a label
    assert!(
        err.contains("gw.example.com"),
        "refusal did not name the exposure: {err}"
    );
    assert!(
        err.contains("auth.enabled"),
        "refusal did not carry the remedy: {err}"
    );
    // AND: it says what a restart does with this same file
    assert!(
        err.contains("next start"),
        "refusal did not say what a restart does with this file: {err}"
    );
    // AND: it makes NO claim about what remains in force, anywhere in the
    // message — prefix included. A refusal cannot speak for the whole running
    // process: `LiveConfig::pending_restart_fields` can already hold a
    // restart-only edit published by an EARLIER reload, so the running process
    // and the published config differ before this reload is even attempted.
    // "Unchanged" is a claim about state this path never reads.
    //
    // The reason recorded here until 2026-09-06 was the MIK-7256 leak —
    // `Config::load` applying the candidate's env files to the process, read
    // back per call through `std::env::var`. That mechanism is GONE: env files
    // build an `EnvOverlay` published only by a reload that got that far
    // (`ReloadContext::publish_overlay`, `src/config_reload/reload_context.rs`),
    // and `env::var` no longer appears anywhere under `src/capability/`. The
    // assertion outlived its rationale; the rationale above is the one that
    // holds today.
    //
    // Every phrasing that has appeared here, not only the last one. An earlier
    // version of this case listed the two the body had just been corrected of,
    // and so did not notice that the shared PREFIX still said "the running
    // gateway is unchanged" — the same claim, three words shorter, in the one
    // part of the message the test was not reading.
    for claim in [
        "unchanged",
        "in force",
        "still serving",
        "nothing was applied",
        "no changes were made",
    ] {
        assert!(
            !err.to_ascii_lowercase().contains(claim),
            "the refusal claims {claim:?} — what remains in force is what it \
             cannot know: {err}"
        );
    }
    // AND: it says precisely what did not happen — no backend moved, nothing
    // published. Not "nothing was applied", which would be a wider claim than
    // THIS check can keep: it asks `network_bind_refusal` and nothing else,
    // while a restart reads the whole file. (Until 2026-09-06 the reason given
    // here was the MIK-7256 leak — `Config::load` having already applied the
    // candidate's `env_files`. That mechanism is gone; the assertion is not.)
    assert!(
        err.contains("No backend was started or stopped")
            && err.contains("no configuration was published"),
        "refusal did not say what was skipped: {err}"
    );
}

#[tokio::test]
async fn enabling_auth_in_the_same_edit_does_not_mask_the_exposure() {
    // GIVEN: the same running gateway
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: the file declares a public URL AND enables authentication — the
    // remediation this project recommends everywhere. A reload does not apply
    // `auth`: the router snapshots it at construction, so the request path is
    // still running the old, permissive state while the origin gate has already
    // started admitting the new host.
    write_owner_only(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nsecurity:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx.reload_outcome().await.expect_err(
        "a reload was applied because the FILE enabled auth, while the running \
         gateway's auth is unchanged — the exposure this refusal exists to stop",
    );
    assert!(err.starts_with(POSTURE_REFUSED_PREFIX), "{err}");
}

#[tokio::test]
async fn setting_the_override_in_the_same_edit_does_not_mask_it_either() {
    // GIVEN: the same running gateway
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: the file declares a public URL and sets the escape hatch. Like
    // `auth`, the override is restart-only, so it silences nothing on a running
    // process. A refusal that read the file would let it silence this one.
    write_owner_only(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\n  allow_unauthenticated_network_bind: true\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx
        .reload_outcome()
        .await
        .expect_err("the file's override silenced a refusal it cannot silence until a restart");
    assert!(err.starts_with(POSTURE_REFUSED_PREFIX), "{err}");
}

#[tokio::test]
async fn a_refused_reload_applies_nothing_at_all() {
    // GIVEN: a gateway running on loopback, with no backends
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: one edit adds both a backend and the public URL that refuses
    write_owner_only(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nbackends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());

    let _ = ctx
        .reload_outcome()
        .await
        .expect_err("the reload was applied");

    // THEN: the backend in the same file was never registered — the refusal runs
    // before `apply_patch`, which stops and starts backends
    assert!(
        ctx.registry.get("svc").is_none(),
        "a refused reload registered a backend from the same file"
    );
    // AND: nothing was published, so the origin gate never sees the new host
    assert!(
        ctx.live_config.get().server.public_url.is_none(),
        "a refused reload published its config"
    );
}

#[tokio::test]
async fn a_reload_that_does_not_open_the_tools_still_applies() {
    // GIVEN: a gateway whose RUNNING config already closes the tool surface.
    //
    // From the running config, not the file: reading it from the file is the
    // mistake the refusal prevents, and a case written that way passes by it.
    let mut running = Config::default();
    running.auth.enabled = true;
    running.auth.bearer_token = Some("secret".to_string());
    running.server.cleartext_http = crate::config::CleartextHttp::TlsTerminatedUpstream;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: the same public URL is declared, over tools that need a credential
    write_owner_only(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\n  cleartext_http: tls_terminated_upstream\nsecurity:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\nbackends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .unwrap();
    let ctx = posture_context(&path, running);

    // THEN: it applies, and the backend beside it registers
    ctx.reload_outcome()
        .await
        .expect("a reload that leaves the tools behind a credential was refused");
    assert!(
        ctx.registry.get("svc").is_some(),
        "an applied reload did not register its backend"
    );
    assert_eq!(
        ctx.live_config.get().server.public_url.as_deref(),
        Some("https://gw.example.com")
    );
}

#[tokio::test]
async fn a_published_but_not_running_auth_value_does_not_mask_it_either() {
    // GIVEN: a gateway running with authentication OFF, whose operator has just
    // done what this project advises — turned it on in the file and been told it
    // is restart-required. The value is now PUBLISHED in the live snapshot and
    // is not in force: the router is still running the startup auth state.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "security:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());
    ctx.reload_outcome()
        .await
        .expect("enabling auth with no public_url is not a refusable change");
    assert!(
        ctx.live_config.get().auth.enabled,
        "the first reload did not publish, so the second cannot demonstrate anything"
    );
    assert!(
        !ctx.live_config.running().auth.enabled,
        "the running snapshot moved, which it must never do without a restart"
    );

    // WHEN: they then add the public URL — a second reload, against a published
    // snapshot that disagrees with what is running
    write_owner_only(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nsecurity:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    )
    .unwrap();

    // THEN: still refused. A refusal that overlaid onto the PUBLISHED snapshot
    // would read `auth.enabled = true` here and let it through, which is the
    // round-1 masking hole arriving one reload later.
    let err = ctx.reload_outcome().await.expect_err(
        "the second reload was applied because the published snapshot said auth \
         was on, while the request path is still running without it",
    );
    assert!(err.starts_with(POSTURE_REFUSED_PREFIX), "{err}");
}

/// The overlay names the live fields by hand, because `pending_restart_fields`
/// returns names and offers no way to apply them. This is the tripwire that
/// catches a field BECOMING live: it does not check the overlay, it fails when
/// the set it was derived from changes, and sends the reader to the design.
#[test]
fn the_live_field_allow_list_has_not_grown() {
    let mut wanted = Config::default();
    wanted.server.public_url = Some("https://gw.example.com".to_string());
    wanted.control_plane.role_mapping.rules = vec![crate::control_plane::ControlPlaneRoleRule {
        issuer: "https://idp.example.com".to_string(),
        group: Some("admins".to_string()),
        email: None,
        domain: None,
        role: crate::control_plane::ControlPlaneRole::Admin,
    }];

    assert!(
        pending_restart_fields(&Config::default(), &wanted).is_empty(),
        "a field that used to be applied live is now restart-required"
    );

    // And every input the refusal reads is still restart-only. Named one by one
    // rather than as one blob: each is a field the overlay deliberately takes
    // from the RUNNING config, and the overlay is unsound the moment any of them
    // starts applying live.
    for (name, edit) in [
        (
            "auth",
            (|c: &mut Config| c.auth.enabled = true) as fn(&mut Config),
        ),
        ("auth", |c: &mut Config| {
            c.auth.public_paths = vec!["/mcp".to_string()];
        }),
        ("server", |c: &mut Config| {
            c.server.host = "0.0.0.0".to_string();
        }),
        ("server", |c: &mut Config| {
            c.server.allow_unauthenticated_network_bind = true;
        }),
    ] {
        let mut also = wanted.clone();
        edit(&mut also);
        assert!(
            pending_restart_fields(&Config::default(), &also).contains(&name),
            "a field the reload posture overlay reads from the running config is \
             now applied live; the overlay must carry it — see \
             docs/design/unauthenticated-network-posture.md, Decision C"
        );
    }
}

/// The file watcher must log a posture refusal as a refusal, not as the
/// broken-config-file alert a parse failure raises — an operator sent hunting
/// YAML will not revert the `public_url` that is the actual problem.
///
/// Asserted against the string a refused reload really produces, rather than
/// against the constant. That is the whole point: the constant is a PREFIX with
/// the refusal text behind it, so an arm written `e == POSTURE_REFUSED_PREFIX` —
/// the shape the neighbouring `SHUTDOWN_ABORTED_ERROR` arm uses — never matches
/// and falls through to the parse-failure arm. This test fails on that mistake.
#[tokio::test]
async fn the_watcher_recognises_a_posture_refusal_and_not_as_a_broken_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, "server:\n  public_url: \"https://gw.example.com\"\n").unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx
        .reload_outcome()
        .await
        .expect_err("the reload was applied");

    assert!(
        is_posture_refusal(&err),
        "the watcher would log this refusal as a broken config file: {err}"
    );
    assert!(
        !is_posture_refusal(SHUTDOWN_ABORTED_ERROR),
        "the shutdown abort is not a posture refusal"
    );
    assert!(
        !is_posture_refusal("failed to parse config file: invalid YAML at line 3"),
        "a parse failure is not a posture refusal"
    );
}

#[tokio::test]
async fn a_reload_is_not_refused_for_a_state_it_did_not_cause() {
    // GIVEN: a gateway already running in the refusable state — wide bind, no
    // credential. Unreachable through `Gateway::run`, which refuses to start
    // there; reachable through `run_stdio`, which has no listener and never runs
    // the check. Keying the refusal on the TRANSITION rather than on the
    // candidate alone is what keeps that gateway able to reload at all.
    let mut running = Config::default();
    running.server.host = "0.0.0.0".to_string();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: it reloads something unrelated
    write_owner_only(
        &path,
        "server:\n  host: \"0.0.0.0\"\nbackends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .unwrap();
    let ctx = posture_context(&path, running);

    // THEN: it applies. The refusal answers "would this reload OPEN the tools",
    // not "are they open" — the second would wedge such a gateway permanently.
    ctx.reload_outcome()
        .await
        .expect("a reload was refused for a state that predates it");
    assert!(ctx.registry.get("svc").is_some());
}

#[tokio::test]
async fn a_blank_public_path_in_force_is_tools_open_and_refuses() {
    // GIVEN: a gateway running on loopback whose public_paths carry a BLANK
    // entry — a stray dash in YAML. Startup allowed it: on loopback with no
    // declared name, reachability is the half that was missing. But blank is a
    // prefix of every path (`ResolvedAuthConfig::is_public_path`), so at request
    // time this gateway's tools need no credential, whatever `auth.enabled`
    // says.
    //
    // Staged in the RUNNING config, not the file, and that is the whole case.
    // In the file it would be harmless here: `auth` is not applied by a reload,
    // so the request path would keep the old, closed paths and the in-force
    // state would be safe. It is being ALREADY IN FORCE that makes it the live
    // half of the forbidden state.
    let mut running = Config::default();
    running.auth.enabled = true;
    running.auth.bearer_token = Some("secret".to_string());
    running.auth.public_paths = vec!["/health".to_string(), String::new()];

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: the file supplies the other half — a name it is reached by
    write_owner_only(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nsecurity:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n    - \"\"\n",
    )
    .unwrap();
    let ctx = posture_context(&path, running);

    // THEN: refused. `auth.enabled` is true on both sides, so the overlay saves
    // nothing here — this rests entirely on the refusal counting a blank entry
    // as public, which it did not always do.
    let err = ctx
        .reload_outcome()
        .await
        .expect_err("a blank public path opened every route and the reload was applied");
    assert!(err.starts_with(POSTURE_REFUSED_PREFIX), "{err}");
}

#[tokio::test]
async fn a_file_that_a_restart_would_accept_is_not_reported_as_one_to_revert() {
    // GIVEN: a gateway running with authentication OFF
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: one edit declares the public URL and turns authentication on — the
    // fix, written correctly. A reload still cannot apply it, because the auth
    // half needs a restart while the public_url half would take effect at once.
    write_owner_only(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\n  cleartext_http: tls_terminated_upstream\nsecurity:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx
        .reload_outcome()
        .await
        .expect_err("the reload was applied");

    // THEN: it says a restart applies it — not "revert this". Telling an
    // operator to undo the fix they just wrote correctly is the worse failure,
    // and the deployment guide tells them to do exactly this and restart.
    assert!(
        err.contains("A restart would not refuse it for this reason"),
        "an operator who wrote the fix correctly was told to revert it: {err}"
    );
    assert!(
        !err.contains("Revert it"),
        "a startup-safe file was reported as one to revert: {err}"
    );
}

#[tokio::test]
async fn tightening_public_paths_in_the_same_edit_does_not_mask_it() {
    // GIVEN: the shape `mcp-gateway init` writes, which is what a default
    // install runs: authentication ON, and `/mcp` public so the MCP client that
    // was already configured keeps working. Tools are therefore invocable
    // without a credential, on purpose, on loopback.
    let mut running = Config::default();
    running.auth.enabled = true;
    running.auth.bearer_token = Some("secret".to_string());
    running.auth.public_paths = vec!["/health".to_string(), "/mcp".to_string()];

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: one edit publishes the gateway by name AND closes `/mcp` — both
    // halves of the correct fix, written together
    write_owner_only(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\n  cleartext_http: tls_terminated_upstream\nsecurity:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    )
    .unwrap();
    let ctx = posture_context(&path, running);

    // THEN: refused, because the tightening is not in force. This is the case
    // an overlay that took `auth.enabled` from the running config but
    // `public_paths` from the file would let through: both halves must come
    // from the same side, and that side is what is running.
    let err = ctx.reload_outcome().await.expect_err(
        "the file's tightened public_paths masked the exposure, while the request \
         path still has /mcp open",
    );
    assert!(err.starts_with(POSTURE_REFUSED_PREFIX), "{err}");
    // AND: a restart on this file is right, so it must not say revert.
    assert!(
        err.contains("A restart would not refuse it for this reason"),
        "the correct fix was reported as one to revert: {err}"
    );
}

/// Every refusal reads as a sentence.
///
/// A Rust string literal wrapped across lines WITHOUT a trailing `\` keeps the
/// indentation of the continuation line, so the message reaches an operator
/// with runs of spaces in it. The other cases here assert substrings that
/// happen to fall inside one line, so all of them passed while both branches of
/// the restart advice were mangled. This one reads the whole message.
#[tokio::test]
async fn a_refusal_reads_as_a_sentence_on_both_branches() {
    // Two files, one per branch of the restart advice: the first refuses at the
    // next start too, the second is accepted by one.
    for file in [
        "server:\n  public_url: \"https://gw.example.com\"\n",
        "server:\n  public_url: \"https://gw.example.com\"\n  cleartext_http: tls_terminated_upstream\nsecurity:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        write_owner_only(&path, file).unwrap();
        let ctx = posture_context(&path, clean_running());

        let err = ctx
            .reload_outcome()
            .await
            .expect_err("the reload was applied");

        assert!(
            !err.contains("  "),
            "the refusal carries a run of spaces, so a literal lost its line \
             continuation: {err}"
        );
        assert!(
            err.trim_end().ends_with('.'),
            "the refusal does not end as a sentence: {err}"
        );
    }
}

#[tokio::test]
async fn the_override_is_reported_as_a_file_a_restart_accepts() {
    // The escape hatch is honoured at STARTUP, so a file that sets it is
    // accepted by a restart even though the reload cannot apply it. Telling
    // that operator to revert would be wrong, and this is the case where the
    // two branches of the advice are easiest to get backwards: the file leaves
    // the tools open on purpose, which reads like the revert case.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\n  allow_unauthenticated_network_bind: true\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx
        .reload_outcome()
        .await
        .expect_err("the reload was applied");
    assert!(
        err.contains("A restart would not refuse it for this reason"),
        "a file the escape hatch makes startup-legal was reported as one to \
         revert: {err}"
    );
}
