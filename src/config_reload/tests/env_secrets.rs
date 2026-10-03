// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Env-file diagnostics and secrets that rotate while the process runs.

use super::env_support::*;
use super::*;
use crate::config::{EnvOverlay, LiveEnv};

/// A cross-file substitution is refused at startup, not only on reload.
///
/// The loader this change replaced exported each file into the process
/// environment, so a later file's `${KEY}` resolved. Nothing writes the process
/// environment now, so the reference expands to nothing and the value is lost
/// without an edit. The reload path refused that; startup accepted it silently.
#[test]
fn a_cross_file_substitution_is_refused_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let base = env_file(
        dir.path(),
        "base.env",
        "MCP_GW_TEST_XFILE_BASE=host.invalid\n",
    );
    let user = env_file(
        dir.path(),
        "user.env",
        "MCP_GW_TEST_XFILE_URL=https://${MCP_GW_TEST_XFILE_BASE}/api\n",
    );
    let cfg = config_naming_env_files(
        dir.path(),
        &[&base.to_string_lossy(), &user.to_string_lossy()],
    );

    let err = Config::load_evaluated(Some(&cfg))
        .expect_err("a cross-file substitution must not load silently");
    let message = err.to_string();
    assert!(
        message.contains("MCP_GW_TEST_XFILE_BASE"),
        "the refusal must name the key; got {message}"
    );
    assert!(
        message.contains(&*user.to_string_lossy()),
        "the refusal must name the file that substitutes; got {message}"
    );
}

/// The malformed line every 6c case uses. Carries a value so the no-secrets half
/// of the assertion has something to catch: a malformed line in a credential
/// file is a credential.
const ENVFILE_6C_BAD_VALUE: &str = "s3cr3t-6c-leaked-91bf0e";

fn envfile_6c_file(dir: &std::path::Path) -> std::path::PathBuf {
    env_file(
        dir,
        "broken.env",
        &format!("MCP_GW_TEST_ENVFILE6C_OK=fine\nthis is not a pair {ENVFILE_6C_BAD_VALUE}\n"),
    )
}

/// Asserts the shared shape of a 6c diagnostic: names the file, the line number
/// and the category, and echoes neither the offending line nor its value.
fn assert_6c_diagnostic(diagnostic: &str, path: &std::path::Path) {
    assert!(
        diagnostic.contains(&*path.to_string_lossy()),
        "the diagnostic must name the file; got {diagnostic}"
    );
    // The path is stripped before this one is asked. A temporary directory's
    // random name carries digits, so a bare digit search passed on macOS and
    // failed on Linux while the diagnostic named no line number on either.
    let without_path = diagnostic.replace(&*path.to_string_lossy(), "<path>");
    assert!(
        without_path.contains("line 2"),
        "the diagnostic must name the line number; got {diagnostic}"
    );
    assert!(
        diagnostic.to_lowercase().contains("parse"),
        "the diagnostic must name the category; got {diagnostic}"
    );
    assert!(
        !diagnostic.contains(ENVFILE_6C_BAD_VALUE),
        "the diagnostic leaked a value from the offending line; got {diagnostic}"
    );
    assert!(
        !diagnostic.contains("this is not a pair"),
        "the diagnostic echoed the offending line; got {diagnostic}"
    );
}

/// ENVFILE.6c, startup half — the no-secrets rule had no case at either entry
/// point, so a diagnostic that echoed the line to be helpful would have shipped.
#[test]
fn envfile_6c_a_malformed_line_at_startup_names_file_line_and_category_only() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = envfile_6c_file(dir.path());
    let cfg = config_naming_env_files(dir.path(), &[&env_path.to_string_lossy()]);

    let err = Config::load_evaluated(Some(&cfg))
        .expect_err("a malformed env file must not load silently");
    assert_6c_diagnostic(&err.to_string(), &env_path);
}

/// ENVFILE.6c, reload half — same rule at the other entry point. A reload that
/// cannot parse its env files is rejected and the previous overlay stands.
#[tokio::test]
async fn envfile_6c_a_malformed_line_on_a_reload_names_file_line_and_category_only() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = env_file(dir.path(), "broken.env", "MCP_GW_TEST_ENVFILE6C_OK=fine\n");
    let cfg = config_naming_env_files(dir.path(), &[&env_path.to_string_lossy()]);

    let home = RecordingHome::new();
    let startup = startup_through(&cfg, &home);
    home.finish_startup();

    // WHEN: the file becomes unparseable and a reload runs
    envfile_6c_file(dir.path());
    let ctx = reload_context_with_env(&cfg, &startup);
    let err = ctx
        .reload_outcome()
        .await
        .expect_err("a reload whose env files do not parse must be rejected");
    assert_6c_diagnostic(&err, &env_path);

    // AND: the previous overlay stands
    assert_eq!(
        ctx.live_env()
            .get()
            .resolve("MCP_GW_TEST_ENVFILE6C_OK")
            .as_deref(),
        Some("fine"),
        "a rejected reload leaves the overlay in force untouched"
    );
}

/// ENVFILE.10c — the four auth forms of .10a on an accepted reload, over a
/// config patch that is BYTE-IDENTICAL to the running config, so the only change
/// is the env file's value.
///
/// Asserts the NARROWING rather than the capability. A single criterion
/// previously asserted .10b's outcome for all five, which the source check
/// disproved: `ResolvedAuthConfig::try_from_config` runs once at startup and
/// nothing rebuilds it. The byte-identical patch is what makes the case able to
/// fail: with any auth FIELD edited, the tracked-section reporting that already
/// exists reports a restart on its own, so the criterion went green while the
/// env-file-only rotation it exists to catch went unreported.
#[tokio::test]
async fn envfile_10c_a_byte_identical_patch_still_reports_the_rotated_startup_only_key() {
    let digest = |v: &str| crate::config::api_key_digest_spec(v.as_bytes());
    // The four forms funnelled through `validate_env_reference`
    // (`src/config/mod.rs:627,630,637,645`).
    let forms: [(&str, &str); 4] = [
        (
            "MCP_GW_TEST_ENVFILE10C_BEARER",
            "security:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"env:MCP_GW_TEST_ENVFILE10C_BEARER\"\n",
        ),
        (
            "MCP_GW_TEST_ENVFILE10C_APIKEY",
            "security:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  api_keys:\n    - name: k\n      key_sha256: \"env:MCP_GW_TEST_ENVFILE10C_APIKEY\"\n",
        ),
        (
            "MCP_GW_TEST_ENVFILE10C_HS256",
            "agent_auth:\n  enabled: true\n  agents:\n    - client_id: a\n      name: a\n      audience: mcp-gateway-test\n      hs256_secret: \"env:MCP_GW_TEST_ENVFILE10C_HS256\"\n",
        ),
        (
            "MCP_GW_TEST_ENVFILE10C_ADMIN",
            "key_server:\n  enabled: true\n  admin_token: \"env:MCP_GW_TEST_ENVFILE10C_ADMIN\"\n",
        ),
    ];

    for (key, section) in forms {
        let mut old = format!("s3cr3t-10c-{key}-old");
        let mut new = format!("s3cr3t-10c-{key}-new");
        if key.ends_with("APIKEY") {
            (old, new) = (digest(&old), digest(&new));
        }

        let dir = tempfile::tempdir().unwrap();
        let env_path = env_file(dir.path(), "secrets.env", &format!("{key}={old}\n"));
        let cfg = dir.path().join("gateway.yaml");
        let yaml = format!("env_files:\n  - '{}'\n{section}", env_path.display());
        write_owner_only(&cfg, &yaml).unwrap();

        let home = RecordingHome::new();
        let startup = startup_through(&cfg, &home);
        home.finish_startup();

        // The holder, built once at startup, exactly as the gateway builds it.
        let (auth, env) = (&startup.config.auth, &startup.overlay);
        let holder = crate::gateway::auth::ResolvedAuthConfig::try_from_config(auth, env).unwrap();

        // WHEN: only the env file's value changes. The config file is rewritten
        // BYTE-IDENTICALLY, so the tracked-section reporting that already exists
        // has nothing of its own to report — the rotation is the whole change.
        write_owner_only(&cfg, &yaml).unwrap();
        write_owner_only(&env_path, format!("{key}={new}\n")).unwrap();

        let ctx = reload_context_with_env(&cfg, &startup);
        let outcome = ctx.reload_outcome().await.unwrap();

        // THEN: the outcome reports `restart_required` and names the changed key
        assert!(
            outcome.restart_required,
            "{key}: a startup-only holder cannot take the rotation: {outcome:?}"
        );
        let report = format!("{} {:?}", outcome.changes, outcome.pending_restart_fields);
        assert!(
            report.contains(key),
            "{key}: the report must name the changed key; got {report}"
        );
        assert!(
            !report.contains(&old) && !report.contains(&new),
            "{key}: the report leaked a value; got {report}"
        );

        // AND: the resolved holder still carries the STARTUP value. Asserted through `ResolvedAuthConfig` for its two forms; `agent_auth`
        // and `key_server` have no reachable resolved holder here, so for them
        // this asserts the outcome half only. Stated rather than approximated.
        if key.ends_with("BEARER") {
            assert_eq!(
                holder.bearer_token.as_deref(),
                Some(old.as_str()),
                "{key}: the running holder must keep the startup value"
            );
        } else if key.ends_with("APIKEY") {
            assert_eq!(
                holder.api_keys.first().map(|k| hex::encode(k.digest)),
                old.strip_prefix("sha256:").map(str::to_string),
                "{key}: the running holder must keep the startup value"
            );
        }

        // AND: the rotation itself did reach the overlay — the report is about a
        // holder that cannot take it, not about a publish that never happened.
        assert_eq!(
            ctx.live_env().get().resolve(key).as_deref(),
            Some(new.as_str()),
            "{key}: the accepted reload must publish the rotated value"
        );
    }
}

#[test]
fn load_config_patch_refuses_a_substitution_naming_a_defined_key() {
    let dir = tempfile::tempdir().unwrap();
    // Two files: the reference has to live in a *different* file from the
    // assignment. A file substituting a key it supplies itself resolves within
    // its own buffer and is not what this guard refuses.
    let defining_path = dir.path().join("defining.env");
    let env_path = dir.path().join("gateway.env");
    let config_path = dir.path().join("gateway.yaml");
    write_owner_only(
        &config_path,
        format!(
            "env_files:\n  - '{}'\n  - '{}'\n",
            defining_path.display(),
            env_path.display()
        ),
    )
    .unwrap();
    write_owner_only(&defining_path, "MCP_GW_TEST_BASE=https://host\n").unwrap();
    write_owner_only(&env_path, "MCP_GW_TEST_OTHER=plain\n").unwrap();

    // GIVEN: a gateway started from env files that hold no substitution
    let startup = Config::load_evaluated(Some(&config_path)).unwrap();

    // WHEN: a cross-file substitution is added and the files are reloaded.
    // Startup refuses these files outright, so an edit after startup is the
    // only way the reload path ever sees one.
    write_owner_only(
        &env_path,
        "MCP_GW_TEST_OTHER=plain\nMCP_GW_TEST_URL=${MCP_GW_TEST_BASE}/v1\n",
    )
    .unwrap();
    let live_config = std::sync::Arc::new(LiveConfig::new(startup.config.clone()));
    let env = LiveEnv::new(startup.overlay, startup.env_paths);
    let result = load_config_patch(&config_path, &live_config, &env);

    // THEN: the reload is refused, naming the file and the key, with no value
    let Err(message) = result else {
        panic!("a substitution naming a defined key must refuse the reload")
    };
    assert!(
        message.contains("MCP_GW_TEST_BASE") && message.contains("gateway.env"),
        "the refusal must name the key and the file: {message}"
    );
    assert!(
        !message.contains("https://host"),
        "the refusal must not log a value: {message}"
    );
}

// -------------------------------------------------------------------------
// Startup-only environment keys
// -------------------------------------------------------------------------

/// Builds an overlay holding exactly `assignments`.
fn overlay_of(dir: &std::path::Path, name: &str, assignments: &str) -> Arc<EnvOverlay> {
    let path = dir.join(name);
    write_owner_only(&path, assignments).expect("write env file");
    Arc::new(EnvOverlay::from_paths(std::slice::from_ref(&path)))
}

fn reload_of(overlay: Arc<EnvOverlay>, secret_refs: &[&str]) -> EvaluatedReload {
    EvaluatedReload {
        config: Config::default(),
        patch: ConfigPatch::default(),
        overlay,
        secret_refs: secret_refs.iter().map(ToString::to_string).collect(),
    }
}

/// A restart requirement is outstanding until the process restarts, so every
/// reload in between must keep reporting it. Measuring against the last
/// published overlay reports the rotation once and then forgets it, because
/// the second reload compares the new value against itself.
#[test]
fn a_rotated_secret_stays_reported_until_the_process_restarts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let startup = overlay_of(dir.path(), "startup.env", "ROTATING_SECRET=old\n");
    let rotated = overlay_of(dir.path(), "rotated.env", "ROTATING_SECRET=new\n");
    let env = LiveEnv::new(startup, ResolvedEnvFiles::default());
    let evaluated = reload_of(Arc::clone(&rotated), &["ROTATING_SECRET"]);

    assert_eq!(
        changed_startup_env_keys(&env, &evaluated),
        vec!["ROTATING_SECRET".to_string()],
        "the reload that carries the rotation must report it"
    );

    env.set(rotated);
    assert_eq!(
        changed_startup_env_keys(&env, &evaluated),
        vec!["ROTATING_SECRET".to_string()],
        "a later reload must still report it: nothing has restarted"
    );
}

/// The attestation signer is built once at startup, straight off the overlay.
/// Its keys appear in no config field, so tracking only the config's own
/// `env:` references leaves a rotation invisible while the running signer
/// keeps using the superseded key.
#[test]
fn a_rotated_attestation_key_is_reported_although_no_config_field_names_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let startup = overlay_of(
        dir.path(),
        "startup.env",
        "GATEWAY_ATTESTATION_SIGNING_KEY=old\n",
    );
    let rotated = overlay_of(
        dir.path(),
        "rotated.env",
        "GATEWAY_ATTESTATION_SIGNING_KEY=new\n",
    );
    let env = LiveEnv::new(startup, ResolvedEnvFiles::default());

    assert_eq!(
        changed_startup_env_keys(&env, &reload_of(rotated, &[])),
        vec!["GATEWAY_ATTESTATION_SIGNING_KEY".to_string()],
        "a startup-only key nothing references must still be reported"
    );
}

/// GH475.CFG.6 — an `error_budget:` edit is reported as needing a restart.
///
/// The section is read once while the meta-MCP server is built, so a hot
/// reload cannot apply it; the honest answer is "restart required", not
/// silence.
#[test]
fn gh475_cfg_6_error_budget_change_needs_restart() {
    let running = Config::default();

    let mut wanted = Config::default();
    wanted.error_budget.threshold = Some(0.25);
    let pending = super::pending_restart_fields(&running, &wanted);
    assert!(
        pending.contains(&"error_budget"),
        "a backend threshold edit must be reported: {pending:?}"
    );

    // The nested half separately: a capability-only edit must not be swallowed
    // by the backend half comparing equal.
    let mut nested = Config::default();
    nested.error_budget.capability.cooldown = Some(std::time::Duration::from_secs(30));
    let pending = super::pending_restart_fields(&running, &nested);
    assert!(
        pending.contains(&"error_budget"),
        "a capability-only edit must be reported: {pending:?}"
    );

    // The diff must also see the edit at all. An empty patch returns before the
    // new snapshot is published, so `pending_restart_fields` would then compare
    // the running config against the *stale* snapshot, find nothing, and the
    // operator would be told "no changes" for an edit that needs a restart.
    for changed in [&wanted, &nested] {
        assert!(
            !super::compute_diff(&running, changed).is_empty(),
            "an error_budget-only edit must produce a non-empty patch"
        );
    }
}
