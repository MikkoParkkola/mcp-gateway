// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a reload reports when only `auth.api_keys` changes. The key table
//! applies live (the next request is judged by it: the K rows in
//! `gateway/router/live_keys_tests.rs`), so a key-only edit must not be
//! reported as waiting for a restart; any other restart-only `auth` field
//! still is.
//!
//! The running config here is the startup load of the same kind of file, not
//! `Config::default()`: a default config differs from any loaded one in
//! fields the edit never touches (`default_routing_profile` is `""` by
//! `Default` and `"default"` by serde), which a report would rightly list.

use super::env_support::*;
use super::*;
use crate::config::LiveEnv;

/// One key entry as an operator writes it, with `extra` lines (each already
/// indented under the entry) after the required fields.
fn entry(name: &str, extra: &[&str]) -> String {
    let spec = crate::config::api_key_digest_spec(format!("report-{name}").as_bytes());
    let mut text =
        format!("    - name: {name}\n      key_sha256: \"{spec}\"\n      backends: [\"*\"]\n");
    for line in extra {
        text.push_str(line);
        text.push('\n');
    }
    text
}

/// A multi-user auth section: `auth_extra` lines (indented under `auth:`)
/// before the key list `keys`; `enabled: true` unless they set it.
fn file(auth_extra: &[&str], keys: &[String]) -> String {
    let mut text = String::from("auth:\n");
    if !auth_extra.iter().any(|line| line.starts_with("  enabled:")) {
        text.push_str("  enabled: true\n");
    }
    for line in auth_extra {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str("  api_keys:\n");
    for key in keys {
        text.push_str(key);
    }
    text
}

/// The outcome of reloading `after` over a gateway started from `before`.
async fn report(before: &str, after: &str) -> crate::config_reload::ReloadOutcome {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("gateway.yaml");
    write_owner_only(&cfg, before).unwrap();
    let home = RecordingHome::new();
    let startup = startup_through(&cfg, &home);
    home.finish_startup();
    let ctx = ReloadContext::new(
        cfg.clone(),
        Arc::new(LiveConfig::new(startup.config.clone())),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
    .with_env(Arc::new(LiveEnv::new(
        startup.overlay.clone(),
        startup.env_paths.clone(),
    )));
    write_owner_only(&cfg, after).unwrap();
    ctx.reload_outcome().await.expect("the reload applies")
}

/// A reload whose only change is in `auth.api_keys` reports nothing waiting
/// for a restart: a key added, a key's fields changed (the rotation fields
/// included), and a key removed while the gateway stays multi-user.
#[tokio::test]
async fn a_key_only_reload_reports_no_restart() {
    let two = file(&[], &[entry("a", &[]), entry("b", &[])]);
    let rotated_digest = crate::config::api_key_digest_spec(b"report-b-before-rotation");
    let rotation = format!("      previous_key_sha256: \"{rotated_digest}\"");
    let edits = [
        (
            "a key added",
            two.clone(),
            file(&[], &[entry("a", &[]), entry("b", &[]), entry("c", &[])]),
        ),
        (
            "a key's fields changed",
            two.clone(),
            file(
                &[],
                &[
                    entry("a", &[]),
                    entry(
                        "b",
                        &[
                            "      rate_limit: 7",
                            "      allowed_tools: [\"search\"]",
                            "      denied_tools: [\"delete\"]",
                            "      expires_at: \"2099-01-01T00:00:00Z\"",
                            &rotation,
                            "      previous_expires_at: \"2098-01-01T00:00:00Z\"",
                        ],
                    ),
                ],
            ),
        ),
        (
            "a key removed",
            file(&[], &[entry("a", &[]), entry("b", &[]), entry("c", &[])]),
            two,
        ),
    ];
    for (what, before, after) in edits {
        let outcome = report(&before, &after).await;
        assert!(
            !outcome.restart_required
                && outcome.pending_restart_fields.is_empty()
                && !outcome.changes.contains("NOT YET APPLIED"),
            "{what}: reported as waiting for a restart: pending={:?} changes={}",
            outcome.pending_restart_fields,
            outcome.changes
        );
    }
}

/// Any other restart-only `auth` field still reports `auth` as waiting for a
/// restart, on its own and in the same edit as a key change, so excluding the
/// key table hides no real restart. `enabled` and `single_user` are judged
/// here too: the running settings decide whether keys flip the gateway
/// between one user and many, so an edit to them that keeps two keys is
/// applied for the keys and reported for the rest. (`dashboard_session`
/// applies live and was never reported.)
#[tokio::test]
async fn another_auth_field_still_reports_a_restart() {
    let keys = [entry("a", &[]), entry("b", &[])];
    let more_keys = [entry("a", &[]), entry("b", &[]), entry("c", &[])];
    let before = file(&[], &keys);
    let groups: [(&str, &[&str]); 5] = [
        (
            "bearer_token",
            &["  bearer_token: \"report-bearer-token-0123456789\""],
        ),
        (
            "public_paths",
            &["  public_paths: [\"/health\", \"/status\"]"],
        ),
        (
            "client_circuit_breaker",
            &["  client_circuit_breaker:", "    failure_threshold: 9"],
        ),
        ("enabled", &["  enabled: false"]),
        ("single_user", &["  single_user: true"]),
    ];
    for (field, lines) in groups {
        for (with_keys, after) in [
            ("alone", file(lines, &keys)),
            ("with a key added", file(lines, &more_keys)),
        ] {
            let outcome = report(&before, &after).await;
            assert!(
                outcome.restart_required && outcome.pending_restart_fields == ["auth"],
                "{field} {with_keys}: not reported as auth waiting for a restart: pending={:?} changes={}",
                outcome.pending_restart_fields,
                outcome.changes
            );
        }
    }
}
