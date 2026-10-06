// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the restart-required classification of a reload.

use super::LiveConfig;
use crate::config::Config;

fn with_auth(enabled: bool) -> Config {
    let mut c = Config::default();
    c.auth.enabled = enabled;
    c
}

#[test]
fn a_restart_only_change_keeps_reporting_until_a_restart() {
    // The diff compares the file against the published snapshot. Publishing
    // a restart-only edit into that snapshot makes the NEXT reload see no
    // difference, so the warning appears once and never again: an operator
    // who enables authentication, sees the warning, and later edits
    // something unrelated is told everything is fine while authentication
    // has never been on.
    let live = LiveConfig::new(with_auth(false));

    live.set(with_auth(true));
    assert!(
        live.restart_required(),
        "the first reload must report that a restart is needed"
    );

    // An unrelated later edit. Authentication is still not running.
    let mut later = with_auth(true);
    later.server.max_body_size = 1234;
    live.set(later);
    assert!(
        live.restart_required(),
        "it must keep reporting until a restart makes the running process agree"
    );
}

/// A restart-only edit can make the restart itself refuse to serve.
///
/// The reload answers "restart required". The startup posture check
/// (MIK-7254) then refuses to bind a network-reachable gateway whose tools
/// need no credential — so an operator who disables authentication on a
/// `0.0.0.0` gateway is advised to do the one thing that takes the gateway
/// away. Exposure is not the risk here; availability is, and the operator
/// finds out only after the process they were serving with is gone.
#[test]
fn a_restart_that_would_refuse_is_named_in_the_outcome() {
    fn reachable(auth: bool) -> Config {
        let mut c = Config::default();
        c.server.host = "0.0.0.0".to_string();
        c.auth.enabled = auth;
        c
    }

    let live = LiveConfig::new(reachable(true));
    live.set(reachable(false));
    let warned = super::with_pending_restart(
        crate::config_reload::ReloadOutcome {
            changes: "auth.enabled".to_string(),
            restart_required: false,
            restart_reason: None,
            pending_restart_fields: Vec::new(),
        },
        &live,
        Vec::new(),
    );
    assert!(
        warned.restart_required,
        "the edit is restart-only, so the outcome must still say so"
    );
    assert!(
        warned.changes.contains("a restart would not start"),
        "the restart advice must carry its own consequence: {}",
        warned.changes
    );

    // And it must stay quiet otherwise: the same restart-only edit on a
    // loopback gateway starts fine, and a warning there would train the
    // operator to ignore this one.
    let local = LiveConfig::new(Config::default());
    local.set(with_auth(false));
    let quiet = super::with_pending_restart(
        crate::config_reload::ReloadOutcome {
            changes: "auth.enabled".to_string(),
            restart_required: false,
            restart_reason: None,
            pending_restart_fields: Vec::new(),
        },
        &local,
        Vec::new(),
    );
    assert!(
        !quiet.changes.contains("would not start"),
        "a restart that starts must not be reported as refusing: {}",
        quiet.changes
    );
}

#[test]
fn every_tracked_section_is_covered() {
    // The classifier used to name eight sections while the diff tracked
    // seventeen, so a change to one of the other nine reported as applied
    // while nothing read it — the hand-list this was meant to replace.
    let running = Config::default();
    let mut wanted = Config::default();
    wanted.meta_mcp.enabled = !wanted.meta_mcp.enabled;
    let pending = super::pending_restart_fields(&running, &wanted);
    assert!(
        pending.contains(&"meta_mcp"),
        "a tracked section outside the original list must be reported: {pending:?}"
    );

    // Every restart-only server field, not a hand-picked few:
    // `shutdown_timeout` was omitted before.
    for (label, changed) in [
        (
            "shutdown_timeout",
            Config {
                server: crate::config::ServerConfig {
                    shutdown_timeout: std::time::Duration::from_secs(7),
                    ..Config::default().server
                },
                ..Config::default()
            },
        ),
        (
            "env_files",
            Config {
                env_files: vec!["x.env".to_string()],
                ..Config::default()
            },
        ),
    ] {
        let pending = super::pending_restart_fields(&running, &changed);
        assert!(
            !pending.is_empty(),
            "a change to {label} must be reported as needing a restart"
        );
    }

    // `public_url` is the one server field that IS re-read per request, so
    // changing it alone must NOT demand a restart.
    let public_url_only = Config {
        server: crate::config::ServerConfig {
            public_url: Some("https://mcp.example.com".to_string()),
            ..Config::default().server
        },
        ..Config::default()
    };
    assert!(
        super::pending_restart_fields(&running, &public_url_only).is_empty(),
        "a hot-reloadable field must not demand a restart"
    );

    // Top-level scalars too: they sit outside every section and were
    // reported as applied while nothing re-read them.
    let profile_change = Config {
        default_routing_profile: "research".to_string(),
        ..Config::default()
    };
    assert!(
        super::pending_restart_fields(&running, &profile_change)
            .contains(&"default_routing_profile"),
        "a top-level field must be reported too"
    );

    let names: Vec<&str> = super::tracked_sections(&running, &running)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    for expected in [
        "auth",
        "mtls",
        "key_server",
        "capabilities",
        "playbooks",
        "cache",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} must be tracked: {names:?}"
        );
    }
}

#[test]
fn no_pending_restart_when_the_file_matches_the_running_process() {
    let live = LiveConfig::new(with_auth(false));
    live.set(with_auth(false));
    assert!(!live.restart_required());
}

/// MIK-7645 AC3 guard: surfaced tools are filled once at startup
/// (`with_surfaced_tools` in `build_meta_mcp`), so a replay's record can name
/// the surfaced tool's server by looking it up again. A reload that changes
/// them must stay restart-pending. If `meta_mcp.surfaced_tools` is ever made
/// live-reloadable, this fails: admission must then hand the resolved
/// `(server, tool)` to `audit_replay` (MIK-7645 AC3).
#[test]
fn a_surfaced_tools_change_is_restart_pending() {
    let running = Config::default();
    let mut wanted = Config::default();
    wanted
        .meta_mcp
        .surfaced_tools
        .push(crate::config::SurfacedToolConfig {
            server: "alpha".to_string(),
            tool: "t".to_string(),
        });
    let pending = super::pending_restart_fields(&running, &wanted);
    assert!(
        pending.contains(&"meta_mcp"),
        "surfaced tools changed without a restart; see MIK-7645 AC3: {pending:?}"
    );
}
