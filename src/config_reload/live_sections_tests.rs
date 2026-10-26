// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart classification for the settings that apply on reload (ADR-023).
//!
//! A reload compares the file with the running process and names each section
//! that will only take effect after a restart. A setting that now applies on
//! reload must leave that report, and every other setting in its section must
//! stay in it, alone or in a combined edit.

use super::LiveConfig;
use crate::config::Config;

/// The restart-pending sections after publishing `wanted` over `running`.
fn pending(running: &Config, wanted: Config) -> Vec<&'static str> {
    let live = LiveConfig::new(running.clone());
    live.set(wanted);
    live.pending_restart_fields()
}

// R1: the two security flags apply on reload, so an edit to only them is not
// restart-pending.
#[test]
fn r1_a_security_flag_only_edit_is_not_restart_pending() {
    let running = Config::default();
    let mut sanitize = running.clone();
    sanitize.security.sanitize_input = !running.security.sanitize_input;
    assert_eq!(
        pending(&running, sanitize),
        Vec::<&str>::new(),
        "sanitize_input"
    );

    let mut ssrf = running.clone();
    ssrf.security.ssrf_protection = !running.security.ssrf_protection;
    assert_eq!(
        pending(&running, ssrf),
        Vec::<&str>::new(),
        "ssrf_protection"
    );
}

// R2: every other security field stays restart-pending, including the
// collusion lists, which stay restart-only until their evidence is judged
// against the current rules.
#[test]
fn r2_any_other_security_field_stays_restart_pending() {
    let running = Config::default();
    let edits: Vec<(&str, Box<dyn Fn(&mut Config)>)> = vec![
        (
            "trust_configured_backends",
            Box::new(|c| {
                c.security.trust_configured_backends = !c.security.trust_configured_backends
            }),
        ),
        (
            "provenance_stamping",
            Box::new(|c| c.security.provenance_stamping = !c.security.provenance_stamping),
        ),
        (
            "collusion.sources",
            Box::new(|c| {
                c.security
                    .firewall
                    .collusion
                    .sources
                    .push("mail".to_string())
            }),
        ),
    ];
    for (name, edit) in edits {
        let mut wanted = running.clone();
        edit(&mut wanted);
        assert!(
            pending(&running, wanted).contains(&"security"),
            "a change to security.{name} must stay restart-pending"
        );
    }
}

// R3: a hot flag edited together with a restart-only security field still
// leaves the section pending.
#[test]
fn r3_a_combined_security_edit_stays_restart_pending() {
    let running = Config::default();
    let mut wanted = running.clone();
    wanted.security.sanitize_input = !running.security.sanitize_input;
    wanted.security.trust_configured_backends = !running.security.trust_configured_backends;
    assert!(pending(&running, wanted).contains(&"security"));
}

// R4: the existing dashboard_session exclusion, pinned. A change to only it is
// not pending; a change to another auth field is.
#[test]
fn r4_dashboard_session_alone_is_not_pending_and_other_auth_is() {
    let running = Config::default();
    let mut session = running.clone();
    session.auth.dashboard_session.idle_timeout_secs =
        running.auth.dashboard_session.idle_timeout_secs + 1;
    assert_eq!(pending(&running, session), Vec::<&str>::new());

    let mut enabled = running.clone();
    enabled.auth.enabled = !running.auth.enabled;
    assert!(pending(&running, enabled).contains(&"auth"));
}

// R5: the idempotency section is captured at startup, so an edit to it alone
// must be reported as needing a restart. Today it is in no tracked section.
#[test]
fn r5_an_idempotency_only_edit_is_restart_pending() {
    let running = Config::default();
    let mut wanted = running.clone();
    wanted
        .idempotency
        .read_only_tools
        .push(crate::config::IdempotencyReadOnlyTool {
            server: "files".to_string(),
            tool: "read".to_string(),
        });
    assert!(
        pending(&running, wanted).contains(&"idempotency"),
        "the idempotency section is read once at startup"
    );
}
