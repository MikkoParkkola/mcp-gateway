// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Served line and running-version time for a refused reload.
//!
//! An invalid-config reload serves the parser's line and the time the
//! configuration still running was applied. A later validation has no line.
//! A posture refusal and an admin write serve neither. The clock is the
//! process clock the reload stamps with, pinned for the whole check.

use std::time::Duration;

use serde_json::{Value, json};

use super::{RefusalKind, RefusalLedger};

/// When the running version's reload applied, as seconds and as the RFC 3339
/// second the served field has to equal.
const APPLIED_SECS: u64 = 1_800_000_000;
const APPLIED_AT: &str = "2027-01-15T08:00:00Z";

/// When the refusal is recorded, ten minutes later. Three distinct instants
/// (startup, apply, refusal) let a row tell which one `running_since` names.
const REFUSED_SECS: u64 = 1_800_000_600;
const REFUSED_AT: &str = "2027-01-15T08:10:00Z";

/// The version a refused reload leaves running. A second load of these same
/// bytes applies and changes nothing, which is the applied time the refusal
/// is judged against.
const RUNNING: &str = "\
# operator's note
backends:
  a:
    http_url: \"http://127.0.0.1:9/mcp\" # first
";

/// The unclosed bracket is the seventh line. The parser's syntax location is
/// that line; an earlier value would be a different fault.
const SYNTAX_ON_LINE_7: &str = "\
server:
  port: 39401
backends:
  inventory:
    http_url: \"http://127.0.0.1:9/mcp\"
    headers:
      X-Trace: [unclosed
";

/// YAML that parses, with a port that is not a port.
const INVALID_VALUE: &str = "server:\n  port: not-a-number\n";

/// A public URL on an open gateway: the posture rule a reload refuses.
const POSTURE: &str = "server:\n  public_url: \"https://gw.example.com\"\n";

/// `server.max_body_size: 0` is a byte count, so it parses and deserializes.
/// `Config::validate_with_env` then refuses it: the count must be positive.
/// That check has no YAML location.
const VALIDATES_LATER: &str = "server:\n  max_body_size: 0\n";

/// The startup load, before any reload applies. A later refusal must name
/// this instant, not the instant it was itself recorded.
const STARTUP_SECS: u64 = 1_700_000_000;
const STARTUP_AT: &str = "2023-11-14T22:13:20Z";

const WITHHELD_CAUSE: &str =
    "the file does not parse or validate (detail withheld: it can quote a configured value)";

fn fixed_clock() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + Duration::from_secs(APPLIED_SECS)
}

/// Start, apply `RUNNING`, then reload `next`, each at its own instant, and
/// return the newest served refusal. A running time equal to the apply proves
/// an applied reload moves it and the refusal does not.
async fn served_after(next: &str) -> Value {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let ctx = {
        let _clock = crate::clock::test_clock::at_secs(STARTUP_SECS);
        crate::gateway::test_helpers::write_owner_only(&path, RUNNING)
            .expect("write the running config");
        let running = crate::config::Config::load(Some(&path)).expect("startup loads");
        crate::config_reload::ReloadContext::new(
            path.clone(),
            std::sync::Arc::new(crate::config_reload::LiveConfig::new(running)),
            std::sync::Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config")
        .with_reporting(super::ReloadReporting::default())
    };
    {
        let _clock = crate::clock::test_clock::at_secs(APPLIED_SECS);
        ctx.reload_outcome()
            .await
            .expect("the running file applies");
    }
    let _clock = crate::clock::test_clock::at_secs(REFUSED_SECS);
    crate::gateway::test_helpers::write_owner_only(&path, next).expect("write the refused config");
    ctx.reload_outcome()
        .await
        .expect_err("the reload is refused");
    let list = serde_json::to_value(ctx.refusals().list()).expect("serialises");
    list.as_array()
        .and_then(|rows| rows.first().cloned())
        .expect("a refusal was recorded")
}

#[tokio::test(flavor = "current_thread")]
async fn v1_a_syntax_error_on_line_7_serves_the_line_and_the_running_time() {
    let refusal = served_after(SYNTAX_ON_LINE_7).await;
    assert_eq!(refusal["code"], json!("invalid_config"), "{refusal}");
    assert_eq!(refusal["cause"], json!(WITHHELD_CAUSE), "{refusal}");
    assert_eq!(refusal["line"], json!(7), "{refusal}");
    assert_eq!(refusal["running_since"], json!(APPLIED_AT), "{refusal}");
    assert_eq!(refusal["at"], json!(REFUSED_AT), "{refusal}");
}

#[tokio::test(flavor = "current_thread")]
async fn v2_a_posture_refusal_omits_the_line_and_the_running_time() {
    let refusal = served_after(POSTURE).await;
    assert_eq!(refusal["code"], json!("posture"), "{refusal}");
    assert!(refusal.get("line").is_none(), "{refusal}");
    assert!(refusal.get("running_since").is_none(), "{refusal}");
}

#[tokio::test(flavor = "current_thread")]
async fn v3_a_value_of_the_wrong_type_serves_its_line_and_the_running_time() {
    // `port: not-a-number` is a type error on line 2: the deserializer places it
    // (yaml Error::location for a serde message), as frame 26i shows "line 48: expects
    // a number".
    let refusal = served_after(INVALID_VALUE).await;
    assert_eq!(refusal["code"], json!("invalid_config"), "{refusal}");
    assert_eq!(refusal["line"], json!(2), "{refusal}");
    assert_eq!(refusal["running_since"], json!(APPLIED_AT), "{refusal}");
}

#[tokio::test(flavor = "current_thread")]
async fn v3b_a_later_validation_serves_no_line_and_the_running_time() {
    let refusal = served_after(VALIDATES_LATER).await;
    assert_eq!(refusal["code"], json!("invalid_config"), "{refusal}");
    assert!(refusal.get("line").is_none(), "{refusal}");
    assert_eq!(refusal["running_since"], json!(APPLIED_AT), "{refusal}");
}

/// No reload has applied. The refusal names the startup load, and its own
/// `at` is the later instant it was recorded. Built as every production path
/// builds it: `with_reporting` hands over the gateway's reporting, whose tally
/// that call stamps (the tally `new` stamped is discarded).
#[tokio::test(flavor = "current_thread")]
async fn a_refused_reload_before_any_apply_serves_the_startup_load_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let ctx = {
        let _clock = crate::clock::test_clock::at_secs(STARTUP_SECS);
        crate::gateway::test_helpers::write_owner_only(&path, RUNNING)
            .expect("write the running config");
        let running = crate::config::Config::load(Some(&path)).expect("startup loads");
        crate::config_reload::ReloadContext::new(
            path.clone(),
            std::sync::Arc::new(crate::config_reload::LiveConfig::new(running)),
            std::sync::Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config")
        .with_reporting(super::ReloadReporting::default())
    };
    let _clock = crate::clock::test_clock::at_secs(APPLIED_SECS);
    crate::gateway::test_helpers::write_owner_only(&path, SYNTAX_ON_LINE_7)
        .expect("write the refused config");
    ctx.reload_outcome()
        .await
        .expect_err("the reload is refused");
    let list = serde_json::to_value(ctx.refusals().list()).expect("serialises");
    let refusal = list
        .as_array()
        .and_then(|rows| rows.first().cloned())
        .expect("a refusal was recorded");
    assert_eq!(refusal["code"], json!("invalid_config"), "{refusal}");
    assert_eq!(refusal["line"], json!(7), "{refusal}");
    assert_eq!(refusal["running_since"], json!(STARTUP_AT), "{refusal}");
    assert_eq!(refusal["at"], json!(APPLIED_AT), "{refusal}");
}

#[test]
fn v4_an_admin_write_omits_the_line_and_the_running_time() {
    // A line is offered and the tally has a time, so only the kind can drop
    // them: "x" and "y" classify as invalid config, as a reload's file would.
    let tally = std::sync::Arc::new(super::super::reload_tally::ReloadTally::default());
    tally.note_loaded();
    assert!(tally.last_applied_at().is_some(), "the premise: a running time exists");
    let ledger = RefusalLedger::with_clock(fixed_clock).observing(tally);
    ledger.record(RefusalKind::Add, Some("inventory"), "x", Some(5));
    ledger.record(RefusalKind::Edit, Some("billing"), "y", Some(5));
    let body = serde_json::to_value(ledger.list()).expect("serialises");
    let rows = body.as_array().expect("a list");
    assert_eq!(rows.len(), 2, "{body}");
    for kind in ["add", "edit"] {
        let refusal = rows
            .iter()
            .find(|row| row["kind"] == kind)
            .expect(kind);
        assert!(refusal.get("line").is_none(), "{kind}: {refusal}");
        assert!(
            refusal.get("running_since").is_none(),
            "{kind}: {refusal}"
        );
    }
}
