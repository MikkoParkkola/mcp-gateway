// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Served line and running-version time for a refused reload.
//!
//! The ledger takes a line and drops it, and both served fields stay unset,
//! so a row that requires either value fails on that assertion. The clock is
//! the process clock the reload stamps with, pinned to the same instant the
//! ledger tests use, because that stamp is not the ledger's own clock.

use std::time::Duration;

use serde_json::{Value, json};

use super::{RefusalKind, RefusalLedger};

/// The instant every pinned clock in these rows reads, as seconds and as the
/// RFC 3339 second the served field has to equal.
const APPLIED_SECS: u64 = 1_800_000_000;
const APPLIED_AT: &str = "2027-01-15T08:00:00Z";

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

const WITHHELD_CAUSE: &str =
    "the file does not parse or validate (detail withheld: it can quote a configured value)";

fn fixed_clock() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + Duration::from_secs(APPLIED_SECS)
}

/// Apply `RUNNING`, then reload `next` and return the newest served refusal.
/// The clock stays pinned for both stamps: the applied version and the refusal.
async fn served_after(next: &str) -> Value {
    let _clock = crate::clock::test_clock::at_secs(APPLIED_SECS);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, RUNNING).expect("write the running config");
    let running = crate::config::Config::load(Some(&path)).expect("startup loads");
    let ctx = crate::config_reload::ReloadContext::new(
        path.clone(),
        std::sync::Arc::new(crate::config_reload::LiveConfig::new(running)),
        std::sync::Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    ctx.reload_outcome()
        .await
        .expect("the running file applies");
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
}

#[tokio::test(flavor = "current_thread")]
async fn v2_a_posture_refusal_omits_the_line_and_the_running_time() {
    let refusal = served_after(POSTURE).await;
    assert_eq!(refusal["code"], json!("posture"), "{refusal}");
    assert!(refusal.get("line").is_none(), "{refusal}");
    assert!(refusal.get("running_since").is_none(), "{refusal}");
}

#[tokio::test(flavor = "current_thread")]
async fn v3_an_invalid_value_omits_the_line_and_serves_the_running_time() {
    let refusal = served_after(INVALID_VALUE).await;
    assert_eq!(refusal["code"], json!("invalid_config"), "{refusal}");
    assert!(refusal.get("line").is_none(), "{refusal}");
    assert_eq!(refusal["running_since"], json!(APPLIED_AT), "{refusal}");
}

#[test]
fn v4_an_admin_write_omits_the_line_and_the_running_time() {
    let ledger = RefusalLedger::with_clock(fixed_clock);
    ledger.record(RefusalKind::Add, Some("inventory"), "x", None);
    ledger.record(RefusalKind::Edit, Some("billing"), "y", None);
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
