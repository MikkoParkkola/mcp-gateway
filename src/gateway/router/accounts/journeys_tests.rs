// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows for the journey owner API: the L2 bridge predicate for principals
//! the router fixture cannot mint (OIDC), and the status view mapping.

use super::{admissible, is_bridged, status_body};
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::{JourneyReason, JourneyStatus, JourneyView};

fn config(session: bool) -> crate::config::Config {
    let session = if session {
        "      session:\n        user_endpoint: http://127.0.0.1:9/api/v1/auths/\n"
    } else {
        ""
    };
    serde_yaml::from_str(&format!(
        r"
accounts:
  schema_version: accounts.v1
  deployment: single_process
  instance_id: unit
  store_dir: /unused/store
  authority_dir: /unused/authority
  current_key_id: primary
  keys:
    primary: env:UNUSED
  adapters:
    - kind: openwebui_signed_header
      installation_id: desk
      header: x-openwebui-assertion
      issuer: open-webui
      hmac_secret_ref: env:UNUSED_HMAC
      allowed_api_key_names: [owui]
{session}"
    ))
    .unwrap()
}

fn identity(issuer: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice".into(),
        email: String::new(),
        name: None,
        groups: Vec::new(),
        issuer: issuer.into(),
    }
}

/// T-POST-NOBRIDGE (OIDC half): only the bridge adapter's namespace passes.
#[test]
fn bridge_predicate_admits_only_the_session_adapters_principal() {
    let bridged = config(true);
    assert!(is_bridged(&bridged, &identity("openwebui-adapter:4:desk")));
    assert!(!is_bridged(&bridged, &identity("https://idp.example")));
    assert!(!is_bridged(
        &bridged,
        &identity("openwebui-adapter:5:desk2")
    ));
    assert!(!is_bridged(
        &config(false),
        &identity("openwebui-adapter:4:desk")
    ));
}

fn view(status: JourneyStatus, reason: Option<JourneyReason>) -> JourneyView {
    JourneyView {
        status,
        reason,
        expires_at: None,
        replay_refused: false,
        replay_refusals: 0,
    }
}

/// §3: a superseded journey is reported as expired, reason superseded.
#[test]
fn status_body_reports_superseded_as_expired() {
    let body = status_body(&view(
        JourneyStatus::Superseded,
        Some(JourneyReason::Superseded),
    ));
    assert_eq!(body["status"], "expired");
    assert_eq!(body["reason"], "superseded");
    let pending = status_body(&view(JourneyStatus::Pending, None));
    assert_eq!(pending["status"], "pending");
    assert!(pending["reason"].is_null());
}

/// Mutant: the body cap, the field caps or the byte-exact return-path match is
/// removed, so an oversized or unlisted request reaches the store.
#[test]
fn a_create_body_is_capped_and_its_return_path_matched_exactly() {
    // Both long paths are allow-listed, so only the length cap can refuse one.
    let at_cap = format!("/{}", "p".repeat(255));
    let over_cap = format!("/{}", "p".repeat(256));
    let yaml = format!(
        "accounts:\n  schema_version: accounts.v1\n  deployment: single_process\n  \
         instance_id: unit\n  store_dir: /unused/store\n  authority_dir: /unused/authority\n  \
         current_key_id: primary\n  keys:\n    primary: env:UNUSED\n  hosted:\n    \
         public_origin: https://chat.fixture.test\n    return_paths: [\"/\", \"{at_cap}\", \"{over_cap}\"]\n"
    );
    let config: crate::config::Config = serde_yaml::from_str(&yaml).expect("config");
    let body = |value: serde_json::Value| axum::body::Bytes::from(value.to_string());
    let ok = serde_json::json!({"account_id": "work", "return_path": "/"});
    assert!(admissible(&config, &body(ok.clone())).is_some(), "control");

    let mut padded = ok.to_string();
    padded.push_str(&" ".repeat(5000));
    assert!(
        admissible(&config, &axum::body::Bytes::from(padded)).is_none(),
        "over the body cap"
    );
    let long_id = serde_json::json!({"account_id": "a".repeat(65), "return_path": "/"});
    assert!(
        admissible(&config, &body(long_id)).is_none(),
        "account id cap"
    );
    let at_cap = serde_json::json!({"account_id": "work", "return_path": at_cap});
    assert!(
        admissible(&config, &body(at_cap)).is_some(),
        "return path at the cap"
    );
    let over_cap = serde_json::json!({"account_id": "work", "return_path": over_cap});
    assert!(
        admissible(&config, &body(over_cap)).is_none(),
        "return path cap"
    );
    let unlisted = serde_json::json!({"account_id": "work", "return_path": "/other"});
    assert!(
        admissible(&config, &body(unlisted)).is_none(),
        "unlisted path"
    );
    assert!(admissible(&config, &axum::body::Bytes::from("not json")).is_none());
}
