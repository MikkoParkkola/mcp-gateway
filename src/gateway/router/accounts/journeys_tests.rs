// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows for the journey owner API: the L2 bridge predicate for principals
//! the router fixture cannot mint (OIDC), and the status view mapping.

use super::{is_bridged, status_body};
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
    assert!(!is_bridged(&bridged, &identity("openwebui-adapter:5:desk2")));
    assert!(!is_bridged(&config(false), &identity("openwebui-adapter:4:desk")));
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
    let body = status_body(&view(JourneyStatus::Superseded, Some(JourneyReason::Superseded)));
    assert_eq!(body["status"], "expired");
    assert_eq!(body["reason"], "superseded");
    let pending = status_body(&view(JourneyStatus::Pending, None));
    assert_eq!(pending["status"], "pending");
    assert!(pending["reason"].is_null());
}
