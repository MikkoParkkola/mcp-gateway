// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each refusal changes one field of the same valid, receipt-producing table.

use super::*;
use crate::config::{ApiKeyConfig, AuthConfig, Config, EnvOverlay, api_key_digest_spec};
use crate::gateway::auth::ResolvedAuthConfig;

const TARGET: &str = "removed-key";
const TARGET_TOKEN: &str = "receipt-removed-current-token";
const TARGET_PREVIOUS: &str = "receipt-removed-previous-token";
const RECORD_KEY: &str = "receipt-tests-record-key-at-least-32-bytes";

fn baseline() -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: Some("receipt-unrelated-running-bearer".into()),
        api_keys: vec![ApiKeyConfig {
            name: "survivor".into(),
            key_sha256: Some(api_key_digest_spec(b"receipt-survivor-current")),
            previous_key_sha256: Some(api_key_digest_spec(b"receipt-survivor-previous")),
            previous_expires_at: Some("2099-01-01T00:00:00Z".parse().expect("expiry")),
            backends: vec!["*".into()],
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn confirm(auth: AuthConfig) -> Result<RevokeReceipt, String> {
    let overlay = EnvOverlay::none();
    auth.validate_api_key_material(&overlay)
        .expect("loadable key material, including the previous slot's expiry");
    auth.validate_distinct_principals(&overlay)
        .expect("no live credential collision");
    let resolved = ResolvedAuthConfig::try_from_config(&auth, &overlay, RECORD_KEY)
        .expect("valid resolved auth table");
    let live = LiveConfig::with_auth(
        Config {
            auth,
            ..Default::default()
        },
        Arc::new(resolved),
    );
    let tags = [TARGET_TOKEN, TARGET_PREVIOUS]
        .map(|token| digest_tag_of(&Sha256::digest(token.as_bytes()).into()))
        .into_iter()
        .collect::<BTreeSet<_>>();
    RevokeCheck {
        name: TARGET.into(),
        tags: Arc::new(OnceLock::from(tags)),
        live: Arc::new(live),
    }
    .confirm(FileRevision::of(b"published config"))
}

fn assert_no_receipt(auth: AuthConfig) {
    assert_eq!(
        confirm(auth).expect_err("the receipt must be refused"),
        "revoke postcondition failed after durable completion"
    );
}

#[test]
fn a_receipt_is_given_when_name_and_every_tag_are_gone() {
    let receipt = confirm(baseline()).expect("all revoke postconditions hold");
    assert_eq!(receipt.name, TARGET);
    assert_eq!(receipt.revision, FileRevision::of(b"published config"));
}

#[test]
fn the_name_still_present_gives_no_receipt() {
    let mut auth = baseline();
    auth.api_keys[0].name = TARGET.into();
    assert_no_receipt(auth);
}

#[test]
fn a_target_tag_in_another_keys_previous_slot_gives_no_receipt() {
    let mut auth = baseline();
    // Legal: the removed key is absent, so this digest belongs to only one
    // live slot. S is historical selection evidence, not another live key.
    auth.api_keys[0].previous_key_sha256 = Some(api_key_digest_spec(TARGET_PREVIOUS.as_bytes()));
    assert_no_receipt(auth);
}

#[test]
fn a_target_tag_equal_to_the_running_bearer_gives_no_receipt() {
    let mut auth = baseline();
    // Legal for the same reason: no current or previous API-key slot holds it.
    auth.bearer_token = Some(TARGET_TOKEN.into());
    assert_no_receipt(auth);
}
