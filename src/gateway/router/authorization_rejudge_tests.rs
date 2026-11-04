// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Queued work re-judged at dispatch is bound to the exact credential it was
//! admitted under (`KeyBinding::Credential`): the same key, unchanged, runs it;
//! the same name and principal under another digest does not.

use super::{KeyGone, OwnedRouterAuthorizer};
use crate::config::{ApiKeyConfig, AuthConfig, EnvOverlay, api_key_digest_spec};
use crate::gateway::auth::ResolvedAuthConfig;

const A: &str = "rejudge-secret-a";
const B: &str = "rejudge-secret-b";
const PRINCIPAL: &str = "0c1d2e3f4a5b";

fn table(current: &str, previous: Option<&str>) -> ResolvedAuthConfig {
    let now = crate::clock::utc_now().expect("the test clock reads");
    let key = ApiKeyConfig {
        name: "ops".to_owned(),
        key_sha256: Some(api_key_digest_spec(current.as_bytes())),
        principal: Some(PRINCIPAL.to_owned()),
        previous_key_sha256: previous.map(|p| api_key_digest_spec(p.as_bytes())),
        previous_expires_at: previous.map(|_| now + crate::duration_bound::delta!(minutes, 15)),
        backends: vec!["*".to_owned()],
        ..Default::default()
    };
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![key],
        ..AuthConfig::default()
    };
    ResolvedAuthConfig::try_from_config(
        &auth,
        &EnvOverlay::none(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
    .expect("the table resolves")
}

#[test]
fn queued_work_runs_only_under_the_exact_credential_it_was_admitted_with() {
    let admitted = table(A, None);
    let client = admitted.validate_token(A).expect("A authenticates");
    let owned = OwnedRouterAuthorizer::capture(Some(&client), None, None);
    let now = crate::clock::utc_now().ok();
    assert!(
        matches!(owned.rejudged(&admitted, now), Ok(Some(_))),
        "control: the unchanged key runs its queued work"
    );
    assert_eq!(
        owned.rejudged(&table(B, None), now).err(),
        Some(KeyGone),
        "a key re-issued under the same principal ran the old secret's work"
    );
    assert_eq!(
        owned.rejudged(&table(B, Some(A)), now).err(),
        Some(KeyGone),
        "a rotated key ran work admitted under its previous secret"
    );
}
