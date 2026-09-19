//! MIK-6744: the OAuth token store must be keyed by principal.
//!
//! `TokenStorage` keys tokens by `(backend_name, resource_url)` only, so every
//! identity sharing a gateway reads and writes the same file: whoever
//! authenticates first hands their access token to everyone else.
//!
//! This test is `#[ignore]`d because the store has no principal parameter to
//! express the second identity with. The identity-keyed store is designed in
//! `docs/design/2026-09-06-personal-accounts.md` line 98 (a versioned
//! `(principal_authority, principal_subject, backend_id, resource,
//! oauth_issuer)` key, length-prefixed and domain-separated); that doc lives on
//! branch `codex/v4-release-delivery`, commit e123bb36, not on this branch.
//! Un-ignore and re-express against the principal-keyed API when it lands.

use mcp_gateway::oauth::{TokenInfo, TokenStorage};
use tempfile::TempDir;

fn token(access: &str) -> TokenInfo {
    TokenInfo {
        access_token: access.to_string(),
        token_type: "Bearer".to_string(),
        refresh_token: None,
        expires_at: None,
        scope: None,
        token_endpoint: None,
        client_id: None,
        client_secret: None,
    }
}

#[test]
#[ignore = "MIK-6744: fails by construction until the token store is identity-keyed"]
fn a_second_identity_must_not_read_the_first_identitys_token() {
    let dir = TempDir::new().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();

    storage
        .save("backend", "http://localhost", &token("alice-secret"))
        .unwrap();

    // There is no principal parameter, so this call *is* Bob's read: same
    // arguments, same file, Alice's token. The assertion states the
    // requirement and fails today by construction.
    assert!(
        storage.load("backend", "http://localhost").is_none(),
        "bob read alice's token: the store is not identity-keyed"
    );
}
