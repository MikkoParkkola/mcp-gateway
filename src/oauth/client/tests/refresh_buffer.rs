// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8044.SURF.2 (AUTO): the OAuth refresh buffer.

use super::*;

// MIK-8044.SURF.2 (AUTO): an unset refresh buffer derives from the token's
// lifetime, max(300 s, 10 %). Built through serde so the rows compile before
// the fields exist (base proof).

fn unix_now() -> u64 {
    crate::clock::unix_secs().expect("clock after the epoch")
}

/// C3: unset buffer, a one-hour token with 330 s left refreshes (10 % of 3600
/// is 360, above the 300 s floor).
#[test]
fn an_unset_buffer_derives_from_the_token_lifetime() {
    let token_dir = tempfile::tempdir().expect("token dir");
    let storage = Arc::new(TokenStorage::new(token_dir.path().join("tokens")).unwrap());
    let client = OAuthClient::new(
        Client::new(),
        "backend".to_string(),
        "http://localhost".to_string(),
        vec![],
        storage,
        OAuthClientConfig::default(),
    );
    let token: TokenInfo = serde_json::from_value(serde_json::json!({
        "access_token": "tok",
        "expires_at": unix_now() + 330,
        "lifetime_secs": 3600,
    }))
    .expect("token json");
    *client.current_token.write() = Some(token);
    assert!(client.needs_proactive_refresh());
}

/// C4a: a token answer's `expires_in` is stored as the token's lifetime.
#[test]
fn a_token_answer_stores_its_lifetime() {
    let token = TokenInfo::from_response("tok".to_string(), None, None, Some(3600), None);
    let json = serde_json::to_value(&token).expect("serialize");
    assert_eq!(json["lifetime_secs"], serde_json::json!(3600), "{json}");
}

/// C5: an unset buffer is not written back as a number.
#[test]
fn an_unset_buffer_is_not_serialized() {
    let cfg: crate::config::OAuthConfig = crate::yaml::from_str("enabled: true\n").expect("parse");
    let text = crate::yaml::to_string(&cfg).expect("serialize");
    assert!(!text.contains("token_refresh_buffer_secs"), "{text}");
    let back: crate::config::OAuthConfig = crate::yaml::from_str(&text).expect("reload");
    let again = crate::yaml::to_string(&back).expect("serialize again");
    assert!(!again.contains("token_refresh_buffer_secs"), "{again}");
}

/// C7 (guard): a set buffer wins over the token lifetime: 60 s set, a
/// one-hour token with 200 s left does not refresh (10 % of 3600 would).
#[test]
fn a_set_buffer_wins_over_the_token_lifetime() {
    let token_dir = tempfile::tempdir().expect("token dir");
    let storage = Arc::new(TokenStorage::new(token_dir.path().join("tokens")).unwrap());
    let client = OAuthClient::new(
        Client::new(),
        "backend".to_string(),
        "http://localhost".to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: Some(60),
            ..Default::default()
        },
    );
    let token = TokenInfo {
        expires_at: Some(unix_now() + 200),
        ..TokenInfo::from_response("tok".to_string(), None, None, Some(3600), None)
    };
    *client.current_token.write() = Some(token);
    assert!(!client.needs_proactive_refresh());
}

/// C1: the derivation table.
#[test]
fn the_refresh_buffer_table() {
    use crate::oauth::client::refresh_buffer;
    assert_eq!(refresh_buffer(Some(60), Some(3600)), 60);
    assert_eq!(refresh_buffer(None, Some(3600)), 360);
    assert_eq!(refresh_buffer(None, Some(1800)), 300);
    assert_eq!(refresh_buffer(None, None), 300);
}

/// C2b (guard): a set buffer above the duration bound is still refused.
#[test]
fn a_set_buffer_above_the_bound_is_refused() {
    let over = crate::duration_bound::MAX_DURATION.as_secs() + 1;
    let parsed: std::result::Result<crate::config::OAuthConfig, crate::yaml::Error> =
        crate::yaml::from_str(&format!("token_refresh_buffer_secs: {over}\n"));
    let err = parsed.expect_err("refused").to_string();
    assert!(
        !err.contains(&over.to_string()),
        "the refused value is printed: {err}"
    );
}

/// C4c: a token answer without `expires_in` carries no lifetime.
#[test]
fn an_answer_without_expires_in_has_no_lifetime() {
    let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
    assert_eq!(token.lifetime_secs, None);
    let json = serde_json::to_value(&token).expect("serialize");
    assert!(json.get("lifetime_secs").is_none(), "{json}");
}

/// C6 (guard): a token stored before `lifetime_secs` existed loads, and its
/// buffer is the 300 s floor.
#[test]
fn an_old_stored_token_loads_with_the_floor_buffer() {
    let token: TokenInfo = serde_json::from_value(serde_json::json!({
        "access_token": "tok",
        "expires_at": unix_now() + 3600,
    }))
    .expect("an old token loads");
    assert_eq!(token.lifetime_secs, None);
    assert_eq!(
        crate::oauth::client::refresh_buffer(None, token.lifetime_secs),
        300
    );
}

/// C2a: `oauth: {}` leaves the buffer unset, not 300.
#[test]
fn an_empty_oauth_block_leaves_the_buffer_unset() {
    let cfg: crate::config::OAuthConfig = crate::yaml::from_str("{}\n").expect("parse");
    assert_eq!(cfg.token_refresh_buffer_secs, None);
}
