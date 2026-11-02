// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A key's holders are bound to the secret that opened them: a leaked
//! rotation ends them, a routine one keeps them through the grace, and a row
//! stored without its secret is refused.

use super::*;

/// A subscription stored before holders were bound to their secret carries
/// its key's name and principal but no fingerprint: nothing says which secret
/// opened it, so it is refused (fail closed). The same row with the
/// fingerprint of the key's current secret is admitted (control).
#[tokio::test]
async fn a_subscription_stored_without_its_secret_is_refused() {
    let row = |tag: Option<String>| {
        let mut api_key = serde_json::json!({
            "name": "alice",
            "principal": crate::gateway::auth::principal_of("s1").storage_form(),
        });
        if let Some(tag) = tag {
            api_key["digest_tag"] = tag.into();
        }
        let stored = serde_json::json!({
            "v": 1, "id": "s", "principal": "p", "api_key": api_key,
            "url": "https://h/x", "name": "e", "arguments": {}, "secret": "whsec_x",
            "previous_secret": null, "previous_until": null,
            "granted_at": "2026-10-01T00:00:00Z", "expires_at": null, "active": true,
            "failed_since": null, "last_delivery_at": null, "last_error": null
        });
        serde_json::from_value::<Subscription>(stored).expect("loads")
    };
    let live = services(vec![key("alice", "s1", None)]);
    assert_eq!(
        live.admission(&row(None), Some("x")).await,
        AccessVerdict::Refuses,
        "a row stored without its secret's fingerprint was admitted"
    );
    let tag = crate::gateway::auth::secret_tag("s1");
    assert_eq!(
        live.admission(&row(Some(tag)), Some("x")).await,
        AccessVerdict::Admits,
        "control: the same row bound to the current secret is admitted"
    );
}

/// Two digests sharing their first 6 bytes share a derived principal and
/// would share a 12-hex fingerprint. A holder opened with one still ends when
/// the key rotates to the other: the tag is the full hash of the digest. The
/// control keeps the digest it was opened with and is admitted.
#[tokio::test]
async fn a_rotation_to_a_digest_sharing_the_old_prefix_still_ends_the_holder() {
    let prefix = "a1b2c3d4e5f6";
    let old = format!("{prefix}{}", "0".repeat(52));
    let new = format!("{prefix}{}", "1".repeat(52));
    let digest = |hex: &str| {
        crate::config::parse_api_key_digest(&format!("sha256:{hex}")).expect("a digest")
    };
    let with_digest = |hex: &str| ApiKeyConfig {
        key_sha256: Some(format!("sha256:{hex}")),
        ..key("alice", "unused", None)
    };
    let sub: Subscription = serde_json::from_value(serde_json::json!({
        "v": 1, "id": "s", "principal": "p",
        "api_key": {
            "name": "alice",
            "principal": prefix,
            "digest_tag": crate::gateway::auth::digest_tag_of(&digest(&old)),
        },
        "url": "https://h/x", "name": "e", "arguments": {}, "secret": "whsec_x",
        "previous_secret": null, "previous_until": null,
        "granted_at": "2026-10-01T00:00:00Z", "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("loads");
    // The tag is the whole hash of the digest, computed here on its own: a
    // later truncation fails this line even where the pair above would not.
    let whole = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(digest(&old)));
    assert_eq!(whole.len(), 64);
    assert_eq!(crate::gateway::auth::digest_tag_of(&digest(&old)), whole);
    assert_eq!(
        services(vec![with_digest(&old)])
            .admission(&sub, Some("x"))
            .await,
        AccessVerdict::Admits,
        "control: the digest it was opened with"
    );
    assert_eq!(
        services(vec![with_digest(&new)])
            .admission(&sub, Some("x"))
            .await,
        AccessVerdict::Refuses,
        "rotated to a digest sharing the old prefix, the holder lived on"
    );
}

/// A key rotated because its secret leaked keeps its principal, so its grants
/// and tasks survive (ADR-022), but a watch opened with the leaked secret must
/// stop: nothing that secret opened may keep receiving events.
#[test]
fn a_watch_opened_with_a_leaked_secret_ends_at_the_rotation() {
    let watch = presented("alice", "s1");
    let mut rotated = key("alice", "s2", None);
    rotated.principal = Some(watch.principal.clone());
    assert!(
        !services(vec![rotated]).admits(Some(&watch), "x"),
        "a leaked rotation left the old secret's watch admitted"
    );
}

/// A routine rotation keeps the old secret's watch for the grace, and only
/// for the grace.
#[test]
fn a_watch_opened_with_the_old_secret_lasts_exactly_the_grace() {
    let watch = presented("alice", "s1");
    let rotated = |grace_end| {
        let mut k = key("alice", "s2", None);
        k.principal = Some(watch.principal.clone());
        k.previous_key_sha256 = Some(api_key_digest_spec(b"s1"));
        k.previous_expires_at = Some(grace_end);
        k
    };
    let now = chrono::Utc::now();
    assert!(
        services(vec![rotated(
            now + crate::duration_bound::delta!(minutes, 15)
        )])
        .admits(Some(&watch), "x"),
        "inside the grace the old secret's watch carries on"
    );
    assert!(
        !services(vec![rotated(
            now - crate::duration_bound::delta!(minutes, 1)
        )])
        .admits(Some(&watch), "x"),
        "after the grace the old secret's watch was still admitted"
    );
}
