// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A new bearer token against the config's API keys (W5, SAVE.5): refused
//! before any store entry when it would match a key, or when a key cannot be
//! compared with it.

use super::*;

/// W5: a new bearer token that is an API key's credential is refused before
/// any store entry exists, and nothing is written.
#[tokio::test]
async fn a_bearer_duplicating_an_api_key_is_refused_before_any_store_entry() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    let base = with_key("");
    write_owner_only(&path, &base).expect("write config");
    let ctx = context(&path);
    let store = Counting::new(dir.path());

    replace_detached(
        ctx,
        save(
            dir.path(),
            Arc::clone(&store),
            &["auth", "bearer_token"],
            &with_key("  bearer_token: {slot}\n"),
            CRED,
        ),
        WAIT,
    )
    .await
    .expect_err("one secret would match two credentials");

    assert_eq!(read(&path), base);
    assert_eq!(
        store.creates(),
        0,
        "W5: a store entry was created for a bearer that duplicates an API key"
    );
}

/// SAVE.5: a key whose current or previous digest cannot be read is refused
/// by the shared-credential check before any entry, never left out of the
/// comparison; the refusal names the key's field, never the bearer or a
/// digest.
#[tokio::test]
async fn a_bearer_against_a_key_whose_digest_cannot_be_read_is_refused_before_entry() {
    let digest = crate::hashing::sha256_hex(CRED);
    let cases = [
        (
            "previous_key_sha256",
            "      previous_key_sha256: \"env:ZQ_SAVE5_UNSET_DIGEST\"\n      previous_expires_at: \"2099-01-01T00:00:00Z\"\n      key_sha256:",
        ),
        (
            "key_sha256",
            "      key_sha256: \"env:ZQ_SAVE5_UNSET_DIGEST\"\n      unused:",
        ),
    ];
    for (field, lines) in cases {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("gateway.yaml");
        let base = with_key("");
        write_owner_only(&path, &base).expect("write config");
        let ctx = context(&path);
        let store = Counting::new(dir.path());
        let mut unreadable = with_key("").replace("      key_sha256:", lines);
        if field == "key_sha256" {
            // The readable digest line is dropped: only the reference stays.
            unreadable = unreadable.replace(&format!("      unused: \"sha256:{digest}\"\n"), "");
        }
        let text = unreadable.replace("backends:\n", "  bearer_token: {slot}\nbackends:\n");

        let refused = replace_detached(
            ctx,
            save(
                dir.path(),
                Arc::clone(&store),
                &["auth", "bearer_token"],
                &text,
                CRED,
            ),
            WAIT,
        )
        .await
        .expect_err("a key that cannot be compared refuses the bearer");

        assert_eq!(read(&path), base, "{field}");
        assert_eq!(store.creates(), 0, "SAVE.5 {field}: an entry was created");
        let ReplaceError::Refused(message) = &refused else {
            panic!("SAVE.5 {field}: not the shared-credential refusal: {refused:?}");
        };
        assert_eq!(
            message,
            &format!(
                "auth.api_keys['ci'].{field} cannot be read, so the new bearer token \
                 cannot be checked against it; fix that key first"
            ),
            "SAVE.5 {field}"
        );
        let bearer = String::from_utf8_lossy(CRED);
        assert!(
            !message.contains(&digest) && !message.contains(bearer.as_ref()),
            "SAVE.5 {field}: the refusal quotes a credential: {message}"
        );
    }
}

/// W5, control: the collision is judged on the config the save makes, not
/// the running one. Removing key `ci` in the same save frees its credential
/// for the bearer.
#[tokio::test]
async fn a_running_key_removed_in_the_same_save_no_longer_collides() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, with_key("")).expect("write config");
    let ctx = context(&path);
    let store = Counting::new(dir.path());
    let without_key = "auth:\n  bearer_token: {slot}\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

    replace_detached(
        ctx,
        save(
            dir.path(),
            Arc::clone(&store),
            &["auth", "bearer_token"],
            without_key,
            CRED,
        ),
        WAIT,
    )
    .await
    .expect("the key is gone, so the bearer collides with nothing");

    assert!(read(&path).contains("bearer_token: \""), "{}", read(&path));
    assert_eq!(store.creates(), 1);
}
