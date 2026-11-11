// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The revoke target selection, judged directly. A running gateway cannot
//! hold a digest shared between keys or with the bearer (the auth table is
//! refused at load), so `identity_in_use` is a defensive refusal no router
//! row can reach; these rows drive the pure selection with such inputs.

use super::{KeyIdentity, select_target};
use crate::gateway::auth::digest_tag_of;

fn digest(secret: &str) -> [u8; 32] {
    <sha2::Sha256 as sha2::Digest>::digest(secret.as_bytes()).into()
}

fn key<'a>(name: &'a str, current: &str, previous: Option<&str>) -> KeyIdentity<'a> {
    KeyIdentity {
        name,
        current: digest(current),
        previous: previous.map(digest),
    }
}

#[test]
fn a_target_sharing_another_keys_current_digest_is_identity_in_use() {
    let file = [key("target", "shared", None), key("other", "shared", None)];
    let error = select_target(&file, &[], "target", None, None).expect_err("refused");
    assert_eq!(error, "identity_in_use");
}

#[test]
fn a_target_sharing_another_keys_previous_digest_is_identity_in_use() {
    let file = [
        key("target", "target-secret", None),
        key("other", "other-secret", Some("target-secret")),
    ];
    let error = select_target(&file, &[], "target", None, None).expect_err("refused");
    assert_eq!(error, "identity_in_use");
}

#[test]
fn a_target_equal_to_the_running_bearer_is_identity_in_use() {
    let file = [key("target", "target-secret", None)];
    let error =
        select_target(&file, &[], "target", None, Some("target-secret")).expect_err("refused");
    assert_eq!(error, "identity_in_use");
}

#[test]
fn a_bound_absent_target_contributes_its_tag_and_selects() {
    let tag = digest_tag_of(&digest("gone-secret"));
    let others = [key("other", "other-secret", None)];
    let set = select_target(&others, &others, "target", Some(&tag), None).expect("selected");
    assert!(set.contains(&tag), "the bound tag joins the target set");
}

#[test]
fn a_clean_target_selects_its_current_and_previous_tags() {
    let file = [key("target", "target-secret", Some("old-secret"))];
    let set = select_target(&file, &file, "target", None, None).expect("selected");
    assert!(set.contains(&digest_tag_of(&digest("target-secret"))));
    assert!(set.contains(&digest_tag_of(&digest("old-secret"))));
    assert_eq!(set.len(), 2);
}
