// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A revocation through the route in a file whose document sits in a YAML
//! frame: the entry goes, the key stops working, and the frame stays.

use super::super::keys_create_fixture_tests::{item, root_item, yaml_of};
use super::keys_revoke_target_tests::{tag, target_setup};
use super::*;

#[test]
fn a_framed_file_takes_a_revocation_through_the_route() {
    let mut setup = target_setup();
    let keys = yaml_of(&[root_item(), item("target", "target-secret", "")]);
    setup.text = format!("--- # gateway\n{keys}...\n");
    let fx = Fixture::new(setup);
    let body = json!({"revision": revision(&fx), "expected_key_tag": tag("target-secret")});
    let sent = send_delete(&fx, "target", Call::new(&body), None);
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.body);
    assert_eq!(sent.json()["revoked"], true, "{}", sent.body);
    let text = fx.text();
    assert!(text.starts_with("--- # gateway\n"), "{text:?}");
    assert!(text.ends_with("...\n"), "{text:?}");
    assert!(!text.contains("name: target"), "{text:?}");
    let generation = fx.live.generation();
    let auth = generation.auth();
    assert!(
        auth.validate_token("target-secret").is_none(),
        "the revoked key still works"
    );
    assert!(
        auth.validate_token(super::super::keys_create_fixture_tests::ROOT)
            .is_some()
    );
}
