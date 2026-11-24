// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config read lists each secret slot that holds a reference as a record
//! (server, kind, field, reference), because the flat `secret_references`
//! key joins those parts with dots and two slots can join to one key.
//!
//! RECORDS below is the agreed shape, and the Server page's tests use the same
//! content: one config, the records served for it (by server, then kind, then
//! field, each by bytes) and the flat map, which this change must not alter.

use super::*;

/// The config, its records in served order, and its flat map. In the config,
/// `git`'s header `env.TOKEN` and `git.headers`'s env `TOKEN` both join to
/// `backends.git.headers.env.TOKEN`, and both hold the same reference, so
/// the map's one value for that key is the same whichever slot is walked last.
/// `svc`'s header `env.KEY` joins to a key that also reads as an env `KEY` of a
/// server `svc.headers`, which does not exist. `git`'s env fields are written
/// out of byte order, and `git`'s `GIT_PLAIN` holds a plain value.
const RECORDS: &str = r#"{
  "gateway_yaml": "backends:\n  git:\n    command: 'echo'\n    env:\n      Z_TOKEN: 'env:GIT_Z'\n      a.b.TOKEN: 'env:GIT_DOTTED'\n      A_TOKEN: 'env:GIT_A'\n      GIT_PLAIN: 'a-plain-literal-value'\n    headers:\n      env.TOKEN: 'env:SHARED_TOKEN'\n      Authorization: 'keychain:gw.git'\n  git.headers:\n    command: 'echo'\n    env:\n      TOKEN: 'env:SHARED_TOKEN'\n  github:\n    command: 'echo'\n    env:\n      GITHUB_TOKEN: 'file:/run/secrets/github'\n  a:\n    command: 'echo'\n    headers:\n      x: 'env:A_X'\n  a.b:\n    command: 'echo'\n    env:\n      y: 'env:AB_Y'\n  svc:\n    command: 'echo'\n    headers:\n      env.KEY: 'keychain:gw.svc'\n",
  "secret_reference_records": [
    {"server": "a", "kind": "headers", "field": "x", "reference": "env:A_X"},
    {"server": "a.b", "kind": "env", "field": "y", "reference": "env:AB_Y"},
    {"server": "git", "kind": "env", "field": "A_TOKEN", "reference": "env:GIT_A"},
    {"server": "git", "kind": "env", "field": "Z_TOKEN", "reference": "env:GIT_Z"},
    {"server": "git", "kind": "env", "field": "a.b.TOKEN", "reference": "env:GIT_DOTTED"},
    {"server": "git", "kind": "headers", "field": "Authorization", "reference": "keychain:gw.git"},
    {"server": "git", "kind": "headers", "field": "env.TOKEN", "reference": "env:SHARED_TOKEN"},
    {"server": "git.headers", "kind": "env", "field": "TOKEN", "reference": "env:SHARED_TOKEN"},
    {"server": "github", "kind": "env", "field": "GITHUB_TOKEN", "reference": "file:/run/secrets/github"},
    {"server": "svc", "kind": "headers", "field": "env.KEY", "reference": "keychain:gw.svc"}
  ],
  "secret_references": {
    "backends.a.b.env.y": "env:AB_Y",
    "backends.a.headers.x": "env:A_X",
    "backends.git.env.A_TOKEN": "env:GIT_A",
    "backends.git.env.Z_TOKEN": "env:GIT_Z",
    "backends.git.env.a.b.TOKEN": "env:GIT_DOTTED",
    "backends.git.headers.Authorization": "keychain:gw.git",
    "backends.git.headers.env.TOKEN": "env:SHARED_TOKEN",
    "backends.github.env.GITHUB_TOKEN": "file:/run/secrets/github",
    "backends.svc.headers.env.KEY": "keychain:gw.svc"
  }
}"#;

fn records() -> Value {
    serde_json::from_str(RECORDS).expect("RECORDS is JSON")
}

/// GET /ui/api/config with `yaml` as the gateway's config file (none when
/// `yaml` is `None`).
async fn read_config(yaml: Option<&str>) -> Value {
    let dir = TempDir::new().expect("tempdir");
    let path = yaml.map(|text| {
        let path = dir.path().join("gateway.yaml");
        // Owner-only, as the gateway requires of a config that may hold secrets.
        write_owner_only(&path, text).expect("write the config");
        path
    });
    let (state, _store) = make_app_state(None, path).await;
    let (status, read) =
        send_json(&create_router(state), Method::GET, "/ui/api/config", None).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    read
}

/// REC.1, REC.3: the records are exactly the four-member list, in served
/// order; the pair that shares one flat key is two records with their own
/// server, kind and field; the key that also reads as another server's
/// slot gives only its real record.
#[tokio::test]
async fn rec1_each_reference_slot_is_one_record_in_served_order() {
    let want = records();
    let yaml = want["gateway_yaml"].as_str().expect("the config text");
    let read = read_config(Some(yaml)).await;

    assert_eq!(
        read["secret_reference_records"], want["secret_reference_records"],
        "{read}"
    );

    let map = read["secret_references"].as_object().expect("the flat map");
    let shared = "backends.git.headers.env.TOKEN";
    assert!(map.contains_key(shared), "{read}");
    let sharing: Vec<&Value> = read["secret_reference_records"]
        .as_array()
        .expect("the list")
        .iter()
        .filter(|r| {
            format!(
                "backends.{}.{}.{}",
                r["server"].as_str().unwrap_or_default(),
                r["kind"].as_str().unwrap_or_default(),
                r["field"].as_str().unwrap_or_default()
            ) == shared
        })
        .collect();
    assert_eq!(
        sharing,
        vec![
            &json!({"server": "git", "kind": "headers", "field": "env.TOKEN", "reference": "env:SHARED_TOKEN"}),
            &json!({"server": "git.headers", "kind": "env", "field": "TOKEN", "reference": "env:SHARED_TOKEN"}),
        ],
        "one flat key, two records"
    );
}

/// REC.2: the flat map is what the route served before the records existed.
/// A pin: green before this change too; the map below was recorded from it.
#[tokio::test]
async fn rec2_the_flat_map_is_unchanged() {
    let want = records();
    let yaml = want["gateway_yaml"].as_str().expect("the config text");
    let read = read_config(Some(yaml)).await;
    assert_eq!(
        serde_json::to_string(&read["secret_references"]).expect("json"),
        serde_json::to_string(&want["secret_references"]).expect("json"),
    );
}

/// REC.4: a slot holding a plain value is in neither the map nor the list,
/// and its value is nowhere in the answer.
#[tokio::test]
async fn rec4_a_plain_value_is_in_neither() {
    let want = records();
    let yaml = want["gateway_yaml"].as_str().expect("the config text");
    let read = read_config(Some(yaml)).await;
    let text = read.to_string();
    assert!(!text.contains("GIT_PLAIN"), "{text}");
    assert!(!text.contains("a-plain-literal-value"), "{text}");
}

/// The member is always present: an empty list for a config with no
/// reference, with no config path, and when the config does not load.
#[tokio::test]
async fn rec1_the_list_is_empty_never_missing() {
    let none = read_config(Some(
        "backends:\n  plain:\n    command: 'echo'\n    env:\n      K: 'v'\n",
    ))
    .await;
    let no_path = read_config(None).await;
    let broken = read_config(Some("backends: [unclosed\n")).await;
    for (case, read) in [
        ("no reference", &none),
        ("no config path", &no_path),
        ("a config that does not load", &broken),
    ] {
        assert_eq!(
            read["secret_reference_records"],
            json!([]),
            "{case}: {read}"
        );
        assert_eq!(read["secret_references"], json!({}), "{case}: {read}");
    }
}
