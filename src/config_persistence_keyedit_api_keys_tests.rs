// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API-key rows: the edits the web UI's key routes make to `auth.api_keys`,
//! on the auth block `gateway init` writes. Adding a key and adding,
//! changing or removing one of its fields are edits the editor already
//! proves; removing a whole key is a list-element removal.

use super::super::GiveUp;
use super::*;

/// The auth block `build_init_config` writes (src/commands/mod.rs), with
/// its comments and a fixed token: it holds no `api_keys`.
const INIT_AUTH: &str = "\
# Admin credential, generated for this install.
#
# On Unix this file is written readable only by you. Do not commit it.
auth:
  enabled: true
  bearer_token: \"init-token\"
  single_user: true
  public_paths:
    - \"/health\"
    - \"/mcp\"

# Auth is on, so every tool call is recorded in a tamper-evident audit
security:
  transparency_log:
    enabled: true
";

/// One configured key, after a first create.
const ONE_KEY: &str = "\
auth:
  enabled: true # keys below
  api_keys:
    - name: ops
      key_sha256: \"sha256:aa\"
      previous_key_sha256: \"sha256:bb\"
      previous_expires_at: \"2026-12-01T00:00:00Z\"
";

fn api_key(i: usize, field: &str) -> FieldPath {
    FieldPath(vec![
        Segment::Key("auth".into()),
        Segment::Key("api_keys".into()),
        Segment::Index(i),
        Segment::Key(field.into()),
    ])
}

fn set(i: usize, field: &str, value: &str) -> (FieldPath, Change) {
    (api_key(i, field), Change::Set(Scalar::Str(value.into())))
}

/// Every line of `original` is still in `edited`, in order: the edit only
/// added or removed lines.
#[track_caller]
fn keeps_every_line(original: &str, edited: &str) {
    let mut rest = edited.lines();
    for line in original.lines() {
        assert!(
            rest.any(|l| l == line),
            "line {line:?} was lost or moved in:\n{edited}"
        );
    }
}

fn loaded(text: &str) -> crate::yaml::Value {
    crate::yaml::from_str(text).expect("the edited file loads")
}

#[test]
fn a_first_key_on_inits_file_creates_the_list() {
    let out = edited(
        INIT_AUTH,
        &[set(0, "name", "ops"), set(0, "key_sha256", "sha256:aa")],
    );
    keeps_every_line(INIT_AUTH, &out);
    let doc = loaded(&out);
    assert_eq!(doc["auth"]["api_keys"][0]["name"], "ops", "{out}");
    assert_eq!(
        doc["auth"]["api_keys"][0]["key_sha256"], "sha256:aa",
        "{out}"
    );
    assert_eq!(doc["auth"]["bearer_token"], "init-token", "{out}");
}

#[test]
fn a_second_key_is_appended() {
    let out = edited(
        ONE_KEY,
        &[set(1, "name", "ci"), set(1, "key_sha256", "sha256:cc")],
    );
    keeps_every_line(ONE_KEY, &out);
    let doc = loaded(&out);
    assert_eq!(doc["auth"]["api_keys"][0]["name"], "ops", "{out}");
    assert_eq!(doc["auth"]["api_keys"][1]["name"], "ci", "{out}");
}

#[test]
fn a_rotation_adds_fields_to_an_existing_key() {
    let original = "auth:\n  api_keys:\n    - name: ops\n      key_sha256: \"sha256:aa\"\n";
    let out = edited(
        original,
        &[
            set(0, "key_sha256", "sha256:cc"),
            set(0, "previous_key_sha256", "sha256:aa"),
            set(0, "previous_expires_at", "2026-12-01T00:00:00Z"),
        ],
    );
    let doc = loaded(&out);
    let key = &doc["auth"]["api_keys"][0];
    assert_eq!(key["key_sha256"], "sha256:cc", "{out}");
    assert_eq!(key["previous_key_sha256"], "sha256:aa", "{out}");
    assert_eq!(key["previous_expires_at"], "2026-12-01T00:00:00Z", "{out}");
}

#[test]
fn a_rotation_field_is_removed_from_a_key() {
    let out = edited(
        ONE_KEY,
        &[
            (api_key(0, "previous_key_sha256"), Change::Remove),
            (api_key(0, "previous_expires_at"), Change::Remove),
        ],
    );
    let doc = loaded(&out);
    let key = &doc["auth"]["api_keys"][0];
    assert!(key.get("previous_key_sha256").is_none(), "{out}");
    assert!(key.get("previous_expires_at").is_none(), "{out}");
    assert_eq!(key["name"], "ops", "{out}");
    assert!(out.contains("# keys below"), "{out}");
}

/// Removing a whole key is a list-element removal, which the editor
/// refuses today. This row pins that before the removal is built.
#[test]
fn removing_a_whole_key_gives_up_today() {
    let whole = FieldPath(vec![
        Segment::Key("auth".into()),
        Segment::Key("api_keys".into()),
        Segment::Index(0),
    ]);
    match edit_in_place(ONE_KEY, &[(whole, Change::Remove)]) {
        Err(ComputeRefusal::Unprovable { code, .. }) => {
            assert_eq!(code, GiveUp::SequenceShape);
        }
        other => panic!("expected a sequence-shape give-up, got {other:?}"),
    }
}
