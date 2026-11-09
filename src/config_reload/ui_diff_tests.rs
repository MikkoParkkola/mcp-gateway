// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The settings preview (rows D1-D25).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{PatchStep, PreviewRefused, Shown, UiPreview, UiRefused, path_text, ui_diff};
use crate::config_persistence::keyedit::{GiveUp, Scalar, Segment};
use crate::config_reload::ReloadContext;
use crate::config_reload::reload_context::replace::{FileRevision, RefusalClass};
use crate::config_reload::ui_fields::{FieldId, Param, PreviewEdit, PreviewValue};
use crate::gateway::test_helpers::write_owner_only;

const URL: &str = "http://127.0.0.1:9/mcp";

/// gateway.yaml holding `text`, and a gateway started on it.
fn gateway(text: &str) -> (tempfile::TempDir, PathBuf, Arc<ReloadContext>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, text).expect("write");
    let ctx = crate::config_reload::replace_test_support::context(&path);
    (dir, path, ctx)
}

fn rewrite(path: &Path, text: &str) {
    write_owner_only(path, text).expect("rewrite");
}

fn id(name: &str) -> FieldId {
    FieldId::of(name).expect("in FIELDS")
}

fn set(name: &str, param: Param, value: Scalar) -> (FieldId, Param, PreviewValue) {
    (id(name), param, PreviewValue::Set(value))
}

fn s(text: &str) -> Scalar {
    Scalar::Str(text.to_owned())
}

fn on(backend: &str) -> Param {
    Param {
        backend: Some(backend.to_owned()),
        index: None,
    }
}

fn edit(fields: Vec<(FieldId, Param, PreviewValue)>) -> PreviewEdit {
    PreviewEdit { fields }
}

async fn preview(ctx: &ReloadContext, fields: Vec<(FieldId, Param, PreviewValue)>) -> UiPreview {
    match ui_diff(ctx, &edit(fields)).await {
        Ok(preview) => preview,
        Err(e) => panic!("previewed: {e:?}"),
    }
}

fn diff_text(preview: &UiPreview) -> String {
    match &preview.shown {
        Shown::Diff(diff) => diff.render(),
        Shown::Patch(patch) => panic!("a diff, got the patch {patch:?}"),
    }
}

fn patch_of(preview: &UiPreview) -> &super::Patch {
    match &preview.shown {
        Shown::Patch(patch) => patch,
        Shown::Diff(diff) => panic!("the patch, got the diff {}", diff.render()),
    }
}

fn key(k: &str) -> Segment {
    Segment::Key(k.to_owned())
}

/// D1, D9: one typed change is one `-`/`+` pair under the two headers, no
/// other line of the commented file; the revision is the bytes' hash.
#[tokio::test]
async fn a_typed_change_returns_a_zero_context_unified_diff() {
    let text = "# operator's note\nenvironment: \"dev\"\nauth:\n  enabled: false\n";
    let (_dir, _path, ctx) = gateway(text);
    let got = preview(&ctx, vec![set("environment", Param::default(), s("prod"))]).await;
    assert_eq!(
        diff_text(&got),
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -2,1 +2,1 @@\n-environment: \"dev\"\n+environment: \"prod\"\n"
    );
    assert_eq!(got.revision, FileRevision::of(text.as_bytes()));
}

/// D2: an insert that creates its parent, and a removal that empties one,
/// each show only their own lines.
#[tokio::test]
async fn an_inserted_and_a_removed_field_show_as_their_own_lines() {
    let (_dir, _path, ctx) = gateway("environment: \"dev\"\n");
    let got = preview(
        &ctx,
        vec![set(
            "auth.single_user",
            Param::default(),
            Scalar::Bool(true),
        )],
    )
    .await;
    assert_eq!(
        diff_text(&got),
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -1,0 +2,2 @@\n+auth:\n+  single_user: true\n"
    );
    let (_dir, _path, ctx) = gateway("environment: \"dev\"\nauth:\n  single_user: true\n");
    let got = preview(
        &ctx,
        vec![(
            id("auth.single_user"),
            Param::default(),
            PreviewValue::Remove,
        )],
    )
    .await;
    assert_eq!(
        diff_text(&got),
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -2,2 +1,0 @@\n-auth:\n-  single_user: true\n"
    );
}

/// D3: a secret field's old literal shows as `<set>`, the new secret as
/// `<new secret>`; neither the literal nor a slot placeholder appears.
#[tokio::test]
async fn a_secret_field_shows_masked_old_and_new() {
    let (_dir, _path, ctx) = gateway("auth:\n  bearer_token: \"s3cr3t-literal\"\n");
    let got = preview(
        &ctx,
        vec![(
            id("auth.bearer_token"),
            Param::default(),
            PreviewValue::Secret,
        )],
    )
    .await;
    let text = diff_text(&got);
    assert_eq!(
        text,
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -2,1 +2,1 @@\n-  bearer_token: <set>\n+  bearer_token: <new secret>\n"
    );
    assert!(
        !text.contains("s3cr3t") && !text.contains("__mcpgw_slot_"),
        "{text}"
    );
}

/// D4: an edit beside credentials of other fields, among repeated identical
/// lines, shows none of them.
#[tokio::test]
async fn no_neighbouring_credential_ever_appears() {
    let text = format!(
        "auth:\n  bearer_token: \"bearer-neighbour-1\"\nbackends:\n  one:\n    http_url: \"{URL}\"\n    env:\n      API_KEY: \"env-neighbour-2\"\n    owner: \"Team A\"\n  two:\n    http_url: \"{URL}\"\n    env:\n      API_KEY: \"env-neighbour-2\"\n    owner: \"Team A\"\n"
    );
    let (_dir, _path, ctx) = gateway(&text);
    let got = preview(&ctx, vec![set("backends.owner", on("two"), s("Team B"))]).await;
    let text = diff_text(&got);
    assert_eq!(
        text,
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -13,1 +13,1 @@\n-    owner: \"Team A\"\n+    owner: \"Team B\"\n"
    );
    assert!(!text.contains("neighbour"), "{text}");
}

/// D5: an edit of an aliased key cannot be proven in place: the patch, with
/// the editor's code and one step.
#[tokio::test]
async fn an_anchored_edited_key_returns_the_patch() {
    let (_dir, _path, ctx) = gateway("x-defaults: &env \"dev\"\nenvironment: *env\n");
    let got = preview(&ctx, vec![set("environment", Param::default(), s("prod"))]).await;
    let patch = patch_of(&got);
    assert_eq!(patch.code, GiveUp::Anchor, "{patch:?}");
    assert_eq!(
        patch.steps,
        vec![PatchStep::Set {
            path: vec![key("environment")],
            value: Some("\"prod\"".to_owned()),
        }]
    );
}

/// D6: a secret in a patch is a step with no value and no placeholder.
#[tokio::test]
async fn a_secret_field_in_a_patch_is_a_valueless_step() {
    let (_dir, _path, ctx) = gateway("auth:\n  bearer_token: &t \"lit-d6\"\nx-copy: *t\n");
    let got = preview(
        &ctx,
        vec![(
            id("auth.bearer_token"),
            Param::default(),
            PreviewValue::Secret,
        )],
    )
    .await;
    let patch = patch_of(&got);
    assert_eq!(
        patch.steps,
        vec![PatchStep::SetSecret {
            path: vec![key("auth"), key("bearer_token")],
        }]
    );
    let shown = format!("{patch:?}");
    assert!(
        !shown.contains("lit-d6") && !shown.contains("__mcpgw_slot_"),
        "{shown}"
    );
}

/// D7: a backend resolves against the bytes read, not the loaded config.
#[tokio::test]
async fn parameters_resolve_against_the_bytes_read() {
    let (_dir, path, ctx) = gateway(&format!("backends:\n  svc:\n    http_url: \"{URL}\"\n"));
    rewrite(
        &path,
        &format!("backends:\n  other:\n    http_url: \"{URL}\"\n"),
    );
    let got = ui_diff(&ctx, &edit(vec![set("backends.owner", on("svc"), s("A"))])).await;
    assert!(
        matches!(got, Err(UiRefused::BadParam(f, _)) if f == id("backends.owner")),
        "{got:?}"
    );
}

/// D8: a pending journal is refused and left for the writer; a missing
/// file is refused.
#[tokio::test]
async fn a_pending_journal_and_a_missing_config_are_refused() {
    let text = "environment: \"dev\"\n";
    let (_dir, path, ctx) = gateway(text);
    crate::config_persistence::journal::begin(
        &path,
        FileRevision::of(text.as_bytes()).as_str().to_owned(),
    )
    .expect("journal");
    let one = || edit(vec![set("environment", Param::default(), s("prod"))]);
    let got = ui_diff(&ctx, &one()).await;
    assert_eq!(got, Err(UiRefused::Preview(PreviewRefused::Recovering)));
    assert!(
        crate::config_persistence::lock::journal_pending(&path),
        "the journal is left"
    );
    let (_dir, path, ctx) = gateway(text);
    std::fs::remove_file(&path).expect("remove");
    let got = ui_diff(&ctx, &one()).await;
    assert_eq!(got, Err(UiRefused::Preview(PreviewRefused::NoConfigFile)));
}

/// D10: a backend name that is not a plain key gives the patch, its path
/// quoted so it names the one key.
#[tokio::test]
async fn a_non_plain_backend_name_returns_a_quoted_patch_path() {
    let (_dir, _path, ctx) = gateway(&format!(
        "backends:\n  team.prod:\n    http_url: \"{URL}\"\n"
    ));
    let got = preview(&ctx, vec![set("backends.owner", on("team.prod"), s("A"))]).await;
    let patch = patch_of(&got);
    assert_eq!(patch.code, GiveUp::NotPlainKey, "{patch:?}");
    let PatchStep::Set { path, .. } = &patch.steps[0] else {
        panic!("{patch:?}");
    };
    assert_eq!(path_text(path), "backends.\"team.prod\".owner");
    assert_eq!(
        path_text(&[key("a"), Segment::Index(2), key("b")]),
        "a[2].b"
    );
}

/// D11: a preview writes nothing, whichever answer it gives.
#[tokio::test]
async fn ui_diff_writes_nothing() {
    for text in [
        "environment: \"dev\"\n",
        "x-d: &e \"dev\"\nenvironment: *e\n",
    ] {
        let (_dir, path, ctx) = gateway(text);
        let before = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .expect("mtime");
        let _ = preview(&ctx, vec![set("environment", Param::default(), s("prod"))]).await;
        assert_eq!(std::fs::read_to_string(&path).expect("read"), text);
        let after = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .expect("mtime");
        assert_eq!(before, after, "{text:?}");
    }
}

/// D13: a secret written over several lines cannot be shown masked line
/// for line: the patch, with no value.
#[tokio::test]
async fn a_multi_line_secret_in_a_hunk_gives_the_valueless_patch() {
    let (_dir, _path, ctx) =
        gateway("environment: \"dev\"\nauth:\n  bearer_token: |\n    multi-line-secret\n");
    let got = preview(
        &ctx,
        vec![(
            id("auth.bearer_token"),
            Param::default(),
            PreviewValue::Remove,
        )],
    )
    .await;
    let patch = patch_of(&got);
    assert_eq!(patch.code, GiveUp::SecretSpan, "{patch:?}");
    assert!(!format!("{patch:?}").contains("multi-line"), "{patch:?}");
}

/// D17: removing the secret field shows its line masked.
#[tokio::test]
async fn removing_the_secret_field_shows_it_masked() {
    let (_dir, _path, ctx) =
        gateway("environment: \"dev\"\nauth:\n  bearer_token: \"s3cr3t-d17\"\n");
    let got = preview(
        &ctx,
        vec![(
            id("auth.bearer_token"),
            Param::default(),
            PreviewValue::Remove,
        )],
    )
    .await;
    assert_eq!(
        diff_text(&got),
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -2,2 +1,0 @@\n-auth:\n-  bearer_token: <set>\n"
    );
}

/// D18: a file that does not parse is refused, no patch.
#[tokio::test]
async fn an_unparseable_config_is_invalid() {
    let (_dir, path, ctx) = gateway("environment: \"dev\"\n");
    rewrite(&path, "environment: [\n");
    let got = ui_diff(
        &ctx,
        &edit(vec![set("environment", Param::default(), s("prod"))]),
    )
    .await;
    assert!(matches!(got, Err(UiRefused::Invalid(_))), "{got:?}");
}

/// D20: a typed value is the caller's own input and is shown as typed, even
/// when it equals a secret in the file; the secret's line never appears.
#[tokio::test]
async fn a_typed_value_is_echoed_as_typed() {
    let (_dir, _path, ctx) =
        gateway("environment: \"dev\"\nauth:\n  bearer_token: \"same-as-typed\"\n");
    let got = preview(
        &ctx,
        vec![set("environment", Param::default(), s("same-as-typed"))],
    )
    .await;
    assert_eq!(
        diff_text(&got),
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -1,1 +1,1 @@\n-environment: \"dev\"\n+environment: \"same-as-typed\"\n"
    );
}

/// D21: a provable edit whose result the reload would refuse is `Invalid`.
/// The loader's refusal is now typed.
#[tokio::test]
async fn an_edit_the_loader_refuses_is_invalid() {
    let (_dir, path, ctx) = gateway("environment: \"dev\"\n");
    rewrite(
        &path,
        "environment: \"dev\"\nsecurity:\n  posture: hardened\n",
    );
    let got = ui_diff(
        &ctx,
        &edit(vec![set("environment", Param::default(), s("prod"))]),
    )
    .await;
    assert!(
        matches!(
            &got,
            Err(UiRefused::ReloadRefused {
                class: RefusalClass::Invalid
            })
        ),
        "{got:?}"
    );
}

/// D22: an unprovable edit whose result the reload would refuse is
/// `Invalid`, not a patch.
/// The loader's refusal is now typed.
#[tokio::test]
async fn an_unprovable_edit_the_loader_refuses_is_invalid_not_a_patch() {
    let (_dir, path, ctx) = gateway("environment: \"dev\"\n");
    rewrite(
        &path,
        "x-e: &e \"dev\"\nenvironment: *e\nsecurity:\n  posture: hardened\n",
    );
    let got = ui_diff(
        &ctx,
        &edit(vec![set("environment", Param::default(), s("prod"))]),
    )
    .await;
    assert!(
        matches!(
            &got,
            Err(UiRefused::ReloadRefused {
                class: RefusalClass::Invalid
            })
        ),
        "{got:?}"
    );
}

/// D23: a trailing comment on the edited line shows as a marker, never its
/// text.
#[tokio::test]
async fn an_inline_comment_on_the_edited_line_is_shown_as_a_marker() {
    let (_dir, _path, ctx) = gateway("environment: \"dev\"  # token=hidden-d23\n");
    let got = preview(&ctx, vec![set("environment", Param::default(), s("prod"))]).await;
    assert_eq!(
        diff_text(&got),
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -1,1 +1,1 @@\n-environment: \"dev\"  # <comment>\n+environment: \"prod\"  # <comment>\n"
    );
}

/// D24: a flow sibling on the edited line never appears.
#[tokio::test]
async fn a_flow_sibling_on_the_edited_line_gives_the_valueless_patch() {
    let (_dir, _path, ctx) = gateway("auth: {enabled: false, bearer_token: \"flow-secret\"}\n");
    let got = preview(
        &ctx,
        vec![set(
            "auth.single_user",
            Param::default(),
            Scalar::Bool(true),
        )],
    )
    .await;
    // The editor refuses to insert into a flow mapping before any diff is
    // built (`config_persistence_keyedit.rs`: insertion gives up when the
    // parent is flow style); the verifier's own flow case is D14.
    let patch = patch_of(&got);
    assert_eq!(patch.code, GiveUp::Flow, "{patch:?}");
    assert!(!format!("{patch:?}").contains("flow-secret"), "{patch:?}");
}

/// D16: a link to the startup file previews; one repointed since is
/// refused.
#[cfg(unix)]
#[tokio::test]
async fn a_repointed_symlink_is_refused_and_the_trusted_one_previews() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (real, other) = (dir.path().join("real.yaml"), dir.path().join("other.yaml"));
    write_owner_only(&real, "environment: \"dev\"\n").expect("write");
    write_owner_only(&other, "environment: \"dev\"\n").expect("write");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&real, &link).expect("link");
    let ctx = crate::config_reload::replace_test_support::context(&link);
    let one = || edit(vec![set("environment", Param::default(), s("prod"))]);
    assert!(ui_diff(&ctx, &one()).await.is_ok());
    std::fs::remove_file(&link).expect("unlink");
    std::os::unix::fs::symlink(&other, &link).expect("relink");
    let got = ui_diff(&ctx, &one()).await;
    assert!(
        matches!(got, Err(UiRefused::Preview(PreviewRefused::Untrusted(_)))),
        "{got:?}"
    );
}

#[cfg(feature = "cost-governance")]
fn at(index: usize) -> Param {
    Param {
        backend: None,
        index: Some(index),
    }
}

#[cfg(feature = "cost-governance")]
fn alert(index: usize, percent: i64, action: &str) -> Vec<(FieldId, Param, PreviewValue)> {
    vec![
        set(
            "cost_governance.alerts.at_percent",
            at(index),
            Scalar::Int(percent),
        ),
        set("cost_governance.alerts.action", at(index), s(action)),
    ]
}

/// D7 (indices): an index past the end, or a new element missing a field,
/// is refused; one complete new element at the end is accepted.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn alert_indices_resolve_against_the_bytes_read() {
    let text = "cost_governance:\n  alerts:\n    - at_percent: 50\n      action: \"log\"\n";
    let (_dir, _path, ctx) = gateway(text);
    let past = ui_diff(&ctx, &edit(alert(2, 90, "block"))).await;
    assert!(matches!(past, Err(UiRefused::BadParam(..))), "{past:?}");
    let half = ui_diff(
        &ctx,
        &edit(vec![set(
            "cost_governance.alerts.at_percent",
            at(1),
            Scalar::Int(90),
        )]),
    )
    .await;
    assert!(matches!(half, Err(UiRefused::BadParam(..))), "{half:?}");
    let got = preview(&ctx, alert(1, 90, "block")).await;
    assert_eq!(
        diff_text(&got),
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -4,0 +5,2 @@\n+    - at_percent: 90\n+      action: \"block\"\n"
    );
}

/// D19: a contiguous complete batch of new alerts is accepted and, as the
/// editor appends one new element only, given as the patch.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_contiguous_complete_batch_of_new_alerts_gives_the_patch() {
    let (_dir, _path, ctx) = gateway("environment: \"dev\"\n");
    let mut fields = alert(0, 50, "log");
    fields.extend(alert(1, 80, "notify"));
    fields.extend(alert(2, 100, "block"));
    let got = preview(&ctx, fields).await;
    let patch = patch_of(&got);
    assert_eq!(patch.code, GiveUp::SequenceShape, "{patch:?}");
    assert_eq!(patch.steps.len(), 6);
}

/// A3: one alert on a file without the list shows the whole one-element
/// list the file will hold (its three defaults no longer apply).
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn an_alert_without_an_alerts_key_shows_the_whole_new_list() {
    let (_dir, _path, ctx) = gateway("environment: \"dev\"\n");
    let got = preview(&ctx, alert(0, 50, "log")).await;
    assert_eq!(
        diff_text(&got),
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -1,0 +2,4 @@\n+cost_governance:\n+  alerts:\n+    - at_percent: 50\n+      action: \"log\"\n"
    );
}

/// D14 (written after the code, disclosed): the verifier itself, on crafted
/// hunks. A line of the file outside the edited node, a flow line holding a
/// sibling, or a replaced line whose kept bytes are not the key part is
/// refused; an admitted line shows a trailing comment only as a marker.
#[test]
fn the_verifier_refuses_a_foreign_original_line() {
    use crate::config_persistence::keyedit::{Change, FieldPath, Hunk, NewLine};
    let env = FieldPath(vec![key("environment")]);
    let changes = [(env.clone(), Change::Set(s("prod")))];
    let old = |lines: Vec<usize>| Hunk {
        old_start: lines[0] + 1,
        old: lines,
        new_start: 1,
        new: vec![],
    };
    // A foreign key line in a hunk: refused, as a secret when one is edited.
    let file = "environment: \"dev\"\nauth:\n  bearer_token: \"foreign-1\"\n";
    let foreign = [old(vec![2])];
    assert_eq!(
        super::show::diff(file, &changes, &[], &foreign),
        Err(GiveUp::Other)
    );
    let token = FieldPath(vec![key("auth"), key("bearer_token")]);
    assert_eq!(
        super::show::diff(file, &changes, &[token], &foreign),
        Err(GiveUp::SecretSpan)
    );
    // A flow line: its sibling is not the edited node's.
    let flow = "auth: {enabled: false, bearer_token: \"flow-2\"}\n";
    let on = [(
        FieldPath(vec![key("auth"), key("enabled")]),
        Change::Set(Scalar::Bool(true)),
    )];
    assert!(super::show::diff(flow, &on, &[], &[old(vec![0])]).is_err());
    // A replaced line must keep exactly the key part before its new value.
    let shifted = [Hunk {
        old_start: 1,
        old: vec![0],
        new_start: 1,
        new: vec![NewLine {
            text: "environment: \"prod\"".into(),
            replaced: Some((0, 2, 0)),
        }],
    }];
    assert!(super::show::diff(file, &changes, &[], &shifted).is_err());
    // An admitted line: the comment is a marker, never its text.
    let commented = "environment: \"dev\"  # comment-3\n";
    let shown = super::show::diff(commented, &changes, &[], &[old(vec![0])]).expect("admitted");
    assert_eq!(
        shown.hunks[0].old,
        vec!["environment: \"dev\"  # <comment>".to_owned()]
    );
}

/// D25 (written after the code, disclosed): a patch given because the diff
/// could not be masked carries no value at all, not even a typed one
/// (`ui_diff.rs`, the verifier's refusal calls `patch(.., true)`; the
/// `Patch` invariant in the spec).
#[tokio::test]
async fn a_masking_refusal_withholds_every_value() {
    let (_dir, _path, ctx) =
        gateway("environment: \"dev\"\nauth:\n  bearer_token: |\n    multi-line-secret\n");
    let got = preview(
        &ctx,
        vec![
            set("environment", Param::default(), s("prod")),
            (
                id("auth.bearer_token"),
                Param::default(),
                PreviewValue::Remove,
            ),
        ],
    )
    .await;
    let patch = patch_of(&got);
    assert_eq!(patch.code, GiveUp::SecretSpan, "{patch:?}");
    assert_eq!(
        patch.steps,
        vec![
            PatchStep::Set {
                path: vec![key("environment")],
                value: None,
            },
            PatchStep::Remove {
                path: vec![key("auth"), key("bearer_token")],
            },
        ]
    );
}

/// D26: an old secret reference whose quoted spelling escapes a newline
/// (`"env:OLD\n+forged"`) would print as two lines: the valueless patch,
/// and no part of it shown.
#[tokio::test]
async fn an_escaped_newline_in_an_old_reference_gives_the_valueless_patch() {
    let (_dir, config, ctx) = gateway("environment: \"dev\"\n");
    rewrite(&config, "auth:\n  bearer_token: \"env:OLD\\n+forged\"\n");
    let got = preview(
        &ctx,
        vec![(
            id("auth.bearer_token"),
            Param::default(),
            PreviewValue::Secret,
        )],
    )
    .await;
    let patch = patch_of(&got);
    assert_eq!(patch.code, GiveUp::SecretSpan, "{patch:?}");
    assert!(!format!("{patch:?}").contains("forged"), "{patch:?}");
}

/// D27: a typed value equal to a slot's placeholder text is refused,
/// never masked: the editor gives up on an edit whose text holds a slot's
/// placeholder twice ("the file already holds a slot placeholder",
/// `config_persistence_keyedit.rs` `edit_in_place`), and the patch path's
/// check of the expected document refuses it too
/// (`Template::from_placeholders`: each placeholder exactly once), which
/// `ui_diff` reports as `Unsupported` (`ui_diff.rs`, "the edit's secret slots
/// could not be checked").
#[tokio::test]
async fn a_typed_value_equal_to_a_placeholder_is_refused() {
    let (_dir, _path, ctx) = gateway("environment: \"dev\"\nauth:\n  bearer_token: \"old\"\n");
    let got = ui_diff(
        &ctx,
        &edit(vec![
            set(
                "environment",
                Param::default(),
                s("__mcpgw_slot_auth.bearer_token__"),
            ),
            (
                id("auth.bearer_token"),
                Param::default(),
                PreviewValue::Secret,
            ),
        ]),
    )
    .await;
    assert!(matches!(got, Err(UiRefused::Unsupported(_))), "{got:?}");
}

/// D29: a CRLF file shows the same lines as its LF copy, the comment as a
/// marker.
#[tokio::test]
async fn a_crlf_file_shows_the_same_lines() {
    let (_dir, _path, ctx) = gateway("# note\r\nenvironment: \"dev\"  # why\r\n");
    let got = preview(&ctx, vec![set("environment", Param::default(), s("prod"))]).await;
    assert_eq!(
        diff_text(&got),
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -2,1 +2,1 @@\n-environment: \"dev\"  # <comment>\n+environment: \"prod\"  # <comment>\n"
    );
}

/// D19b: a reordered batch previews as the table-ordered one, and its
/// steps follow the table, then the index.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_reordered_alert_batch_gives_the_table_ordered_patch() {
    let (_dir, _path, ctx) = gateway("environment: \"dev\"\n");
    let mut fields = alert(1, 80, "notify");
    fields.extend(alert(0, 50, "log"));
    let got = preview(&ctx, fields).await;
    let patch = patch_of(&got);
    let order: Vec<String> = patch
        .steps
        .iter()
        .map(|step| match step {
            PatchStep::Set { path, .. } => path_text(path),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        order,
        [
            "cost_governance.alerts[0].at_percent",
            "cost_governance.alerts[1].at_percent",
            "cost_governance.alerts[0].action",
            "cost_governance.alerts[1].action",
        ]
    );
}

/// D28: an alert field on its element's dash line shows that line, dash
/// and all.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn an_alert_on_its_dash_line_shows_that_line() {
    let text = "cost_governance:\n  alerts:\n    - at_percent: 50\n      action: \"log\"\n";
    let (_dir, _path, ctx) = gateway(text);
    let got = preview(
        &ctx,
        vec![set(
            "cost_governance.alerts.at_percent",
            at(0),
            Scalar::Int(60),
        )],
    )
    .await;
    assert_eq!(
        diff_text(&got),
        "--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -3,1 +3,1 @@\n-    - at_percent: 50\n+    - at_percent: 60\n"
    );
}

/// K8: red oracle is a `BadParam` reason that omits the submitted backend name.
#[tokio::test]
async fn k8_missing_backend_does_not_echo_name() {
    const CANARY: &str = "missing-backend-canary";
    let (_dir, _path, ctx) = gateway("backends: {}\n");
    let error = ui_diff(&ctx, &edit(vec![set("backends.owner", on(CANARY), s("A"))]))
        .await
        .expect_err("absent backend");
    let UiRefused::BadParam(field, reason) = error else {
        panic!("expected BadParam: {error:?}");
    };
    assert_eq!(field, id("backends.owner"));
    assert!(!reason.contains(CANARY), "{reason}");
}
