// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Policies screen's scalar settings in the field table (ADR-029): each
//! previews and saves in place, applies on reload, and refuses a value its
//! enum does not hold.

use std::sync::Arc;

use super::{SaveEdit, SaveValue, ui_save};
use crate::config_persistence::keyedit::Scalar;
use crate::config_reload::ReloadContext;
use crate::config_reload::reload_context::replace::ui_diff::{Shown, UiRefused, ui_diff};
use crate::config_reload::reload_context::replace::{
    AuditPosture, FileRevision, GatewayAuth, RefusalClass,
};
use crate::config_reload::replace_test_support::{WAIT, context, read};
use crate::config_reload::ui_fields::{FieldId, Param, PreviewEdit, PreviewValue};
use crate::gateway::test_helpers::write_owner_only;

/// Every scalar policy row with a non-default value, in the shape the
/// screen sends it.
fn rows() -> Vec<(&'static str, Scalar, &'static str)> {
    let mut rows = vec![
        (
            "security.tool_policy.enabled",
            Scalar::Bool(false),
            "enabled: false",
        ),
        (
            "security.tool_policy.default_action",
            Scalar::Str("deny".into()),
            "default_action: \"deny\"",
        ),
        (
            "security.tool_policy.use_default_deny",
            Scalar::Bool(false),
            "use_default_deny: false",
        ),
        (
            "security.sanitize_input",
            Scalar::Bool(false),
            "sanitize_input: false",
        ),
        (
            "security.ssrf_protection",
            Scalar::Bool(false),
            "ssrf_protection: false",
        ),
    ];
    if cfg!(feature = "firewall") {
        rows.push((
            "security.firewall.credential_redaction",
            Scalar::Bool(false),
            "credential_redaction: false",
        ));
        rows.push((
            "security.firewall.collusion.action",
            Scalar::Str("block".into()),
            "action: \"block\"",
        ));
    }
    rows
}

const COMMENTED: &str = "# operator's note\nenvironment: \"dev\" # where\n";

/// A relay action other than `off` needs the firewall on: the loader refuses
/// it otherwise (`collusion_gate.rs`, `validate`).
const FIREWALL_ON: &str = "# operator's note\nsecurity:\n  firewall:\n    enabled: true # on\n";

/// The commented file a row is edited on.
fn base_for(name: &str) -> &'static str {
    if name == "security.firewall.collusion.action" {
        FIREWALL_ON
    } else {
        COMMENTED
    }
}

fn gateway(text: &str) -> (tempfile::TempDir, std::path::PathBuf, Arc<ReloadContext>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, text).expect("write");
    let ctx = context(&path);
    (dir, path, ctx)
}

fn id(name: &str) -> FieldId {
    FieldId::of(name).unwrap_or_else(|| panic!("{name} is in FIELDS"))
}

fn preview_edit(name: &str, value: Scalar) -> PreviewEdit {
    PreviewEdit {
        fields: vec![(id(name), Param::default(), PreviewValue::Set(value))],
    }
}

async fn save(
    ctx: &Arc<ReloadContext>,
    path: &std::path::Path,
    name: &str,
    value: Scalar,
) -> Result<super::UiSaved, UiRefused> {
    ui_save(
        Arc::clone(ctx),
        AuditPosture::of(None, GatewayAuth::Off),
        FileRevision::of(read(path).as_bytes()),
        SaveEdit {
            fields: vec![(id(name), Param::default(), SaveValue::Set(value))],
        },
        None,
        WAIT,
    )
    .await
}

/// P1/P2: on a commented file with no `security:` section, each row
/// previews as an insertion of its key alone; the comments stay.
#[tokio::test]
async fn each_policy_row_previews_in_place_on_a_commented_file() {
    for (name, value, line) in rows() {
        let (_dir, _path, ctx) = gateway(base_for(name));
        let preview = ui_diff(&ctx, &preview_edit(name, value))
            .await
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let Shown::Diff(diff) = &preview.shown else {
            panic!("{name}: a diff, got the patch");
        };
        let text = diff.render();
        assert!(text.contains(line), "{name}: {text}");
        assert!(!text.contains("-# operator's note"), "{name}: {text}");
        assert!(!text.contains("-environment"), "{name}: {text}");
    }
}

/// P3: a value outside the enum is refused before any read.
#[tokio::test]
async fn a_value_outside_a_policy_enum_is_refused() {
    let (_dir, path, ctx) = gateway(COMMENTED);
    let mut cases = vec![("security.tool_policy.default_action", "maybe")];
    if cfg!(feature = "firewall") {
        cases.push(("security.firewall.collusion.action", "warn"));
    }
    for (name, bad) in cases {
        let refused = ui_diff(&ctx, &preview_edit(name, Scalar::Str(bad.into())))
            .await
            .expect_err(name);
        assert!(
            matches!(refused, UiRefused::BadValue(..)),
            "{name}: {refused:?}"
        );
    }
    assert_eq!(read(&path), COMMENTED);
}

/// P7: every serde member saves as written; the expected members are
/// listed here, not read from the table.
#[tokio::test]
async fn every_policy_enum_member_saves_as_written() {
    let mut cases = vec![("security.tool_policy.default_action", vec!["allow", "deny"])];
    if cfg!(feature = "firewall") {
        cases.push((
            "security.firewall.collusion.action",
            vec!["off", "observe", "block"],
        ));
    }
    for (name, members) in cases {
        for member in members {
            let base = base_for(name);
            let (_dir, path, ctx) = gateway(base);
            save(&ctx, &path, name, Scalar::Str(member.into()))
                .await
                .unwrap_or_else(|e| panic!("{name}={member}: {e:?}"));
            let text = read(&path);
            assert!(
                text.contains(&format!("\"{member}\"")),
                "{name}={member}: {text}"
            );
            assert!(
                text.starts_with("# operator's note\n"),
                "{name}={member}: {text}"
            );
        }
    }
}

/// P4: a tool-policy default and the input switch apply on reload: the
/// published config changes and nothing is restart-pending.
#[tokio::test]
async fn a_saved_policy_switch_applies_on_reload() {
    let (_dir, path, ctx) = gateway(COMMENTED);
    let saved = save(
        &ctx,
        &path,
        "security.tool_policy.default_action",
        Scalar::Str("deny".into()),
    )
    .await
    .expect("saves");
    assert!(!saved.reload.restart_required, "{:?}", saved.reload);
    assert_eq!(
        ctx.live_config.get().security.tool_policy.default_action,
        crate::security::policy::PolicyAction::Deny
    );
    let saved = save(&ctx, &path, "security.sanitize_input", Scalar::Bool(false))
        .await
        .expect("saves");
    assert!(!saved.reload.restart_required, "{:?}", saved.reload);
    assert!(!ctx.live_config.get().security.sanitize_input);
}

/// P5/P5b: relay detection's action needs the firewall on (else the save is
/// refused), and applies on reload only while the detector runs as asked;
/// otherwise the reload itself reports `security` pending (ADR-029, amended).
#[cfg(feature = "firewall")]
#[tokio::test]
async fn relay_action_needs_the_firewall_and_is_live_only_with_the_running_detector() {
    let block = || Scalar::Str("block".into());
    let pending = |saved: &super::UiSaved| {
        saved
            .reload
            .pending_restart_fields
            .iter()
            .any(|f| f == "security" || f.starts_with("security."))
    };
    // Firewall off (it is on by default, so said explicitly): the loader
    // refuses a relay action other than `off`, so the save is refused and the
    // file is unchanged.
    let off = "# operator's note\nsecurity:\n  firewall:\n    enabled: false # off\n";
    let (_dir, path, ctx) = gateway(off);
    let refused = save(&ctx, &path, "security.firewall.collusion.action", block())
        .await
        .expect_err("needs security.firewall.enabled");
    // The loader's validation refusal, not some other failure.
    assert!(
        matches!(
            refused,
            UiRefused::ReloadRefused {
                class: RefusalClass::Invalid
            }
        ),
        "{refused:?}"
    );
    assert_eq!(read(&path), off);

    // Firewall on, detector unchanged: live.
    let on = "security:\n  firewall:\n    enabled: true\n";
    let (_dir, path, ctx) = gateway(on);
    let saved = save(&ctx, &path, "security.firewall.collusion.action", block())
        .await
        .expect("saves");
    assert!(!pending(&saved), "detector unchanged: {:?}", saved.reload);

    // Firewall on, a detector threshold changed by hand in the same file:
    // pending.
    let (_dir, path, ctx) = gateway(on);
    write_owner_only(
        &path,
        "security:\n  firewall:\n    enabled: true\n    collusion:\n      min_matches: 3\n",
    )
    .expect("hand edit");
    let saved = save(&ctx, &path, "security.firewall.collusion.action", block())
        .await
        .expect("saves");
    assert!(pending(&saved), "detector changed: {:?}", saved.reload);
}

/// P1b: every row also saves in place: the key lands with its value, the
/// operator's comment stays.
#[tokio::test]
async fn each_policy_row_saves_in_place_on_a_commented_file() {
    for (name, value, line) in rows() {
        let base = base_for(name);
        let (_dir, path, ctx) = gateway(base);
        let saved = save(&ctx, &path, name, value)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(saved.changed, "{name}: {saved:?}");
        let text = read(&path);
        assert!(text.contains(line), "{name}: {text}");
        assert!(text.starts_with("# operator's note\n"), "{name}: {text}");
    }
}
