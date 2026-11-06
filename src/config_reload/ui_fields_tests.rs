// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The field table and its early checks (rows F1-F5).

use super::{Apply, EditRefused, FIELDS, FieldId, Param, PreviewEdit, PreviewValue, checked};
use crate::config::Config;
#[cfg(feature = "cost-governance")]
use crate::config_persistence::keyedit::FiniteF64;
use crate::config_persistence::keyedit::Scalar;

fn id(name: &str) -> FieldId {
    FieldId::of(name).unwrap_or_else(|| panic!("{name} is in FIELDS"))
}

fn one(name: &str, param: Param, value: PreviewValue) -> PreviewEdit {
    PreviewEdit {
        fields: vec![(id(name), param, value)],
    }
}

fn backend(name: &str) -> Param {
    Param {
        backend: Some(name.to_owned()),
        index: None,
    }
}

#[cfg(feature = "cost-governance")]
fn index(at: usize) -> Param {
    Param {
        backend: None,
        index: Some(at),
    }
}

/// A minimal gateway.yaml holding `field` with a valid value (an alert with
/// both of its required fields, an owner under a real backend).
fn file_with(field: &str) -> String {
    match field {
        "environment" => "environment: \"staging\"\n".to_owned(),
        "auth.enabled" => "auth:\n  enabled: false\n".to_owned(),
        "auth.single_user" => "auth:\n  single_user: true\n".to_owned(),
        "auth.bearer_token" => "auth:\n  bearer_token: \"env:MCPGW_F1_TOKEN\"\n".to_owned(),
        "cost_governance.enabled" => "cost_governance:\n  enabled: true\n".to_owned(),
        "cost_governance.budgets.daily" => {
            "cost_governance:\n  budgets:\n    daily: 2.5\n".to_owned()
        }
        "cost_governance.alerts.at_percent" | "cost_governance.alerts.action" => {
            "cost_governance:\n  alerts:\n    - at_percent: 50\n      action: \"log\"\n".to_owned()
        }
        "backends.owner" => {
            "backends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    owner: \"Team A\"\n"
                .to_owned()
        }
        other => panic!("no fixture for {other}: add one with the field"),
    }
}

/// F1: every path the table lists is a key the loader accepts (strict keys
/// and validation), so a patch naming it loads once applied by hand.
#[test]
fn every_field_path_loads_under_the_strict_key_check() {
    for field in FIELDS {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        crate::gateway::test_helpers::write_owner_only(&path, &file_with(field.id)).expect("write");
        if let Err(e) = Config::load(Some(&path)) {
            panic!("{}: {e:#}", field.id);
        }
    }
}

/// F2: each refusal comes before any read: nothing here names a file.
#[test]
fn wrong_kind_bad_value_and_bad_param_are_refused_before_any_read() {
    let str_ = |s: &str| PreviewValue::Set(Scalar::Str(s.to_owned()));
    let none = Param::default;
    let cases: Vec<(PreviewEdit, EditRefused)> = vec![
        (
            one("auth.bearer_token", none(), str_("plain")),
            EditRefused::WrongKind(id("auth.bearer_token")),
        ),
        (
            one("environment", none(), PreviewValue::Secret),
            EditRefused::WrongKind(id("environment")),
        ),
        (
            one("auth.enabled", none(), str_("yes")),
            EditRefused::BadValue(id("auth.enabled"), "expected a boolean".into()),
        ),
        (
            one("environment", none(), str_("a\nb")),
            EditRefused::BadValue(id("environment"), "a control character".into()),
        ),
        (
            one("backends.owner", backend("svc"), str_(&"o".repeat(201))),
            EditRefused::BadValue(id("backends.owner"), "over 200 characters".into()),
        ),
        (
            one("environment", backend("svc"), str_("x")),
            EditRefused::BadParam(id("environment"), "takes no backend".into()),
        ),
        (
            one("backends.owner", none(), str_("x")),
            EditRefused::BadParam(id("backends.owner"), "needs a backend".into()),
        ),
        (
            PreviewEdit {
                fields: vec![
                    (id("environment"), none(), str_("a")),
                    (id("environment"), none(), str_("b")),
                ],
            },
            EditRefused::BadParam(id("environment"), "named twice".into()),
        ),
    ];
    #[cfg(feature = "cost-governance")]
    let cases = {
        let mut cases = cases;
        cases.extend([
            (
                one(
                    "cost_governance.alerts.at_percent",
                    index(0),
                    PreviewValue::Set(Scalar::Int(101)),
                ),
                EditRefused::BadValue(
                    id("cost_governance.alerts.at_percent"),
                    "out of range".into(),
                ),
            ),
            (
                one("cost_governance.alerts.action", index(0), str_("warn")),
                EditRefused::BadValue(
                    id("cost_governance.alerts.action"),
                    "not one of log, notify, block".into(),
                ),
            ),
            (
                one(
                    "cost_governance.budgets.daily",
                    none(),
                    PreviewValue::Set(Scalar::Num(FiniteF64::new(-1.0).expect("finite"))),
                ),
                EditRefused::BadValue(id("cost_governance.budgets.daily"), "below 0".into()),
            ),
            (
                one("cost_governance.alerts.action", none(), str_("log")),
                EditRefused::BadParam(id("cost_governance.alerts.action"), "needs an index".into()),
            ),
        ]);
        cases
    };
    for (edit, want) in cases {
        assert_eq!(checked(&edit), Err(want.clone()), "{edit:?}");
    }
}

/// F3: a field's `Apply` is what a reload does with a change to it alone.
#[test]
fn each_fields_apply_matches_the_reload_classifier() {
    // Both sides through the same extraction, so only the field differs.
    let base = Config::from_file_text("").expect("an empty file extracts");
    for field in FIELDS {
        // F1's `auth.enabled: false` is the default, so F3 turns it on.
        let text = match field.id {
            "auth.enabled" => "auth:\n  enabled: true\n".to_owned(),
            other => file_with(other),
        };
        let changed = Config::from_file_text(&text).expect("extracts");
        let pending = crate::config_reload::diff::pending_restart_fields(&base, &changed);
        assert_eq!(
            field.apply == Apply::Restart,
            !pending.is_empty(),
            "{}: the table says {:?}; the reload lists {pending:?}",
            field.id,
            field.apply
        );
    }
}

/// F4: an empty owner, once trimmed, removes the key.
#[test]
fn an_empty_owner_previews_as_a_removal() {
    let edit = one(
        "backends.owner",
        backend("svc"),
        PreviewValue::Set(Scalar::Str("   ".into())),
    );
    let got = checked(&edit).expect("accepted");
    assert_eq!(got.fields[0].2, PreviewValue::Remove);
}

/// F5: an alert's two fields are both required, so neither is removed.
#[cfg(feature = "cost-governance")]
#[test]
fn an_alert_field_cannot_be_removed() {
    for name in [
        "cost_governance.alerts.at_percent",
        "cost_governance.alerts.action",
    ] {
        assert_eq!(
            checked(&one(name, index(0), PreviewValue::Remove)),
            Err(EditRefused::BadParam(
                id(name),
                "a required alert field".into()
            )),
            "{name}"
        );
    }
}
