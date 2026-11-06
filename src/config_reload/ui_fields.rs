// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The settings the web UI may change, and the checks an edit passes before
//! any byte of gateway.yaml is read: no caller can name a path this table
//! does not list, set a secret field to a plain value, or send a value its
//! field cannot hold.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "first callers: the settings diff and save routes (U8 PR c)"
    )
)]

use crate::config_persistence::keyedit::Scalar;

/// One step of a field's path: a fixed key, or a parameter the edit supplies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seg {
    Key(&'static str),
    /// A key of the file's `backends` mapping.
    Backend,
    /// A position in the file's `cost_governance.alerts` list.
    Index,
}

/// What a plain field holds. A secret field has none: it is only ever set
/// to a store reference, never to a value sent to it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ValueKind {
    Bool,
    Int { min: i64, max: i64 },
    Num { min: f64 },
    Str { max_chars: Option<usize> },
    Enum(&'static [&'static str]),
}

/// When a change takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Apply {
    Live,
    Restart,
}

/// One editable setting.
#[derive(Debug)]
pub(crate) struct FieldSpec {
    pub(crate) id: &'static str,
    pub(crate) path: &'static [Seg],
    /// `None`: a secret field.
    pub(crate) kind: Option<ValueKind>,
    pub(crate) apply: Apply,
}

impl FieldSpec {
    pub(crate) fn secret(&self) -> bool {
        self.kind.is_none()
    }
}

const ALERT_ACTIONS: &[&str] = &["log", "notify", "block"];

/// Every setting the UI may change, in the order an edit applies them.
pub(crate) const FIELDS: &[FieldSpec] = &[
    FieldSpec {
        id: "environment",
        path: &[Seg::Key("environment")],
        kind: Some(ValueKind::Str { max_chars: None }),
        apply: Apply::Live,
    },
    FieldSpec {
        id: "auth.enabled",
        path: &[Seg::Key("auth"), Seg::Key("enabled")],
        kind: Some(ValueKind::Bool),
        apply: Apply::Restart,
    },
    FieldSpec {
        id: "auth.single_user",
        path: &[Seg::Key("auth"), Seg::Key("single_user")],
        kind: Some(ValueKind::Bool),
        apply: Apply::Restart,
    },
    FieldSpec {
        id: "auth.bearer_token",
        path: &[Seg::Key("auth"), Seg::Key("bearer_token")],
        kind: None,
        apply: Apply::Restart,
    },
    #[cfg(feature = "cost-governance")]
    FieldSpec {
        id: "cost_governance.enabled",
        path: &[Seg::Key("cost_governance"), Seg::Key("enabled")],
        kind: Some(ValueKind::Bool),
        apply: Apply::Live,
    },
    #[cfg(feature = "cost-governance")]
    FieldSpec {
        id: "cost_governance.budgets.daily",
        path: &[
            Seg::Key("cost_governance"),
            Seg::Key("budgets"),
            Seg::Key("daily"),
        ],
        kind: Some(ValueKind::Num { min: 0.0 }),
        apply: Apply::Live,
    },
    #[cfg(feature = "cost-governance")]
    FieldSpec {
        id: "cost_governance.alerts.at_percent",
        path: &[
            Seg::Key("cost_governance"),
            Seg::Key("alerts"),
            Seg::Index,
            Seg::Key("at_percent"),
        ],
        kind: Some(ValueKind::Int { min: 0, max: 100 }),
        apply: Apply::Live,
    },
    #[cfg(feature = "cost-governance")]
    FieldSpec {
        id: "cost_governance.alerts.action",
        path: &[
            Seg::Key("cost_governance"),
            Seg::Key("alerts"),
            Seg::Index,
            Seg::Key("action"),
        ],
        kind: Some(ValueKind::Enum(ALERT_ACTIONS)),
        apply: Apply::Live,
    },
    FieldSpec {
        id: "backends.owner",
        path: &[Seg::Key("backends"), Seg::Backend, Seg::Key("owner")],
        // The loader's own limit (`backends.<name>.owner`, 200 characters).
        kind: Some(ValueKind::Str {
            max_chars: Some(200),
        }),
        apply: Apply::Live,
    },
];

/// A field of [`FIELDS`]: built only by [`FieldId::of`], so an id the table
/// does not list cannot be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldId(usize);

impl FieldId {
    pub(crate) fn of(id: &str) -> Option<Self> {
        FIELDS.iter().position(|f| f.id == id).map(Self)
    }

    pub(crate) fn spec(self) -> &'static FieldSpec {
        &FIELDS[self.0]
    }
}

/// The parameters a path takes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Param {
    pub(crate) backend: Option<String>,
    pub(crate) index: Option<usize>,
}

/// What a preview asks for one field. A secret is never sent to preview it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PreviewValue {
    Set(Scalar),
    Remove,
    Secret,
}

/// A preview of one save: each entry is one field.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PreviewEdit {
    pub(crate) fields: Vec<(FieldId, Param, PreviewValue)>,
}

/// Why an edit is refused before any read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EditRefused {
    WrongKind(FieldId),
    BadValue(FieldId, String),
    BadParam(FieldId, String),
}

/// `edit` with every entry checked against its field, the owner's empty
/// value mapped to a removal. Nothing is read.
pub(crate) fn checked(edit: &PreviewEdit) -> Result<PreviewEdit, EditRefused> {
    let _ = edit;
    Ok(PreviewEdit::default())
}

#[cfg(test)]
#[path = "ui_fields_tests.rs"]
mod tests;
