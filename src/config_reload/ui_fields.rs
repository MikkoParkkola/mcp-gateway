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
#[cfg_attr(
    all(test, not(feature = "cost-governance")),
    expect(
        dead_code,
        reason = "the integer, number and free-text fields are all cost governance fields"
    )
)]
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

#[cfg(feature = "cost-governance")]
const ALERT_ACTIONS: &[&str] = &["log", "notify", "block"];

/// `PolicyAction`'s serde names (lowercase).
const POLICY_ACTIONS: &[&str] = &["allow", "deny"];

/// `CollusionAction`'s serde names (snake case).
#[cfg(feature = "firewall")]
const COLLUSION_ACTIONS: &[&str] = &["off", "observe", "block"];

/// Every setting the UI may change, in the order an edit applies them.
/// `apply` is what a reload does with a change to that field alone (row F3
/// checks it against the reload's classifier): turning cost governance on
/// or off needs a restart; its budgets and alerts apply on reload while it
/// stays on.
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
        apply: Apply::Restart,
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
    // The Policies screen's scalar settings (ADR-029). Each applies on reload:
    // the restart comparison masks them (`diff.rs`, `security_restart_only_json`).
    // Relay detection's action is live only while the detector runs as asked;
    // otherwise the reload itself reports `security` pending.
    FieldSpec {
        id: "security.tool_policy.enabled",
        path: &[
            Seg::Key("security"),
            Seg::Key("tool_policy"),
            Seg::Key("enabled"),
        ],
        kind: Some(ValueKind::Bool),
        apply: Apply::Live,
    },
    FieldSpec {
        id: "security.tool_policy.default_action",
        path: &[
            Seg::Key("security"),
            Seg::Key("tool_policy"),
            Seg::Key("default_action"),
        ],
        kind: Some(ValueKind::Enum(POLICY_ACTIONS)),
        apply: Apply::Live,
    },
    FieldSpec {
        id: "security.tool_policy.use_default_deny",
        path: &[
            Seg::Key("security"),
            Seg::Key("tool_policy"),
            Seg::Key("use_default_deny"),
        ],
        kind: Some(ValueKind::Bool),
        apply: Apply::Live,
    },
    #[cfg(feature = "firewall")]
    FieldSpec {
        id: "security.firewall.credential_redaction",
        path: &[
            Seg::Key("security"),
            Seg::Key("firewall"),
            Seg::Key("credential_redaction"),
        ],
        kind: Some(ValueKind::Bool),
        apply: Apply::Live,
    },
    #[cfg(feature = "firewall")]
    FieldSpec {
        id: "security.firewall.collusion.action",
        path: &[
            Seg::Key("security"),
            Seg::Key("firewall"),
            Seg::Key("collusion"),
            Seg::Key("action"),
        ],
        kind: Some(ValueKind::Enum(COLLUSION_ACTIONS)),
        apply: Apply::Live,
    },
    FieldSpec {
        id: "security.sanitize_input",
        path: &[Seg::Key("security"), Seg::Key("sanitize_input")],
        kind: Some(ValueKind::Bool),
        apply: Apply::Live,
    },
    FieldSpec {
        id: "security.ssrf_protection",
        path: &[Seg::Key("security"), Seg::Key("ssrf_protection")],
        kind: Some(ValueKind::Bool),
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
    let mut out = Vec::with_capacity(edit.fields.len());
    for (n, (id, param, value)) in edit.fields.iter().enumerate() {
        let spec = id.spec();
        let bad_param = |why: &str| EditRefused::BadParam(*id, why.to_owned());
        let takes = |seg: Seg| spec.path.contains(&seg);
        match (takes(Seg::Backend), param.backend.is_some()) {
            (true, false) => return Err(bad_param("needs a backend")),
            (false, true) => return Err(bad_param("takes no backend")),
            _ => {}
        }
        match (takes(Seg::Index), param.index.is_some()) {
            (true, false) => return Err(bad_param("needs an index")),
            (false, true) => return Err(bad_param("takes no index")),
            _ => {}
        }
        if edit.fields[..n]
            .iter()
            .any(|(other, p, _)| other == id && p == param)
        {
            return Err(bad_param("named twice"));
        }
        let value = match (value, spec.kind) {
            (PreviewValue::Secret | PreviewValue::Remove, None) => value.clone(),
            (PreviewValue::Set(_), None) | (PreviewValue::Secret, Some(_)) => {
                return Err(EditRefused::WrongKind(*id));
            }
            // A list element's fields are all required (an alert has two).
            (PreviewValue::Remove, Some(_)) if takes(Seg::Index) => {
                return Err(bad_param("a required alert field"));
            }
            (PreviewValue::Remove, Some(_)) => PreviewValue::Remove,
            (PreviewValue::Set(scalar), Some(kind)) => {
                let scalar =
                    of_kind(scalar, kind).map_err(|why| EditRefused::BadValue(*id, why))?;
                // The owner as `BackendConfig::owner()` reads it: an empty
                // trimmed value is no owner.
                match &scalar {
                    Scalar::Str(s) if spec.id == "backends.owner" && s.trim().is_empty() => {
                        PreviewValue::Remove
                    }
                    _ => PreviewValue::Set(scalar),
                }
            }
        };
        out.push((*id, param.clone(), value));
    }
    // Table order, then index: the order an edit applies in and a patch
    // lists its steps in, whatever order the caller sent.
    out.sort_by_key(|(id, param, _)| (id.0, param.index));
    Ok(PreviewEdit { fields: out })
}

/// `scalar` when `kind` holds it (an integer is accepted as a number), or
/// why not.
fn of_kind(scalar: &Scalar, kind: ValueKind) -> Result<Scalar, String> {
    match (kind, scalar) {
        (ValueKind::Bool, Scalar::Bool(_)) => Ok(scalar.clone()),
        (ValueKind::Bool, _) => Err("expected a boolean".to_owned()),
        (ValueKind::Int { min, max }, Scalar::Int(n)) => (min..=max)
            .contains(n)
            .then(|| scalar.clone())
            .ok_or_else(|| "out of range".to_owned()),
        (ValueKind::Int { .. }, _) => Err("expected an integer".to_owned()),
        (ValueKind::Num { min }, Scalar::Num(n)) => (n.get() >= min)
            .then(|| scalar.clone())
            .ok_or_else(|| format!("below {min}")),
        (ValueKind::Num { min }, Scalar::Int(n)) => {
            #[expect(clippy::cast_precision_loss, reason = "an amount, not an id")]
            let as_float = *n as f64;
            match crate::config_persistence::keyedit::FiniteF64::new(as_float) {
                Some(f) if as_float >= min => Ok(Scalar::Num(f)),
                _ => Err(format!("below {min}")),
            }
        }
        (ValueKind::Num { .. }, _) => Err("expected a number".to_owned()),
        (ValueKind::Str { max_chars }, Scalar::Str(s)) => {
            if s.chars().any(char::is_control) {
                Err("a control character".to_owned())
            } else if let Some(max) = max_chars
                && s.trim().chars().count() > max
            {
                Err(format!("over {max} characters"))
            } else {
                Ok(scalar.clone())
            }
        }
        (ValueKind::Enum(words), Scalar::Str(s)) => words
            .contains(&s.as_str())
            .then(|| scalar.clone())
            .ok_or_else(|| format!("not one of {}", words.join(", "))),
        (ValueKind::Str { .. } | ValueKind::Enum(_), _) => Err("expected a string".to_owned()),
    }
}

#[cfg(test)]
#[path = "ui_fields_tests.rs"]
mod tests;
