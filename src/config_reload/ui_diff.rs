// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The settings preview: the change a UI edit would make to gateway.yaml,
//! as a zero-context unified diff that never shows a byte of the file
//! outside the edited nodes, or, when the edit cannot be proven in place,
//! the change as steps to apply by hand. It writes nothing.
//!
//! It reads the file as the writer does (the trusted target, the guarded
//! read), refuses while a crashed write awaits recovery, and takes no lock:
//! the save rechecks the revision under the writer's lock.
#![cfg_attr(
    not(any(test, feature = "webui")),
    expect(dead_code, reason = "settings routes require webui")
)]

use std::fmt::Write as _;

use crate::config::UnreadConfig;
use crate::config_persistence::keyedit::{
    self, Change, ComputeRefusal, FieldPath, GiveUp, Segment,
};
use crate::config_reload::ReloadContext;
use crate::config_reload::ui_fields::{EditRefused, FieldId, PreviewEdit, PreviewValue, Seg};
use crate::yaml::Value;

use super::{FileRevision, RefusalClass, ReplaceError};

/// A preview of one edit.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct UiPreview {
    /// The revision of the bytes previewed; the save must match it.
    pub(crate) revision: FileRevision,
    pub(crate) shown: Shown,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Shown {
    Diff(UnifiedDiff),
    Patch(Patch),
}

/// The changed lines of gateway.yaml, secrets masked, no context lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UnifiedDiff {
    pub(crate) hunks: Vec<ShownHunk>,
}

/// One hunk as shown: 1-based starts and the lines without endings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShownHunk {
    pub(crate) old_start: usize,
    pub(crate) old: Vec<String>,
    pub(crate) new_start: usize,
    pub(crate) new: Vec<String>,
}

impl UnifiedDiff {
    /// The diff as text: the two file headers, then each hunk.
    pub(crate) fn render(&self) -> String {
        let mut out = String::from("--- a/gateway.yaml\n+++ b/gateway.yaml\n");
        for hunk in &self.hunks {
            // Writing to a String cannot fail.
            let _ = writeln!(
                out,
                "@@ -{},{} +{},{} @@",
                hunk.old_start,
                hunk.old.len(),
                hunk.new_start,
                hunk.new.len()
            );
            for line in &hunk.old {
                out.push('-');
                out.push_str(line);
                out.push('\n');
            }
            for line in &hunk.new {
                out.push('+');
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }
}

/// An edit to apply by hand, one step per field, when it cannot be made in
/// place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Patch {
    pub(crate) code: GiveUp,
    pub(crate) reason: String,
    pub(crate) line: Option<usize>,
    pub(crate) steps: Vec<PatchStep>,
}

/// One step of a patch. Invariant: a `SetSecret` step, and every step of a
/// patch given because the diff could not be masked, carries no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PatchStep {
    /// `value` is `None` when withheld.
    Set {
        path: Vec<Segment>,
        value: Option<String>,
    },
    Remove {
        path: Vec<Segment>,
    },
    /// "Save this secret alone in Settings after fixing the line."
    SetSecret {
        path: Vec<Segment>,
    },
}

/// A step's path as the operator types it: keys joined by `.`, a position
/// as `[n]`, a key that is not plain double-quoted.
pub(crate) fn path_text(path: &[Segment]) -> String {
    let mut out = String::new();
    for segment in path {
        match segment {
            Segment::Key(key) => {
                if !out.is_empty() {
                    out.push('.');
                }
                let plain = !key.is_empty()
                    && !key.starts_with('-')
                    && key
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
                if plain {
                    out.push_str(key);
                } else {
                    out.push_str(&crate::yaml::double_quoted(key));
                }
            }
            Segment::Index(at) => {
                out.push('[');
                out.push_str(&at.to_string());
                out.push(']');
            }
        }
    }
    out
}

/// Why the file was not previewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PreviewRefused {
    /// A crashed write awaits recovery; the next writer recovers it.
    Recovering,
    /// There is no gateway.yaml: a save could not apply to it.
    NoConfigFile,
    /// The path no longer resolves to the file this gateway started on.
    Untrusted(String),
    /// The guarded read refused or failed.
    Unread(String),
}

/// Why `ui_diff` gave no preview, or `ui_save` wrote nothing.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum UiRefused {
    WrongKind(FieldId),
    BadValue(FieldId, String),
    BadParam(FieldId, String),
    Preview(PreviewRefused),
    /// The loader or the reload would refuse the result.
    Invalid(String),
    ReloadRefused {
        class: RefusalClass,
    },
    Unsupported(String),
    /// Save: auth is on and no audit log is configured, or the audit log
    /// refused this save's intent; nothing was written either way.
    NoAuditLog,
    /// Save: the edit cannot be proven in place; the change as steps.
    Unprovable(Patch),
    /// Save: the file changed since the preview; the preview of it now.
    Stale(Box<UiPreview>),
    /// Save: the file changed, and its fresh preview refused.
    StaleUnpreviewable(String),
    /// Save: another write held the config past the wait.
    Busy,
    /// Save: the secret store refused; no file was written. A timed-out
    /// create may still land an entry, listed as unused.
    SecretsRefused {
        timeout: bool,
    },
    /// Save: the write did not complete; fixed text, the detail is logged.
    Failed(String),
}

impl From<EditRefused> for UiRefused {
    fn from(refused: EditRefused) -> Self {
        match refused {
            EditRefused::WrongKind(id) => Self::WrongKind(id),
            EditRefused::BadValue(id, why) => Self::BadValue(id, why),
            EditRefused::BadParam(id, why) => Self::BadParam(id, why),
        }
    }
}

/// The preview of `edit` against gateway.yaml as it is now.
pub(crate) async fn ui_diff(
    ctx: &ReloadContext,
    edit: &PreviewEdit,
) -> Result<UiPreview, UiRefused> {
    let edit = crate::config_reload::ui_fields::checked(edit)?;
    let (target, text) = read(ctx)?;
    let revision = FileRevision::of(text.as_bytes());
    let changes = changes_for(&edit, &text)?;
    let secrets: Vec<FieldPath> = edit
        .fields
        .iter()
        .zip(&changes)
        .filter(|((id, ..), _)| id.spec().secret())
        .map(|(_, (path, _))| path.clone())
        .collect();
    let shown = match keyedit::edit_in_place(&text, &changes) {
        Ok(template) => {
            validate(ctx, &target, &template).await?;
            match show::diff(&text, &changes, &secrets, template.hunks()) {
                Ok(diff) => Shown::Diff(diff),
                Err(code) => Shown::Patch(patch(
                    &changes,
                    code,
                    "the change cannot be shown masked",
                    true,
                )),
            }
        }
        Err(ComputeRefusal::Unprovable { code, reason }) => {
            let expected = keyedit::expected_text(&text, &changes).ok_or_else(|| {
                UiRefused::Unsupported("the edit cannot be followed in gateway.yaml".to_owned())
            })?;
            let slots: Vec<_> = changes
                .iter()
                .filter_map(|(_, change)| match change {
                    Change::Secret(id) => Some(id.clone()),
                    _ => None,
                })
                .collect();
            let template = keyedit::Template::from_placeholders(expected.into_bytes(), &slots)
                .map_err(|_| {
                    UiRefused::Unsupported(
                        "the edit's secret slots could not be checked".to_owned(),
                    )
                })?;
            validate(ctx, &target, &template).await?;
            Shown::Patch(patch(&changes, code, &reason, false))
        }
        Err(ComputeRefusal::SlotMismatch) => {
            return Err(UiRefused::Unsupported(
                "the edit's secret slots do not match".to_owned(),
            ));
        }
    };
    Ok(UiPreview { revision, shown })
}

/// The editor's changes for a checked `edit` on `text`, the bytes being
/// edited (an empty file is the empty root). The save computes on the
/// locked bytes through this, so preview and save resolve alike.
pub(super) fn changes_for(
    edit: &PreviewEdit,
    text: &str,
) -> Result<Vec<(FieldPath, Change)>, UiRefused> {
    let doc = match crate::yaml::from_str::<Value>(text) {
        Ok(Value::Null) => Value::Mapping(crate::yaml::Mapping::new()),
        Ok(doc) => doc,
        Err(e) => {
            return Err(UiRefused::Invalid(format!(
                "gateway.yaml does not parse: {e}"
            )));
        }
    };
    resolve(edit, &doc)
}

/// Each entry as the editor's change at its path, the path's parameters
/// resolved against `doc`, the bytes read (never the loaded config): a
/// backend must be in the file; an alert index must be in the file's list,
/// or the edit's new indices must run on from its end with every field of
/// each new element set.
fn resolve(edit: &PreviewEdit, doc: &Value) -> Result<Vec<(FieldPath, Change)>, UiRefused> {
    let alerts = doc
        .get("cost_governance")
        .and_then(|c| c.get("alerts"))
        .and_then(Value::as_sequence)
        .map_or(0, Vec::len);
    let element_fields: Vec<FieldId> = crate::config_reload::ui_fields::FIELDS
        .iter()
        .filter(|spec| spec.path.contains(&Seg::Index))
        .filter_map(|spec| FieldId::of(spec.id))
        .collect();
    // Each new index, with the first entry that names it.
    let mut new: std::collections::BTreeMap<usize, FieldId> = std::collections::BTreeMap::new();
    let mut out = Vec::with_capacity(edit.fields.len());
    for (id, param, value) in &edit.fields {
        let bad = |why: String| UiRefused::BadParam(*id, why);
        let mut path = Vec::new();
        for seg in id.spec().path {
            path.push(match seg {
                Seg::Key(k) => Segment::Key((*k).to_owned()),
                Seg::Backend => {
                    let name = param.backend.clone().unwrap_or_default();
                    let known = doc
                        .get("backends")
                        .and_then(Value::as_mapping)
                        .is_some_and(|m| m.get(Value::from(name.as_str())).is_some());
                    if !known {
                        return Err(bad(format!("no such backend for {}", id.spec().id)));
                    }
                    Segment::Key(name)
                }
                Seg::Index => {
                    let at = param.index.unwrap_or_default();
                    if at >= alerts {
                        new.entry(at).or_insert(*id);
                    }
                    Segment::Index(at)
                }
            });
        }
        let path = FieldPath(path);
        let change = match value {
            PreviewValue::Set(scalar) => Change::Set(scalar.clone()),
            PreviewValue::Remove => Change::Remove,
            PreviewValue::Secret => Change::Secret(path.slot()),
        };
        out.push((path, change));
    }
    // New elements run on from the end, each complete.
    for (n, (at, id)) in new.iter().enumerate() {
        let complete = element_fields.iter().all(|field| {
            edit.fields.iter().any(|(id, p, v)| {
                id == field && p.index == Some(*at) && matches!(v, PreviewValue::Set(_))
            })
        });
        if *at != alerts + n || !complete {
            return Err(UiRefused::BadParam(
                *id,
                format!("index out of range for {}", id.spec().id),
            ));
        }
    }
    Ok(out)
}

/// The patch for `changes`: one step per change, in order. `withhold`
/// leaves every value out (a diff that could not be masked).
fn patch(changes: &[(FieldPath, Change)], code: GiveUp, reason: &str, withhold: bool) -> Patch {
    let steps = changes
        .iter()
        .map(|(path, change)| {
            let path = path.0.clone();
            match change {
                Change::Remove => PatchStep::Remove { path },
                Change::Secret(_) => PatchStep::SetSecret { path },
                other => PatchStep::Set {
                    path,
                    value: if withhold {
                        None
                    } else {
                        keyedit::value_text(other)
                    },
                },
            }
        })
        .collect();
    Patch {
        code,
        reason: reason.to_owned(),
        line: None,
        steps,
    }
}

/// The trusted target and its text, read as the writer reads it, with no
/// lock and no recovery.
fn read(ctx: &ReloadContext) -> Result<(std::path::PathBuf, String), UiRefused> {
    if crate::config_persistence::lock::journal_pending(&ctx.config_path) {
        return Err(UiRefused::Preview(PreviewRefused::Recovering));
    }
    let target = crate::identity_grants::journal::resolved(&ctx.config_path);
    if target != ctx.trusted_config {
        return Err(UiRefused::Preview(PreviewRefused::Untrusted(format!(
            "{} now resolves to {}, not to {}, the file this gateway started on",
            ctx.config_path.display(),
            target.display(),
            ctx.trusted_config.display()
        ))));
    }
    match crate::config::read_config_text(&target) {
        Ok(Some(text)) => Ok((target, text)),
        Ok(None) => Err(UiRefused::Preview(PreviewRefused::NoConfigFile)),
        Err(
            UnreadConfig::Refused(why)
            | UnreadConfig::Failed(why)
            | UnreadConfig::NotTheConfig(why),
        ) => Err(UiRefused::Preview(PreviewRefused::Unread(why))),
    }
}

/// The writer's own check before any write, on stand-ins for the slots.
async fn validate(
    ctx: &ReloadContext,
    target: &std::path::Path,
    template: &keyedit::Template,
) -> Result<(), UiRefused> {
    ctx.validate_template(target, template, None)
        .await
        .map_err(|error| validate_refusal(&error))
}

/// The answer to a change the config loader would refuse: fixed text, since
/// the loader's own message can quote what the file holds.
pub(super) const LOADER_REFUSED: &str = "the change would be refused by the config loader";

pub(super) fn validate_refusal(e: &ReplaceError) -> UiRefused {
    match e {
        ReplaceError::ReloadRefused { class, .. } => UiRefused::ReloadRefused { class: *class },
        ReplaceError::Refused(_) => UiRefused::Invalid(LOADER_REFUSED.to_owned()),
        ReplaceError::Unsupported(_) => {
            UiRefused::Unsupported("this change is not supported here".to_owned())
        }
        ReplaceError::Failed(_)
        | ReplaceError::Busy
        | ReplaceError::Stale { .. }
        | ReplaceError::NoAuditLog
        | ReplaceError::AuditRefused(_)
        | ReplaceError::Stage(_)
        | ReplaceError::Write(_)
        | ReplaceError::RollbackFailed { .. }
        | ReplaceError::Unconfirmed { .. }
        | ReplaceError::Secrets(_)
        | ReplaceError::NoConfigFile
        | ReplaceError::ConfigRefused(_) => {
            UiRefused::Failed("the preview did not complete".to_owned())
        }
    }
}

#[path = "ui_diff_show.rs"]
mod show;

#[cfg(test)]
#[path = "ui_diff_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ui_diff_refusal_tests.rs"]
mod refusal_tests;
