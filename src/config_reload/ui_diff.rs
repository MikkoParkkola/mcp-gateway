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
    not(test),
    expect(dead_code, reason = "first caller: the settings diff route (U8 PR c)")
)]

use crate::config_persistence::keyedit::{GiveUp, Segment};
use crate::config_reload::ReloadContext;
use crate::config_reload::ui_fields::{EditRefused, FieldId, PreviewEdit};

use super::FileRevision;

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
        String::new()
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
    let _ = path;
    String::new()
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

/// Why `ui_diff` gave no preview. The save adds its own variants (PR b2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UiRefused {
    WrongKind(FieldId),
    BadValue(FieldId, String),
    BadParam(FieldId, String),
    Preview(PreviewRefused),
    /// The loader or the reload would refuse the result.
    Invalid(String),
    Unsupported(String),
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
    let _ = (ctx, edit);
    Err(UiRefused::Unsupported("not built yet".to_owned()))
}

#[cfg(test)]
#[path = "ui_diff_tests.rs"]
mod tests;
