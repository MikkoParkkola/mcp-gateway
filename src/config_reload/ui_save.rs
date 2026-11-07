// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The settings save: one UI edit written to gateway.yaml through the
//! writer, all or nothing across the file and the secret store (ADR-024).
//!
//! It writes only through the refusing in-place editor, against the
//! revision the operator's preview was made from. A file changed since
//! answers with a fresh preview; an edit that cannot be proven in place
//! answers with the preview's patch. Either way nothing is written and no
//! secret entry exists.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "first caller: the settings save route (U8 PR c)")
)]

use std::sync::Arc;
use std::time::Duration;

use crate::config_persistence::keyedit::Scalar;
use crate::config_reload::ui_fields::{FieldId, Param};
use crate::config_reload::{ReloadContext, ReloadOutcome};
use crate::secret_store::{SecretStore, Vault};
use crate::wiped_bytes::WipedBytes;

use super::ui_diff::UiRefused;
use super::{AuditPosture, FileRevision};

/// What a save asks for one field. A secret carries its value here only.
pub(crate) enum SaveValue {
    Set(Scalar),
    Remove,
    Secret(WipedBytes),
}

/// One save: each entry is one field, as a preview names it.
#[derive(Default)]
pub(crate) struct SaveEdit {
    pub(crate) fields: Vec<(FieldId, Param, SaveValue)>,
}

/// Where a save's secrets go.
pub(crate) struct SecretTarget {
    pub(crate) vault: Vault,
    pub(crate) store: Arc<dyn SecretStore + Send + Sync>,
}

/// A save that was written and accepted.
#[derive(Debug)]
pub(crate) struct UiSaved {
    /// The file's revision now: the new bytes', or `base` when they were
    /// already the file's.
    pub(crate) revision: FileRevision,
    /// Whether the bytes changed.
    pub(crate) changed: bool,
    pub(crate) reload: ReloadOutcome,
}

/// Save `edit` over the file at revision `base`.
pub(crate) async fn ui_save(
    ctx: Arc<ReloadContext>,
    posture: AuditPosture,
    base: FileRevision,
    edit: SaveEdit,
    secrets: Option<SecretTarget>,
    wait: Duration,
) -> Result<UiSaved, UiRefused> {
    let _ = (ctx, posture, base, edit, secrets, wait);
    Err(UiRefused::Unsupported("not built".to_owned()))
}

/// The answer to a write that did not complete; the detail goes to the log.
const FAILED: &str =
    "the save did not complete; gateway.yaml may have changed, so preview it again before retrying";

/// Why the compute stopped, beyond the writer's refusal text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Halt {
    /// The in-place editor could not prove the edit.
    Unprovable,
    /// The template's secret slots did not match the edit's.
    SlotMismatch,
}

/// A writer result, as the save answers it.
#[derive(Debug, PartialEq)]
enum Mapped {
    Refusal(UiRefused),
    /// Answer with the preview of the file as it is now: it changed
    /// (`Stale`), or the edit was not provable (`Unprovable`).
    Repreview {
        stale: bool,
    },
}

/// The save's answer to the writer's refusal `error`, given why the compute
/// stopped, if it did.
fn map_error(error: super::ReplaceError, halt: Option<Halt>) -> Mapped {
    let _ = (error, halt);
    Mapped::Refusal(UiRefused::Unsupported("not built".to_owned()))
}

#[cfg(test)]
#[path = "ui_save_tests.rs"]
mod tests;
