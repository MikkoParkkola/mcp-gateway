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
    not(any(test, feature = "webui")),
    expect(dead_code, reason = "settings routes require webui")
)]

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::config_persistence::keyedit::{self, ComputeRefusal, Scalar, Segment, SlotId};
use crate::config_reload::ui_fields::{self, FieldId, Param, PreviewEdit, PreviewValue, Seg};
use crate::config_reload::{ReloadContext, ReloadOutcome};
use crate::secret_store::{NewSecretOwned, SaveError, SecretStore, StoreError, Vault};
use crate::wiped_bytes::WipedBytes;

use super::ui_diff::{LOADER_REFUSED, PreviewRefused, Shown, UiRefused, changes_for, ui_diff};
use super::{
    AuditPosture, Expected, FileRevision, IntentKind, Replace, ReplaceError, Replaced, SecretStep,
    replace_audited,
};

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
    // The preview's shape, the secret bytes held aside.
    let mut values = Vec::new();
    let fields = edit.fields.into_iter().map(|(id, param, value)| {
        let value = match value {
            SaveValue::Set(scalar) => PreviewValue::Set(scalar),
            SaveValue::Remove => PreviewValue::Remove,
            SaveValue::Secret(bytes) => {
                values.push(NewSecretOwned {
                    field: slot(id, &param).display(),
                    value: bytes,
                });
                PreviewValue::Secret
            }
        };
        (id, param, value)
    });
    let preview = PreviewEdit {
        fields: fields.collect(),
    };
    let checked = ui_fields::checked(&preview)?;
    let names = checked
        .fields
        .iter()
        .map(|(id, param, _)| slot(*id, param).display());
    let kind = IntentKind::Save {
        fields: names.collect(),
    };
    let audit = posture.audit(kind).map_err(|_| UiRefused::NoAuditLog)?;
    let secrets = match (secrets, values.is_empty()) {
        (_, true) => None,
        (Some(target), false) => Some(SecretStep {
            vault: target.vault,
            store: target.store,
            values,
        }),
        (None, false) => {
            return Err(UiRefused::Unsupported(
                "no secret store to save to".to_owned(),
            ));
        }
    };
    let stop = Arc::new(Mutex::new(None));
    let replace = Replace {
        expected: Expected::Revision(base.clone()),
        compute: compute(checked, Arc::clone(&stop)),
        replaced: Replaced::Discard,
        secrets,
    };
    let error = match replace_audited(Arc::clone(&ctx), replace, audit, wait).await {
        Ok(outcome) => {
            return Ok(UiSaved {
                changed: outcome.revision.is_some(),
                revision: outcome.revision.unwrap_or(base),
                reload: outcome.reload,
            });
        }
        Err(error) => error,
    };
    let halt = match stop.lock().take() {
        Some(Stop::Refused(refusal)) => return Err(refusal),
        Some(Stop::Halt(halt)) => Some(halt),
        None => None,
    };
    match map_error(error, halt) {
        Mapped::Refusal(refusal) => Err(refusal),
        Mapped::Repreview { stale } => match (ui_diff(&ctx, &preview).await, stale) {
            (Ok(fresh), true) => Err(UiRefused::Stale(Box::new(fresh))),
            (Ok(fresh), false) => match fresh.shown {
                Shown::Patch(patch) => Err(UiRefused::Unprovable(patch)),
                // Provable now: the file changed since the compute read it.
                Shown::Diff(_) => Err(UiRefused::Stale(Box::new(fresh))),
            },
            (Err(refusal), true) => Err(UiRefused::StaleUnpreviewable(format!("{refusal:?}"))),
            (Err(refusal), false) => Err(refusal),
        },
    }
}

/// Why the compute refused, kept for the answer: the writer only carries
/// its text.
enum Stop {
    Halt(Halt),
    Refused(UiRefused),
}

/// The new bytes from the locked ones: the edit resolved and applied in
/// place, never rendered. A refusal records why in `stop`.
fn compute(edit: PreviewEdit, stop: Arc<Mutex<Option<Stop>>>) -> super::Compute {
    Box::new(move |bytes: &[u8]| {
        let refuse = |why: Stop, text: &str| {
            *stop.lock() = Some(why);
            Err(text.to_owned())
        };
        let Ok(text) = std::str::from_utf8(bytes) else {
            let why = UiRefused::Invalid("gateway.yaml is not UTF-8 text".to_owned());
            return refuse(Stop::Refused(why), "not UTF-8");
        };
        let changes = match changes_for(&edit, text) {
            Ok(changes) => changes,
            Err(refusal) => return refuse(Stop::Refused(refusal), "the edit does not resolve"),
        };
        match keyedit::edit_in_place(text, &changes) {
            Ok(template) => Ok(template),
            Err(ComputeRefusal::Unprovable { .. }) => refuse(
                Stop::Halt(Halt::Unprovable),
                "the edit cannot be proven in place",
            ),
            Err(ComputeRefusal::SlotMismatch) => refuse(
                Stop::Halt(Halt::SlotMismatch),
                "the edit's secret slots do not match",
            ),
        }
    })
}

/// The slot of field `id` at `param`: its path, parameters filled.
fn slot(id: FieldId, param: &Param) -> SlotId {
    let segments = id.spec().path.iter().map(|seg| match seg {
        Seg::Key(key) => Segment::Key((*key).to_owned()),
        Seg::Backend => Segment::Key(param.backend.clone().unwrap_or_default()),
        Seg::Index => Segment::Index(param.index.unwrap_or_default()),
    });
    SlotId(segments.collect())
}

/// The fixed answer to a write that did not complete.
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
fn map_error(error: ReplaceError, halt: Option<Halt>) -> Mapped {
    let refusal = match error {
        ReplaceError::Stale { .. } => return Mapped::Repreview { stale: true },
        ReplaceError::Refused(_) if halt == Some(Halt::Unprovable) => {
            return Mapped::Repreview { stale: false };
        }
        ReplaceError::Refused(_) if halt == Some(Halt::SlotMismatch) => {
            UiRefused::Unsupported("the edit's secret slots do not match".to_owned())
        }
        ReplaceError::ReloadRefused { class, .. } => UiRefused::ReloadRefused { class },
        ReplaceError::Refused(_) => UiRefused::Invalid(LOADER_REFUSED.to_owned()),
        // No log under auth, or the log refused this save's intent: either
        // way the audit the save requires is not there, and nothing was
        // written (the adopt route answers both alike).
        ReplaceError::NoAuditLog | ReplaceError::AuditRefused(_) => UiRefused::NoAuditLog,
        ReplaceError::Busy => UiRefused::Busy,
        ReplaceError::Secrets(SaveError::Refused(e) | SaveError::Store(e)) => match e {
            StoreError::Failed(_) => UiRefused::Failed(FAILED.to_owned()),
            StoreError::TimedOut => UiRefused::SecretsRefused { timeout: true },
            StoreError::Exists
            | StoreError::Unavailable(_)
            | StoreError::Empty
            | StoreError::NotUtf8
            | StoreError::TooLarge { .. } => UiRefused::SecretsRefused { timeout: false },
        },
        ReplaceError::Secrets(SaveError::Commit(never)) => match never {},
        ReplaceError::NoConfigFile => UiRefused::Preview(PreviewRefused::NoConfigFile),
        ReplaceError::ConfigRefused(why) => UiRefused::Preview(PreviewRefused::Unread(why)),
        ReplaceError::Unsupported(why) => UiRefused::Preview(PreviewRefused::Untrusted(why)),
        ReplaceError::Stage(_) => write_failed("stage"),
        ReplaceError::Write(_) => write_failed("write"),
        ReplaceError::Failed(_) => write_failed("failed"),
        ReplaceError::RollbackFailed { .. } => write_failed("rollback_failed"),
        ReplaceError::Unconfirmed { .. } => write_failed("unconfirmed"),
    };
    Mapped::Refusal(refusal)
}

fn write_failed(variant: &'static str) -> UiRefused {
    tracing::warn!(variant, "settings save: the config write did not complete");
    UiRefused::Failed(FAILED.to_owned())
}

#[cfg(test)]
#[path = "ui_save_tests.rs"]
mod tests;
