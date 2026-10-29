// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Write-ahead audit for the byte writer: every write to
//! gateway.yaml on a gateway with an audit log appends a durable intent
//! before anything changes, and so does recovering a crashed write or paying
//! an owed reload. The audit comes from the gateway's posture, never from
//! the caller, through the one entry point [`replace_audited`].
#![expect(
    dead_code,
    reason = "first callers: the web UI settings save, discovery adopt and the configuration-history restore"
)]

use std::sync::Arc;
use std::time::Duration;

use super::{FileRevision, Replace, ReplaceError, ReplaceOutcome};
use crate::config_reload::ReloadContext;

/// What an intent is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntentKind {
    /// Recovering a crashed write, or paying an owed reload, before the
    /// operation that found it pending.
    Recovery,
    /// A web UI settings save.
    Save,
    /// Discovery adopt.
    Adopt,
    /// A configuration-history restore.
    Restore,
}

/// The id an intent was appended under; its outcome record carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IntentId(pub(crate) String);

/// One intent: what is about to change, never a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Intent {
    pub(crate) kind: IntentKind,
    /// The revision the operation is computed against.
    pub(crate) base: FileRevision,
    /// The bytes on disk differ from those the running config was loaded
    /// from.
    pub(crate) outside_change: bool,
    /// The recovery intent appended first, when anything was pending.
    pub(crate) recovery_intent_id: Option<IntentId>,
}

/// Where intents go: the audit log's synced append in production.
pub(crate) trait IntentSink: Send {
    fn append(&mut self, intent: &Intent) -> Result<IntentId, String>;
}

/// Whether this write is audited, from the gateway's posture.
pub(crate) enum Audit {
    /// Intents go to `sink`; the operation's own intent is a `kind`.
    Required {
        sink: Box<dyn IntentSink>,
        kind: IntentKind,
    },
    Off,
}

/// The only way to run the byte writer.
pub(crate) async fn replace_audited(
    ctx: Arc<ReloadContext>,
    replace: Replace,
    audit: Audit,
    wait: Duration,
) -> Result<ReplaceOutcome, ReplaceError> {
    super::spawn_locked(ctx, replace, audit, wait).await
}

impl ReloadContext {
    /// Audit this gateway's recoveries through `sink`, from its posture at
    /// start.
    pub(crate) fn set_recovery_audit(&self, sink: Box<dyn IntentSink>) {
        // Red-first stub: kept, not yet consulted by the reload path.
        *self.recovery_audit.lock() = Some(sink);
    }

    /// With anything pending (a crashed write's journal, or a reload owed
    /// after a failed one), append the recovery's own intent, then recover
    /// and pay the reload. A refused intent recovers and reloads nothing;
    /// the next holder tries again.
    pub(super) async fn recover_audited(
        &self,
        sink: &mut dyn IntentSink,
        journal_pending: bool,
        target: &std::path::Path,
    ) -> Result<Option<IntentId>, ReplaceError> {
        let owed = self.reload_owed.load(std::sync::atomic::Ordering::SeqCst);
        if !journal_pending && !owed {
            return Ok(None);
        }
        // An absent file is the empty revision here: the intent names what is
        // on disk before recovery, whatever it is.
        let on_disk = std::fs::read(target).unwrap_or_default();
        let intent = Intent {
            kind: IntentKind::Recovery,
            base: FileRevision::of(&on_disk),
            outside_change: true,
            recovery_intent_id: None,
        };
        let id = sink.append(&intent).map_err(|e| {
            ReplaceError::Refused(format!(
                "the audit log refused the recovery's record; nothing was recovered or reloaded: {e}"
            ))
        })?;
        let path = target.to_path_buf();
        let recovered =
            tokio::task::spawn_blocking(move || crate::config_persistence::journal::recover(&path))
                .await
                .map_err(|e| ReplaceError::Failed(format!("the recovery task failed: {e}")))?
                .map_err(ReplaceError::Failed)?;
        self.pay_owed_reload(recovered, target).await;
        Ok(Some(id))
    }
}
