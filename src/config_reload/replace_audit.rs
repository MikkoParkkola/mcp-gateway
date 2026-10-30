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
use crate::config_persistence::lock::Locked;
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
        *self.recovery_audit.lock() = Some(sink);
    }

    /// With anything pending (a crashed write's journal, or a reload owed
    /// after a failed one), append the recovery's own intent. `None`:
    /// nothing pending. A refused intent recovers nothing; the next holder
    /// tries again. It does not wait, so a recovery sink lent to it is never
    /// held across an await.
    fn recovery_intent(
        &self,
        sink: &mut dyn IntentSink,
        locked: &Locked,
    ) -> Result<Option<IntentId>, ReplaceError> {
        let owed = self.reload_owed.load(std::sync::atomic::Ordering::SeqCst);
        if !locked.journal_pending && !owed {
            return Ok(None);
        }
        // An absent file is the empty revision: the intent names what is on
        // disk before recovery. Any other read failure recovers nothing.
        let on_disk = match std::fs::read(&locked.target) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                return Err(ReplaceError::Failed(format!(
                    "reading {} for the recovery's record failed: {e}",
                    locked.target.display()
                )));
            }
        };
        let intent = Intent {
            kind: IntentKind::Recovery,
            base: FileRevision::of(&on_disk),
            outside_change: true,
            recovery_intent_id: None,
        };
        sink.append(&intent).map(Some).map_err(|e| {
            ReplaceError::Refused(format!(
                "the audit log refused the recovery's record; nothing was recovered or reloaded: {e}"
            ))
        })
    }

    /// The write path's recovery: on an audited write, its intent, then the
    /// journal recovered and any owed reload paid; unaudited, the lock
    /// already recovered and only the owed reload is paid.
    pub(super) async fn recover_before_write(
        &self,
        audit: &mut Audit,
        locked: Locked,
    ) -> Result<(Locked, Option<IntentId>), ReplaceError> {
        // Exhaustive on purpose: a new audit mode must choose here.
        let sink = match audit {
            Audit::Required { sink, .. } => sink,
            Audit::Off => {
                self.pay_owed_reload(locked.recovered, &locked.target).await;
                return Ok((locked, None));
            }
        };
        let Some(id) = self.recovery_intent(sink.as_mut(), &locked)? else {
            return Ok((locked, None));
        };
        let locked = self.recover_held(locked).await?;
        self.pay_owed_reload(locked.recovered, &locked.target).await;
        Ok((locked, Some(id)))
    }

    /// The reader lock a reload takes: deferred on an audited gateway, so
    /// its recovery intent comes before any recovery.
    pub(crate) async fn reader_lock_for_reload(
        &self,
        deadline: std::time::Instant,
    ) -> crate::config_persistence::lock::ReaderLock {
        let audited = self.recovery_audit.lock().is_some();
        if audited {
            crate::config_persistence::lock::reader_lock_deferred(&self.config_path, deadline).await
        } else {
            crate::config_persistence::lock::reader_lock(&self.config_path, deadline).await
        }
    }

    /// The reload path's recovery on an audited gateway: the intent through
    /// the recovery sink, which stays in its slot (the append does not wait),
    /// then the journal. `Err` is the reason to skip this reload. Without a
    /// sink, `locked` as it came: its acquisition recovered.
    pub(crate) async fn recover_for_reload(&self, locked: Locked) -> Result<Locked, String> {
        let intent = match self.recovery_audit.lock().as_mut() {
            None => return Ok(locked),
            Some(sink) => self.recovery_intent(sink.as_mut(), &locked),
        };
        match intent {
            Ok(None) => Ok(locked),
            Ok(Some(_)) => self
                .recover_held(locked)
                .await
                .map_err(|e| format!("{e:?}")),
            Err(e) => Err(format!("{e:?}")),
        }
    }

    /// Recovers `locked`'s journal with the lock moved into the recovery
    /// task: a caller dropped meanwhile cannot release the lock while the
    /// recovery still writes.
    async fn recover_held(&self, mut locked: Locked) -> Result<Locked, ReplaceError> {
        // Owed before the task starts: a rollback whose caller is dropped
        // meanwhile still leaves its reload to the next lock holder. A
        // recovery that changed nothing costs one redundant reload.
        self.reload_owed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        let pause = Arc::clone(&self.recovery_pause);
        tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            pause.pause_blocking();
            locked.recovered = crate::config_persistence::journal::recover(&locked.target)?;
            locked.journal_pending = false;
            Ok(locked)
        })
        .await
        .map_err(|e| ReplaceError::Failed(format!("the recovery task failed: {e}")))?
        .map_err(ReplaceError::Failed)
    }
}
