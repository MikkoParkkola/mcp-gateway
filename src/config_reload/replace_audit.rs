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
use crate::security::TransparencyLogger;

/// What an intent is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IntentKind {
    /// Recovering a crashed write, or paying an owed reload, before the
    /// operation that found it pending.
    Recovery,
    /// A web UI settings save, naming the fields it edits (their display
    /// ids, never a value).
    Save { fields: Vec<String> },
    /// Discovery adopt.
    Adopt,
    /// A configuration-history restore.
    Restore,
    /// A web UI API key create.
    KeyCreate,
    /// An API key revoke, including unchanged-byte reconciliation.
    KeyRevoke,
    /// A web UI backend route's edit of one backend, named, never a value.
    Backend {
        operation: BackendOp,
        backend: String,
    },
}

/// Who asked for a key write and which key: what a key write's intent names
/// beside its kind, since `Replaced::Discard` keeps no original to diff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyWriter {
    /// The authenticated request's identity.
    pub(crate) actor: crate::security::audit::AuditWho,
    /// The key's name, never a value.
    pub(crate) subject: String,
}

/// Which backend route an intent is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackendOp {
    Add,
    Remove,
    Update,
}

impl BackendOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Update => "update",
        }
    }
}

/// The id an intent was appended under. Only the intent is recorded: no
/// outcome record follows it, so the request's own record (the web UI's
/// admin action) is where an outcome is read.
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
    /// For a key write, who wrote which key; `None` for every other kind,
    /// whose records name the gateway as before.
    pub(crate) writer: Option<KeyWriter>,
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
        writer: Option<KeyWriter>,
    },
    Off,
}

/// Whether the gateway authenticates its callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GatewayAuth {
    On,
    Off,
}

impl GatewayAuth {
    /// From the running config's `auth.enabled`.
    pub(crate) fn of(enabled: bool) -> Self {
        if enabled { Self::On } else { Self::Off }
    }
}

/// The text of [`ReplaceError::NoAuditLog`], which only the web UI routes
/// answer with.
#[cfg(feature = "webui")]
pub(crate) const NO_AUDIT_LOG: &str =
    "auth is on but no audit log is configured; config writes are refused";

/// Where this gateway's writes are audited: its audit log, when it has one.
/// The one place an [`Audit`] is built, so no caller chooses whether its
/// write is audited.
pub(crate) struct AuditPosture {
    log: Option<Arc<TransparencyLogger>>,
    auth: GatewayAuth,
}

impl AuditPosture {
    /// The posture of a gateway whose audit log is `log`, with `auth`.
    pub(crate) fn of(log: Option<Arc<TransparencyLogger>>, auth: GatewayAuth) -> Self {
        Self { log, auth }
    }

    /// Whether a write on this posture must append its intent: the gateway
    /// has an audit log, or has auth on and so refuses every write without
    /// one.
    pub(crate) fn requires_audit(&self) -> bool {
        self.log.is_some() || self.auth == GatewayAuth::On
    }

    /// The audit for one operation of `kind`. Auth on with no audit log is
    /// refused here as well as at startup: an authenticated gateway never
    /// writes its config unaudited.
    pub(crate) fn audit(self, kind: IntentKind) -> Result<Audit, ReplaceError> {
        match (self.log, self.auth) {
            (Some(log), _) => Ok(Audit::Required {
                sink: Box::new(LogSink(log)),
                kind,
                writer: None,
            }),
            (None, GatewayAuth::Off) => Ok(Audit::Off),
            (None, GatewayAuth::On) => Err(ReplaceError::NoAuditLog),
        }
    }

    /// The audit for a key write of `kind`: as [`Self::audit`], with the
    /// intent naming `actor` and the key `subject`.
    pub(crate) fn key_write(
        self,
        kind: IntentKind,
        actor: crate::security::audit::AuditWho,
        subject: &str,
    ) -> Result<Audit, ReplaceError> {
        let mut audit = self.audit(kind)?;
        if let Audit::Required { writer, .. } = &mut audit {
            *writer = Some(KeyWriter {
                actor,
                subject: subject.to_owned(),
            });
        }
        Ok(audit)
    }
}

/// Intents into the audit log, through its synced append: fsynced whatever
/// the log's failure policy, and on the tail other processes appended.
struct LogSink(Arc<TransparencyLogger>);

impl IntentSink for LogSink {
    fn append(&mut self, intent: &Intent) -> Result<IntentId, String> {
        let event = match &intent.kind {
            IntentKind::Recovery => "config_recovery_intent",
            IntentKind::Save { .. } => "config_save_intent",
            IntentKind::Adopt => "config_adopt_intent",
            IntentKind::Restore => "config_restore_intent",
            IntentKind::KeyCreate => "config_key_create_intent",
            IntentKind::KeyRevoke => "config_key_revoke_intent",
            IntentKind::Backend { .. } => "config_backend_intent",
        };
        let mut fields = serde_json::Map::new();
        fields.insert("event".into(), event.into());
        if let IntentKind::Backend { operation, backend } = &intent.kind {
            fields.insert("operation".into(), operation.as_str().into());
            fields.insert("backend".into(), backend.as_str().into());
        }
        if let IntentKind::Save { fields: edited } = &intent.kind {
            fields.insert("fields".into(), edited.clone().into());
        }
        fields.insert("base_revision".into(), intent.base.as_str().into());
        fields.insert("outside_change".into(), intent.outside_change.into());
        if let Some(IntentId(id)) = &intent.recovery_intent_id {
            fields.insert("recovery_intent_id".into(), id.as_str().into());
        }
        // A key write names who wrote which key; every other kind names the
        // gateway, as it always has.
        let envelope = match &intent.writer {
            Some(writer) => {
                fields.insert("subject".into(), writer.subject.as_str().into());
                crate::security::audit::AuditEnvelope::ok(writer.actor.clone())
            }
            None => crate::security::audit::AuditEnvelope::gateway(),
        };
        // ponytail: a synced append on the writer's task; spawn_blocking it
        // if a slow disk ever holds the config lock measurably longer.
        self.0
            .append_event_synced(fields, &envelope)
            .map(IntentId)
            .map_err(|e| e.to_string())
    }
}

/// Tests' writer with no audit: production reaches the writer only through
/// [`replace_audited`] with its posture's audit.
#[cfg(test)]
pub(crate) async fn replace_detached(
    ctx: Arc<ReloadContext>,
    replace: Replace,
    wait: Duration,
) -> Result<ReplaceOutcome, ReplaceError> {
    replace_audited(ctx, replace, Audit::Off, wait).await
}

/// The only way to run the byte writer. Invariant (ADR-024): a save's
/// compute closure produces its bytes through a refusing in-place editor
/// (the key editor or `edit_text`), never through a `CommentLoss::Rewrite`
/// render, so a refusal surfaces as [`ReplaceError::Refused`] and nothing
/// is written.
pub(crate) async fn replace_audited(
    ctx: Arc<ReloadContext>,
    replace: Replace,
    audit: Audit,
    wait: Duration,
) -> Result<ReplaceOutcome, ReplaceError> {
    super::spawn_locked(ctx, replace, audit, wait, None)
        .await
        .map(|(outcome, _)| outcome)
}

/// The same audited transaction, with a revoke receipt taken before unlocking.
pub(crate) async fn replace_audited_revoke(
    ctx: Arc<ReloadContext>,
    replace: Replace,
    audit: Audit,
    wait: Duration,
    check: super::receipt::RevokeCheck,
) -> Result<super::receipt::RevokeReceipt, ReplaceError> {
    if !matches!(
        &audit,
        Audit::Required {
            kind: IntentKind::KeyRevoke,
            ..
        }
    ) {
        return Err(ReplaceError::AuditRefused(
            "revoke requires its audit intent".into(),
        ));
    }
    let (_, receipt) = super::spawn_locked(ctx, replace, audit, wait, Some(check)).await?;
    receipt.ok_or_else(|| ReplaceError::Failed("missing revoke receipt".into()))
}

/// With anything pending (a crashed write's journal, or a reload `owed`
/// after a failed one), append the recovery's own intent. `None`: nothing
/// pending. A refused intent recovers nothing; the next holder tries again.
/// It does not wait, so a recovery sink lent to it is never held across an
/// await. Shared by the running gateway and startup
/// ([`crate::config_reload::recover_before_start`]); the sink is a
/// parameter so where intents go can change underneath both.
pub(crate) fn recovery_intent(
    sink: &mut dyn IntentSink,
    locked: &Locked,
    owed: bool,
) -> Result<Option<IntentId>, ReplaceError> {
    if !locked.journal_pending && !owed {
        return Ok(None);
    }
    // An absent file is the empty revision: the intent names what is on
    // disk before recovery. The read every loader uses: a file the guard
    // refuses is refused before any intent, and nothing is recovered.
    let on_disk = match crate::config::read_config_text(&locked.target) {
        Ok(text) => text.map_or_default(String::into_bytes),
        Err(crate::config::UnreadConfig::Refused(why)) => {
            return Err(ReplaceError::ConfigRefused(why));
        }
        Err(
            crate::config::UnreadConfig::Failed(why)
            | crate::config::UnreadConfig::NotTheConfig(why),
        ) => {
            return Err(ReplaceError::Failed(format!(
                "reading the config for the recovery's record failed: {why}"
            )));
        }
    };
    let intent = Intent {
        kind: IntentKind::Recovery,
        base: FileRevision::of(&on_disk),
        outside_change: true,
        recovery_intent_id: None,
        writer: None,
    };
    sink.append(&intent).map(Some).map_err(|e| {
        ReplaceError::AuditRefused(format!(
            "the audit log refused the recovery's record; nothing was recovered or reloaded: {e}"
        ))
    })
}

/// Startup's recovery intent, before the gateway is built: the audit of the
/// config that survives the recovery (`config`), so the record lands in the
/// log the starting gateway will write. A configured log that cannot open
/// refuses, whatever the auth setting: a recovery is never unaudited when
/// the surviving config names a log. The log is closed on return, so the
/// gateway's own open finds its lease free.
///
/// # Errors
///
/// Why the recovery cannot be recorded; the caller recovers nothing.
pub(crate) fn startup_recovery_intent(
    locked: &Locked,
    config: &crate::config::Config,
) -> Result<(), String> {
    let log = match config.audit_log() {
        None => None,
        Some(log) => Some(Arc::new(
            TransparencyLogger::open(Arc::new(log))
                .map_err(|e| format!("its audit log cannot be opened ({e})"))?,
        )),
    };
    let posture = AuditPosture::of(log, GatewayAuth::of(config.auth.enabled));
    let refused = |e: ReplaceError| match e {
        ReplaceError::Refused(why)
        | ReplaceError::AuditRefused(why)
        | ReplaceError::ConfigRefused(why)
        | ReplaceError::Failed(why) => why,
        other => format!("{other:?}"),
    };
    match posture.audit(IntentKind::Recovery).map_err(refused)? {
        Audit::Off => Ok(()),
        Audit::Required { mut sink, .. } => recovery_intent(sink.as_mut(), locked, false)
            .map(drop)
            .map_err(refused),
    }
}

impl ReloadContext {
    /// Audit this gateway's recoveries through `sink`, from its posture at
    /// start.
    pub(crate) fn set_recovery_audit(&self, sink: Box<dyn IntentSink>) {
        *self.recovery_audit.lock() = Some(sink);
    }

    /// Audit this gateway's recoveries into its audit log.
    pub(in crate::config_reload) fn audit_recoveries_into(&self, log: Arc<TransparencyLogger>) {
        self.set_recovery_audit(Box::new(LogSink(log)));
    }

    /// [`recovery_intent`] with this gateway's owed reload.
    fn recovery_intent(
        &self,
        sink: &mut dyn IntentSink,
        locked: &Locked,
    ) -> Result<Option<IntentId>, ReplaceError> {
        let owed = self.reload_owed.load(std::sync::atomic::Ordering::SeqCst);
        recovery_intent(sink, locked, owed)
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
        .map_err(|e| match e {
            crate::config_persistence::journal::NotRecovered::Refused(why) => {
                ReplaceError::ConfigRefused(why)
            }
            crate::config_persistence::journal::NotRecovered::Failed(why) => {
                ReplaceError::Failed(why)
            }
        })
    }
}
