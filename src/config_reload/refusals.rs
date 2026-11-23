// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What this process refused to apply, and how to fix it: the read model
//! behind `GET /ui/api/refusals`.
//!
//! Bounded and in memory. A restart re-reads the file, and a file that is
//! still wrong is refused, and recorded, again.
//!
//! No refusal's text is ever stored as given. A refusal is classified, and the
//! cause shown is rebuilt from fixed wording plus at most a backend name, so a
//! validator message that quotes a configured value cannot be re-served here.

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Refusals kept; the oldest is dropped first.
pub(crate) const REFUSAL_CAP: usize = 64;

/// Where a refusal came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalKind {
    /// A backend the runtime policy refuses to start (derived on read).
    Startup,
    /// A config reload: file watcher, meta-tool, admin reload, admin write.
    Reload,
    /// `POST /ui/api/backends`.
    Add,
    /// `PATCH /ui/api/backends/{name}`.
    Edit,
}

/// Why, as a stable code a UI can branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    CleartextCredentials,
    Posture,
    RuntimeDenied,
    InvalidConfig,
    /// The file holds a first key that only a restart applies.
    FirstKeyWaiting,
}

/// One refusal as served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Refusal {
    pub id: u64,
    /// RFC 3339, display only; ordering uses `id`. `None` when the clock
    /// could not be read.
    pub at: Option<chrono::DateTime<chrono::Utc>>,
    pub kind: RefusalKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    pub code: RefusalCode,
    pub cause: String,
    pub fix: &'static str,
    pub active: bool,
    /// How many times this same refusal was recorded in a row.
    pub repeats: u32,
    /// Parser line of a reload refused as invalid config: a syntax error, or
    /// a serde error that carries a location. Omitted for every other
    /// refusal. A line quotes no configured value; a check after a clean
    /// parse has no location to give.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// When the configuration still running was applied. Served only for a
    /// reload refused as invalid config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running_since: Option<chrono::DateTime<chrono::Utc>>,
}

/// What every reload context of one gateway reports into: one refusal ledger,
/// one reload tally and one override auditor, shared by the admin API, the meta-tool and the
/// config file watcher, so a refusal is seen wherever it happened.
#[derive(Clone)]
pub struct ReloadReporting {
    pub(crate) refusals: std::sync::Arc<RefusalLedger>,
    pub(crate) override_audit: Option<std::sync::Arc<super::override_audit::OverrideAuditor>>,
    /// Attempts and outcomes of every reload, whichever entry point made it.
    pub(crate) tally: std::sync::Arc<super::reload_tally::ReloadTally>,
    /// The gateway's audit log, when it has one: every reload context built
    /// on this reporting records a recovery intent there before it recovers
    /// a crashed write or pays an owed reload.
    pub(crate) audit_log: Option<std::sync::Arc<crate::security::TransparencyLogger>>,
}

impl Default for ReloadReporting {
    fn default() -> Self {
        Self::fresh(None)
    }
}

impl ReloadReporting {
    /// A ledger that reads this tally's applied time, so an invalid-config
    /// reload can name the version still running.
    fn fresh(
        override_audit: Option<std::sync::Arc<super::override_audit::OverrideAuditor>>,
    ) -> Self {
        let tally = std::sync::Arc::new(super::reload_tally::ReloadTally::default());
        Self {
            refusals: std::sync::Arc::new(
                RefusalLedger::new().observing(std::sync::Arc::clone(&tally)),
            ),
            override_audit,
            tally,
            audit_log: None,
        }
    }

    /// Reporting into `override_audit` as well as a fresh ledger.
    #[must_use]
    pub fn with_override_audit(
        override_audit: std::sync::Arc<super::override_audit::OverrideAuditor>,
    ) -> Self {
        Self::fresh(Some(override_audit))
    }

    /// The same reporting, auditing recoveries into `log` (`None`: auth off
    /// and no audit log, so recoveries are not audited).
    #[must_use]
    pub fn with_audit_log(
        mut self,
        log: Option<std::sync::Arc<crate::security::TransparencyLogger>>,
    ) -> Self {
        self.audit_log = log;
        self
    }
}

/// Shown for every cause the ledger does not classify: the producer's text can
/// quote a configured value, so it is never re-served.
pub(crate) const WITHHELD: &str =
    "the file does not parse or validate (detail withheld: it can quote a configured value)";

/// One stored refusal; `seq` orders it against applied reloads and writes.
#[derive(Debug, Clone)]
struct Entry {
    seq: u64,
    at: SystemTime,
    kind: RefusalKind,
    backend: Option<String>,
    code: RefusalCode,
    cause: String,
    fix: &'static str,
    repeats: u32,
    line: Option<u32>,
    running_since: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Default)]
struct Inner {
    entries: VecDeque<Entry>,
    next_seq: u64,
    reload_applied: u64,
    /// Last applied write per backend, kept only for names an entry carries.
    write_applied: HashMap<String, u64>,
}

impl Inner {
    fn bump(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }
}

/// The ledger.
pub struct RefusalLedger {
    clock: fn() -> SystemTime,
    inner: parking_lot::Mutex<Inner>,
    /// The tally an invalid-config reload reads `running_since` from.
    /// `None` on a ledger built alone: it has no running version to name.
    running: Option<std::sync::Arc<super::reload_tally::ReloadTally>>,
}

impl Default for RefusalLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl RefusalLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(crate::clock::system_time_or_before_epoch)
    }

    /// A ledger stamping `at` from `clock` (tests pin it).
    #[must_use]
    pub fn with_clock(clock: fn() -> SystemTime) -> Self {
        Self {
            clock,
            inner: parking_lot::Mutex::new(Inner::default()),
            running: None,
        }
    }

    /// Read `running_since` from `tally` when an invalid-config reload is
    /// recorded. The tally is the one this gateway's reporting shares.
    #[must_use]
    pub(crate) fn observing(
        mut self,
        tally: std::sync::Arc<super::reload_tally::ReloadTally>,
    ) -> Self {
        self.running = Some(tally);
        self
    }

    /// Record a refused reload or admin write from its error text. A refusal
    /// caused by shutdown is not recorded: nothing about the config is wrong.
    /// `backend_hint` names the backend an add or edit was for.
    ///
    /// `line` is the parser location for an invalid-config reload. It is
    /// stored only for that refusal. The running version's time is read from
    /// the tally, not from the clock at this call: a refusal does not move
    /// the version still running.
    pub fn record(
        &self,
        kind: RefusalKind,
        backend_hint: Option<&str>,
        error: &str,
        line: Option<u32>,
    ) {
        if super::reload_failure(error) == super::ReloadFailure::ShuttingDown {
            return;
        }
        let (code, named) = classify(error);
        let backend = named.or_else(|| backend_hint.map(str::to_owned));
        self.record_coded(kind, backend, code, line);
    }

    /// Record a reload refused only because the file holds a first key that
    /// a restart applies: its own code, never classified from text.
    pub(crate) fn record_first_key_waiting(&self) {
        self.record_coded(
            RefusalKind::Reload,
            None,
            RefusalCode::FirstKeyWaiting,
            None,
        );
    }

    /// Record a reload refused because the file's first key fails another
    /// check: invalid config by type. The refusal's text carries the shared
    /// reload prefix, which classifying by text would call posture.
    pub(crate) fn record_invalid_config(&self) {
        self.record_coded(RefusalKind::Reload, None, RefusalCode::InvalidConfig, None);
    }

    /// Record one refusal whose code is already known.
    fn record_coded(
        &self,
        kind: RefusalKind,
        backend: Option<String>,
        code: RefusalCode,
        line: Option<u32>,
    ) {
        let (cause, fix) = explain(code, kind, backend.as_deref());
        // Both fields belong to an invalid-config reload. An admin write
        // classified the same way, and every other code, serve neither.
        let (line, running_since) =
            if kind == RefusalKind::Reload && code == RefusalCode::InvalidConfig {
                (
                    line,
                    self.running
                        .as_ref()
                        .and_then(|tally| tally.last_applied_at()),
                )
            } else {
                (None, None)
            };
        let at = (self.clock)();
        let mut inner = self.inner.lock();
        let reload_applied = inner.reload_applied;
        let write_applied = backend
            .as_ref()
            .and_then(|b| inner.write_applied.get(b).copied())
            .unwrap_or(0);
        if let Some(newest) = inner.entries.front_mut()
            && newest.kind == kind
            && newest.code == code
            && newest.backend == backend
            && newest.cause == cause
            && is_active(newest, reload_applied, write_applied)
        {
            newest.at = at;
            newest.repeats = newest.repeats.saturating_add(1);
            // The cause text is the same for every invalid file, so a later
            // one with a different line would otherwise keep the first line.
            newest.line = line;
            newest.running_since = running_since;
            return;
        }
        let seq = inner.bump();
        inner.entries.push_front(Entry {
            seq,
            at,
            kind,
            backend,
            code,
            cause,
            fix,
            repeats: 1,
            line,
            running_since,
        });
        inner.entries.truncate(REFUSAL_CAP);
        let Inner {
            entries,
            write_applied,
            ..
        } = &mut *inner;
        write_applied.retain(|name, _| entries.iter().any(|e| e.backend.as_ref() == Some(name)));
    }

    /// A reload applied: every earlier reload refusal is resolved.
    pub fn reload_applied(&self) {
        let mut inner = self.inner.lock();
        inner.reload_applied = inner.bump();
    }

    /// A place in the ledger's order, taken inside a write's lock before the
    /// write commits, so the write's success can be stamped after it commits
    /// without resolving a refusal recorded later.
    pub(crate) fn reserve(&self) -> u64 {
        self.inner.lock().bump()
    }

    /// The write that reserved `ticket` committed: add/edit refusals of
    /// `backend` recorded before it are resolved, later ones stay active.
    pub(crate) fn write_applied_at(&self, backend: &str, ticket: u64) {
        let mut inner = self.inner.lock();
        if inner
            .entries
            .iter()
            .any(|e| e.backend.as_deref() == Some(backend))
        {
            let stamp = inner.write_applied.entry(backend.to_owned()).or_default();
            *stamp = (*stamp).max(ticket);
        }
    }

    /// Newest first.
    #[must_use]
    pub fn list(&self) -> Vec<Refusal> {
        let inner = self.inner.lock();
        inner
            .entries
            .iter()
            .map(|e| {
                let written = e
                    .backend
                    .as_ref()
                    .and_then(|b| inner.write_applied.get(b).copied())
                    .unwrap_or(0);
                Refusal {
                    id: e.seq,
                    at: rfc3339(e.at),
                    kind: e.kind,
                    backend: e.backend.clone(),
                    code: e.code,
                    cause: e.cause.clone(),
                    fix: e.fix,
                    active: is_active(e, inner.reload_applied, written),
                    repeats: e.repeats,
                    line: e.line,
                    running_since: e.running_since,
                }
            })
            .collect()
    }
}

/// A backend the runtime policy refuses to start, as a `startup` refusal.
///
/// Derived on every read rather than stored, so its `id` comes from the name:
/// the same denial keeps the same id across polls, in a range (top bit set)
/// the ledger's sequence never reaches.
#[must_use]
pub(crate) fn startup_refusal(
    backend: &str,
    reasons: &[crate::runtime::RuntimeDenyReason],
) -> Refusal {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    backend.hash(&mut hasher);
    let codes: Vec<String> = reasons
        .iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let (_, fix) = explain(
        RefusalCode::RuntimeDenied,
        RefusalKind::Startup,
        Some(backend),
    );
    Refusal {
        id: hasher.finish() | (1 << 63),
        at: None,
        kind: RefusalKind::Startup,
        backend: Some(backend.to_owned()),
        code: RefusalCode::RuntimeDenied,
        cause: format!(
            "The runtime policy refuses to start server '{backend}': {}.",
            codes.join(", ")
        ),
        fix,
        active: true,
        repeats: 1,
        line: None,
        running_since: None,
    }
}

/// Every backend `registry` holds that its runtime policy denies, as `startup`
/// refusals: what `GET /ui/api/refusals` lists, and what the gateway snapshots
/// once at start.
#[must_use]
pub(crate) fn startup_refusals(registry: &crate::backend::BackendRegistry) -> Vec<Refusal> {
    #[allow(
        clippy::disallowed_methods,
        reason = "Admin: the operator dashboard behind admin auth; not a tenant read"
    )]
    let backends = registry.all();
    backends
        .iter()
        .filter_map(|backend| {
            let runtime = backend.status().runtime?;
            (runtime.state == crate::backend::BackendRuntimeState::Denied)
                .then(|| startup_refusal(&backend.name, &runtime.denied_reasons))
        })
        .collect()
}

fn is_active(entry: &Entry, reload_applied: u64, write_applied: u64) -> bool {
    match entry.kind {
        RefusalKind::Startup => true,
        RefusalKind::Reload => entry.seq > reload_applied,
        RefusalKind::Add | RefusalKind::Edit => entry.seq > write_applied,
    }
}

/// A display time, or `None` for a clock reading before the epoch.
pub(crate) fn rfc3339(at: SystemTime) -> Option<chrono::DateTime<chrono::Utc>> {
    at.duration_since(UNIX_EPOCH).ok()?;
    Some(chrono::DateTime::<chrono::Utc>::from(at))
}

/// Whether `error` is an invalid file, the only reload refusal that serves a
/// line and the running version's time. Posture, cleartext and shutdown do
/// not: shutdown is not a wrong file, and the other two have their own codes.
pub(crate) fn carries_file_line(error: &str) -> bool {
    if super::reload_failure(error) == super::ReloadFailure::ShuttingDown {
        return false;
    }
    classify(error).0 == RefusalCode::InvalidConfig
}

/// The class of `error`, and the backend it names when the class carries one.
///
/// A cleartext refusal is recognised only when the whole message is the
/// producer's, after the known wrappers: `Backend '<name>' ` and then exactly
/// [`crate::config::CLEARTEXT_REFUSAL`]. Anything else, a configured value that
/// merely contains those words included, is unclassified and withheld.
fn classify(error: &str) -> (RefusalCode, Option<String>) {
    if let Some(name) = cleartext_backend(error) {
        return (RefusalCode::CleartextCredentials, Some(name));
    }
    if super::is_posture_refusal(error) {
        return (RefusalCode::Posture, None);
    }
    (RefusalCode::InvalidConfig, None)
}

/// The backend a complete cleartext refusal names, if `error` is exactly one.
fn cleartext_backend(error: &str) -> Option<String> {
    let mut rest = error;
    for wrapper in ["Failed to parse config: ", "Failed to validate config: "] {
        rest = rest.strip_prefix(wrapper).unwrap_or(rest);
    }
    rest = rest
        .strip_prefix("Configuration validation error: ")
        .unwrap_or(rest);
    let (name, tail) = rest.strip_prefix("Backend '")?.split_once("' ")?;
    let plain = !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    (plain && tail == crate::config::CLEARTEXT_REFUSAL).then(|| name.to_owned())
}

/// The cause and fix shown for a class: fixed words plus at most the name.
fn explain(code: RefusalCode, kind: RefusalKind, backend: Option<&str>) -> (String, &'static str) {
    match code {
        RefusalCode::CleartextCredentials => (
            format!(
                "Server '{}' would send credentials in cleartext to a host off this machine.",
                backend.unwrap_or("?")
            ),
            "Use https:// for this server, or set allow_cleartext_credentials on it to accept \
             that its credentials are readable in transit.",
        ),
        RefusalCode::Posture => (
            "The reload changes a setting the network-posture policy refuses, or one that \
             applies only on restart; nothing was applied."
                .to_owned(),
            "Restart the gateway to apply it, or revert the change.",
        ),
        RefusalCode::RuntimeDenied => (
            "The runtime policy refuses to start this server.".to_owned(),
            "Change the server's runtime profile, or the runtime policy that denies it.",
        ),
        RefusalCode::InvalidConfig => (
            WITHHELD.to_owned(),
            match kind {
                RefusalKind::Add | RefusalKind::Edit => {
                    "Correct the server's settings; nothing was written."
                }
                _ => "Correct gateway.yaml; the previous configuration is still running.",
            },
        ),
        // No claim about a restart: a later edit can leave the file unable
        // to start, and the Gateway page says whether it would.
        RefusalCode::FirstKeyWaiting => (
            "gateway.yaml holds API keys that would change the gateway between \
             single-user and multi-user, which a running gateway never does."
                .to_owned(),
            "The Gateway page shows whether a start from this file would succeed; to \
             cancel, revoke the keys.",
        ),
    }
}

impl super::ReloadContext {
    /// The refusals this context's reloads and writes recorded.
    pub(crate) fn refusals(&self) -> &std::sync::Arc<RefusalLedger> {
        &self.reporting.refusals
    }

    /// The attempts and outcomes this context's reloads recorded.
    pub(crate) fn reload_tally(&self) -> &std::sync::Arc<super::reload_tally::ReloadTally> {
        &self.reporting.tally
    }

    /// Share `reporting` with every other reload context of this gateway.
    /// Reporting that carries the audit log audits this context's
    /// recoveries there.
    #[must_use]
    pub fn with_reporting(mut self, reporting: ReloadReporting) -> Self {
        if let Some(log) = reporting.audit_log.clone() {
            self.audit_recoveries_into(log);
        }
        // `new` stamped the tally it built, and this call discards that tally.
        // This one is the gateway's. The first context to take it records the
        // startup load; a later context sharing it, or a reload that already
        // applied, leaves the time where it is.
        reporting.tally.note_loaded();
        self.reporting = reporting;
        self
    }

    /// The reporting this context shares, for a context built elsewhere.
    #[must_use]
    pub fn reporting(&self) -> ReloadReporting {
        self.reporting.clone()
    }
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "refusals_tests.rs"]
mod tests;

#[cfg(tp3)]
#[cfg(test)]
#[path = "refusals_file_line_tests.rs"]
mod file_line_tests;
