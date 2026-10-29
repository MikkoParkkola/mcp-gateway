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
}

/// What every reload context of one gateway reports into: one refusal ledger,
/// one reload tally and one override auditor, shared by the admin API, the meta-tool and the
/// config file watcher, so a refusal is seen wherever it happened.
#[derive(Clone, Default)]
pub struct ReloadReporting {
    pub(crate) refusals: std::sync::Arc<RefusalLedger>,
    pub(crate) override_audit: Option<std::sync::Arc<super::override_audit::OverrideAuditor>>,
    /// Attempts and outcomes of every reload, whichever entry point made it.
    pub(crate) tally: std::sync::Arc<super::reload_tally::ReloadTally>,
}

impl ReloadReporting {
    /// Reporting into `override_audit` as well as a fresh ledger.
    #[must_use]
    pub fn with_override_audit(
        override_audit: std::sync::Arc<super::override_audit::OverrideAuditor>,
    ) -> Self {
        Self {
            refusals: std::sync::Arc::default(),
            override_audit: Some(override_audit),
            tally: std::sync::Arc::default(),
        }
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
        }
    }

    /// Record a refused reload or admin write from its error text. A refusal
    /// caused by shutdown is not recorded: nothing about the config is wrong.
    /// `backend_hint` names the backend an add or edit was for.
    pub fn record(&self, kind: RefusalKind, backend_hint: Option<&str>, error: &str) {
        if super::reload_failure(error) == super::ReloadFailure::ShuttingDown {
            return;
        }
        let (code, named) = classify(error);
        let backend = named.or_else(|| backend_hint.map(str::to_owned));
        let (cause, fix) = explain(code, kind, backend.as_deref());
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
    #[must_use]
    pub fn with_reporting(mut self, reporting: ReloadReporting) -> Self {
        self.reporting = reporting;
        self
    }

    /// The reporting this context shares, for a context built elsewhere.
    #[must_use]
    pub fn reporting(&self) -> ReloadReporting {
        self.reporting.clone()
    }
}

#[cfg(test)]
#[path = "refusals_tests.rs"]
mod tests;
