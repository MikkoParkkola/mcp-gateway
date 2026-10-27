// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An audit record whenever a cleartext-credential override takes effect or
//! ends.
//!
//! `allow_cleartext_credentials` is the operator's recorded decision to send a
//! backend's credentials over a cleartext wire. It "takes effect" when a
//! backend that would otherwise be refused is registered, so the set is read
//! from the backend registry, not from the published config: a reload that
//! registers backends and is then cancelled leaves the override live with the
//! config unpublished.
//!
//! Transitions are computed under one mutex and queued in that order for a
//! single worker, which appends them one at a time. Queueing is synchronous
//! and needs no runtime, so a reload dropped mid-flight still queues its
//! transitions; shutdown drains the queue within a deadline and names
//! anything it could not write.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use crate::backend::BackendRegistry;
#[cfg(test)]
use crate::config::{BackendConfig, Config};
use crate::security::TransparencyLogger;
use crate::security::audit::{AuditEnvelope, AuditFailurePolicy, AuditWho};

/// What happened to one backend's override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverrideAction {
    InEffect,
    Withdrawn,
}

impl OverrideAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::InEffect => "cleartext_override_in_effect",
            Self::Withdrawn => "cleartext_override_withdrawn",
        }
    }
}

/// One queued record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Transition {
    pub action: OverrideAction,
    pub backend: String,
}

#[derive(Debug, Default)]
struct Queue {
    pending: VecDeque<Transition>,
    closed: bool,
}

/// The process's override auditor.
pub struct OverrideAuditor {
    audited: parking_lot::Mutex<BTreeSet<String>>,
    queue: parking_lot::Mutex<Queue>,
    wake: tokio::sync::Notify,
}

/// The worker's handle, held by whoever runs shutdown.
pub struct OverrideAuditDrain {
    auditor: Arc<OverrideAuditor>,
    worker: tokio::task::JoinHandle<()>,
}

impl OverrideAuditor {
    /// Start the auditor and its single append worker. With no `log`, each
    /// transition is a `warn!` naming the action and the backend.
    #[must_use]
    pub fn start(log: Option<Arc<TransparencyLogger>>) -> (Arc<Self>, OverrideAuditDrain) {
        let auditor = Arc::new(Self {
            audited: parking_lot::Mutex::new(BTreeSet::new()),
            queue: parking_lot::Mutex::new(Queue::default()),
            wake: tokio::sync::Notify::new(),
        });
        let worker = tokio::spawn(work(Arc::clone(&auditor), log));
        let drain = OverrideAuditDrain {
            auditor: Arc::clone(&auditor),
            worker,
        };
        (auditor, drain)
    }

    /// Compare the registry's in-effect overrides with the last audited set
    /// and queue one transition per change, in name order.
    pub fn sync(&self, registry: &BackendRegistry) {
        self.sync_from(in_effect(registry));
    }

    /// [`Self::sync`] from configured backends, for tests that hold no
    /// registry.
    #[cfg(test)]
    pub(crate) fn sync_config(&self, backends: &[(String, BackendConfig)]) {
        self.sync_from(
            backends
                .iter()
                .filter(|(name, config)| Config::cleartext_override_in_effect(name, config))
                .map(|(name, _)| name.clone()),
        );
    }

    /// Record the overrides in effect at start, before the gateway serves, and
    /// wait for each record, through the log's timed write so a stuck audit
    /// file cannot hang the start. A failed or timed-out write follows the
    /// log's policy: under `FailClosed` the start is refused; under
    /// `BestEffort` it is logged and the start goes on.
    ///
    /// # Errors
    ///
    /// [`crate::Error::AuditUnavailable`] when a `FailClosed` log cannot take
    /// a record in time.
    pub async fn record_at_start(
        &self,
        registry: &BackendRegistry,
        log: Option<&Arc<TransparencyLogger>>,
    ) -> crate::Result<()> {
        let transitions = diff(&mut self.audited.lock(), in_effect(registry));
        for t in &transitions {
            let Some(log) = log else {
                no_log(t);
                continue;
            };
            let (fields, envelope) = (fields(t), envelope());
            let written = log
                .append_bounded(move |l| {
                    l.append_admin_action("config", fields, &envelope)
                        .map_err(std::io::Error::other)
                })
                .await;
            if let Err(error) = written {
                tracing::error!(
                    action = t.action.as_str(),
                    backend = %t.backend,
                    %error,
                    "cleartext override audit record not written at start"
                );
                if log.failure_policy() == AuditFailurePolicy::FailClosed {
                    return Err(crate::Error::AuditUnavailable);
                }
            }
        }
        Ok(())
    }

    fn sync_from(&self, in_effect: impl Iterator<Item = String>) {
        let mut audited = self.audited.lock();
        let transitions = diff(&mut audited, in_effect);
        if transitions.is_empty() {
            return;
        }
        // Queued while `audited` is still held, so two syncs cannot interleave
        // their transitions.
        {
            let mut queue = self.queue.lock();
            if queue.closed {
                for t in &transitions {
                    unwritten(t);
                }
            } else {
                queue.pending.extend(transitions);
            }
        }
        drop(audited);
        self.wake.notify_one();
    }

    /// A drop guard that syncs against `registry` however the scope ends.
    pub(crate) fn guard<'a>(&'a self, registry: &'a BackendRegistry) -> SyncOnDrop<'a> {
        SyncOnDrop {
            auditor: self,
            registry,
        }
    }
}

/// Syncs on drop: success, refusal, or a cancelled reload future.
pub(crate) struct SyncOnDrop<'a> {
    auditor: &'a OverrideAuditor,
    registry: &'a BackendRegistry,
}

impl Drop for SyncOnDrop<'_> {
    fn drop(&mut self) {
        self.auditor.sync(self.registry);
    }
}

impl OverrideAuditDrain {
    /// Wait for every reload in flight to finish (each queues its transitions
    /// before it lets go of the registry's reload lock), stop taking
    /// transitions, then wait for the worker to write what is queued, all
    /// within `timeout`. What is still queued at the deadline is logged by
    /// name, never dropped silently.
    pub async fn drain(self, registry: &BackendRegistry, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: shutdown waits out reloads in flight; no caller request"
        )]
        let reloads_done = tokio::time::timeout_at(deadline, registry.lock_reload()).await;
        self.auditor.queue.lock().closed = true;
        drop(reloads_done);
        self.auditor.wake.notify_one();
        let Self { auditor, worker } = self;
        let abort = worker.abort_handle();
        if tokio::time::timeout_at(deadline, worker).await.is_err() {
            abort.abort();
            let left = std::mem::take(&mut auditor.queue.lock().pending);
            for t in &left {
                unwritten(t);
            }
        }
    }
}

/// The overrides in effect among `registry`'s backends.
fn in_effect(registry: &BackendRegistry) -> impl Iterator<Item = String> {
    #[allow(
        clippy::disallowed_methods,
        reason = "Lifecycle: auditing the operator's backend set; no caller request"
    )]
    let backends = registry.all();
    backends
        .into_iter()
        .filter(|b| b.cleartext_override_in_effect())
        .map(|b| b.name.clone())
}

/// What changed since `audited`, withdrawals first, each in name order;
/// `audited` becomes `now`.
fn diff(audited: &mut BTreeSet<String>, now: impl Iterator<Item = String>) -> Vec<Transition> {
    let now: BTreeSet<String> = now.collect();
    let withdrawn = audited.difference(&now).map(|b| Transition {
        action: OverrideAction::Withdrawn,
        backend: b.clone(),
    });
    let in_effect = now.difference(audited).map(|b| Transition {
        action: OverrideAction::InEffect,
        backend: b.clone(),
    });
    let transitions = withdrawn.chain(in_effect).collect();
    *audited = now;
    transitions
}

fn fields(t: &Transition) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert("action".into(), t.action.as_str().into());
    fields.insert("backend".into(), t.backend.clone().into());
    fields
}

/// No request principal exists for a file edit: the configuration file is
/// the actor.
fn envelope() -> AuditEnvelope {
    AuditEnvelope::ok(AuditWho::from_actor_id("config_file"))
}

fn no_log(t: &Transition) {
    tracing::warn!(
        action = t.action.as_str(),
        backend = %t.backend,
        "cleartext credential override changed; no transparency log to record it"
    );
}

/// The record that could not be written, named.
fn unwritten(t: &Transition) {
    tracing::error!(
        action = t.action.as_str(),
        backend = %t.backend,
        "cleartext override audit record not written: shutdown deadline passed"
    );
}

/// The single worker: append the front of the queue, then pop it, so an
/// append cut off by the drain deadline is still named.
async fn work(auditor: Arc<OverrideAuditor>, log: Option<Arc<TransparencyLogger>>) {
    loop {
        let notified = auditor.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let next = {
            let queue = auditor.queue.lock();
            match queue.pending.front() {
                Some(t) => Some(t.clone()),
                None if queue.closed => return,
                None => None,
            }
        };
        let Some(t) = next else {
            notified.await;
            continue;
        };
        append(log.as_ref(), &t).await;
        auditor.queue.lock().pending.pop_front();
    }
}

async fn append(log: Option<&Arc<TransparencyLogger>>, t: &Transition) {
    let Some(log) = log else {
        no_log(t);
        return;
    };
    let (fields, envelope) = (fields(t), envelope());
    let written = log
        .append_bounded(move |l| {
            l.append_admin_action("config", fields, &envelope)
                .map_err(std::io::Error::other)
        })
        .await;
    if let Err(error) = written {
        tracing::error!(
            action = t.action.as_str(),
            backend = %t.backend,
            %error,
            "cleartext override audit record not written"
        );
    }
}

#[cfg(test)]
#[path = "override_audit_tests.rs"]
mod tests;
