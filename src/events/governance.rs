// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Governance records (design 3.7): subscribe, refresh, verification,
//! unsubscribe, dead-letter and replay each write one record through the
//! audit chain's `append_event`. Best effort: the act has happened, and a
//! down log is logged. A record names the subscription, the event and the
//! callback host, never the callback path, the secret or a body.

use std::sync::Arc;

use serde_json::Map;

use super::EventsHub;
use super::rpc::Caller;
use super::services::{Scan, Services};
use crate::security::audit::{AuditEnvelope, AuditOutcome, AuditWho};

/// Who an audit record names as the actor.
#[derive(Clone, Copy)]
pub(crate) enum Attribution<'a> {
    /// The gateway itself (a settlement).
    Gateway,
    /// A subscriber calling `events/*`.
    Caller(&'a Caller),
    /// The authenticated admin who triggered the act (a replay).
    Admin(&'a Actor),
}

/// An authenticated admin, as the UI routes resolved it: the credential and,
/// for an SSO admin, the verified `(issuer, subject)`, as the admin audit layer
/// names them.
#[cfg_attr(
    not(feature = "webui"),
    allow(dead_code, reason = "built by the dashboard routes")
)]
pub(crate) struct Actor {
    pub who: AuditWho,
}

/// One governance act.
pub(crate) struct Lifecycle<'a> {
    pub action: &'static str,
    pub subscription_id: &'a str,
    pub event_name: &'a str,
    pub callback_host: &'a str,
    /// What came of it: a verification's outcome, a dead letter's reason.
    pub detail: &'a str,
    /// The dead letter an act is about, when it is about one.
    pub event_id: Option<&'a str>,
    /// The JSON-RPC code the act failed with; `None` when it succeeded.
    pub failed_with: Option<i32>,
}

impl Services {
    /// Write one governance record, attributed as `by` says.
    pub(crate) async fn audit_lifecycle(&self, act: &Lifecycle<'_>, by: Attribution<'_>) {
        let Some(log) = &self.audit else {
            return;
        };
        let mut fields = Map::new();
        fields.insert("action".into(), act.action.into());
        crate::clock::stamp_audit_row(&mut fields);
        fields.insert(
            "subscription_id".into(),
            self.alias(act.subscription_id).into(),
        );
        fields.insert("event_name".into(), act.event_name.into());
        fields.insert("callback_host".into(), act.callback_host.into());
        fields.insert("detail".into(), act.detail.into());
        if let Some(id) = act.event_id {
            fields.insert("event_id".into(), id.into());
            fields.insert("reason".into(), act.detail.into());
        }
        let mut envelope = AuditEnvelope::gateway();
        match by {
            Attribution::Gateway => {}
            Attribution::Caller(caller) => {
                // Credential-derived values, keyed for the record (MIK-8697 §16.12).
                let key = self.record_key();
                let owner = caller
                    .principal
                    .as_deref()
                    .map(|p| crate::gateway::record_principal::record_owner(p, key));
                if let Some(owner) = &owner {
                    fields.insert("principal".into(), owner.clone().into());
                }
                envelope.who = AuditWho::from_parts(
                    caller.credential.kind,
                    crate::gateway::record_principal::InternalPrincipal::new(
                        caller.credential.principal.clone(),
                    )
                    .record_form(key),
                    caller
                        .credential
                        .api_key
                        .as_ref()
                        .map(|k| k.name.as_str())
                        .or(owner.as_deref()),
                    None,
                );
            }
            Attribution::Admin(actor) => {
                envelope.who = actor.who.clone();
            }
        }
        if let Some(code) = act.failed_with {
            envelope.outcome = AuditOutcome::Error(code);
        }
        let written = log
            .append_bounded(move |log| log.append_event(fields, &envelope).map(|_| ()))
            .await;
        if let Err(error) = written {
            tracing::warn!(%error, "events: governance audit record not written");
        }
    }

    /// What the firewall decided about one payload, for the attempt record:
    /// `block`, `redacted`, `pass`, or `none` when no firewall is running.
    pub(crate) fn firewall_verdict(&self, scan: Scan, redacted: bool) -> &'static str {
        #[cfg(feature = "firewall")]
        if self.firewall.is_none() {
            return "none";
        }
        #[cfg(not(feature = "firewall"))]
        let _ = (self, scan, redacted);
        #[cfg(feature = "firewall")]
        return match (scan, redacted) {
            (Scan::Block, _) => "block",
            (Scan::Pass, true) => "redacted",
            (Scan::Pass, false) => "pass",
        };
        #[cfg(not(feature = "firewall"))]
        "none"
    }

    /// What a replay's attempt record says the firewall decided (MIK-8794):
    /// [`Self::firewall_verdict`] over the fresh scan of the stored body,
    /// carried forward by [`carried`] when that body was redacted before it
    /// was stored. `body` is the body the replay sends.
    pub(crate) fn replay_verdict(
        &self,
        scan: Scan,
        redacted: bool,
        stored: Option<&str>,
        body: &[u8],
    ) -> &'static str {
        #[cfg(feature = "firewall")]
        let holds_marker =
            String::from_utf8_lossy(body).contains(crate::security::firewall::redactor::MARKER);
        #[cfg(not(feature = "firewall"))]
        let holds_marker = {
            let _ = body;
            false
        };
        carried(self.firewall_verdict(scan, redacted), stored, holds_marker)
    }
}

/// A replay's verdict from its fresh one (MIK-8794). Redaction twice changes
/// nothing, so a re-scan of a body redacted before it was stored reads
/// `pass`. It stays `redacted` when the stored verdict was `redacted`, or
/// `block` (a blocked event is stored with its body already redacted), and
/// the body still holds the marker: a `block` alone proves no redaction. A
/// fresh `block` or `redacted` stands, and so does `none`.
fn carried(fresh: &'static str, stored: Option<&str>, holds_marker: bool) -> &'static str {
    if fresh == "pass" && matches!(stored, Some("redacted" | "block")) && holds_marker {
        "redacted"
    } else {
        fresh
    }
}

impl EventsHub {
    /// The record of a subscribe, or of a refresh of a live subscription.
    pub(crate) async fn subscribed(
        &self,
        caller: &Caller,
        admission: super::store::Admission,
        id: &str,
        name: &str,
        url: &url::Url,
    ) {
        let act = Lifecycle {
            // The commit's own verdict, not an earlier read: two racing
            // identical subscribes cannot both be the first.
            action: if admission == super::store::Admission::Refreshed {
                "events.refresh"
            } else {
                "events.subscribe"
            },
            subscription_id: id,
            event_name: name,
            callback_host: url.host_str().unwrap_or_default(),
            detail: "",
            event_id: None,
            failed_with: None,
        };
        self.govern(&act, Attribution::Caller(caller)).await;
    }

    /// Write a governance record when the pipeline has started.
    pub(crate) async fn govern(&self, act: &Lifecycle<'_>, by: Attribution<'_>) {
        let services: Option<&Arc<Services>> = self.runtime.services.get();
        if let Some(services) = services {
            services.audit_lifecycle(act, by).await;
        }
    }
}

#[cfg(test)]
#[path = "governance_tests.rs"]
mod tests;
