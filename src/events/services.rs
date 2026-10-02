// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway controls every event payload passes (design §3.6-3.7): the
//! live access re-check, the response firewall, tenant attribution, the
//! budget and the attributed audit record. Handed over once at startup.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::records::{ApiKeyRef, Subscription};
use crate::config_reload::LiveConfig;
use crate::security::TransparencyLogger;

/// What the hub borrows from the rest of the gateway.
pub(crate) struct Services {
    /// The published config: API-key scopes are re-read from it per check.
    pub live: Arc<LiveConfig>,
    #[cfg(feature = "firewall")]
    pub firewall: Option<Arc<crate::security::firewall::Firewall>>,
    pub audit: Option<Arc<TransparencyLogger>>,
    #[cfg(feature = "cost-governance")]
    pub budget: Option<(
        Arc<crate::cost_accounting::enforcer::BudgetEnforcer>,
        Arc<crate::cost_accounting::registry::CostRegistry>,
    )>,
}

/// The firewall's judgement of one payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scan {
    /// Deliverable, with any redaction applied in place.
    Pass,
    /// Refused: dead-letter `firewall_blocked`.
    Block,
}

/// Who an event is for and what it is, for the firewall's audit labels.
pub(crate) struct Subject<'a> {
    pub event_id: &'a str,
    pub principal: &'a str,
    pub backend: &'a str,
    pub name: &'a str,
}

impl Services {
    /// Whether a subscription made with API key `key` may still see
    /// `backend` under the live config. A key that left the config, expired,
    /// or was replaced under the same name sees nothing; a principal without
    /// an API key has no live scope to re-read, so its subscribe-time check
    /// stands.
    pub(crate) fn admits(&self, key: Option<&ApiKeyRef>, backend: &str) -> bool {
        let Some(key) = key else {
            return true;
        };
        let now = chrono::Utc::now();
        self.live
            .get()
            .auth
            .api_keys
            .iter()
            .find(|k| k.name == key.name)
            .filter(|k| !k.is_expired_at(now))
            .filter(|k| {
                k.key_sha256
                    .as_deref()
                    .and_then(crate::config::parse_api_key_digest)
                    .is_some_and(|digest| hex::encode(&digest[..6]) == key.principal)
            })
            .is_some_and(|k| k.backends.iter().any(|b| b == "*" || b == backend))
    }

    /// [`Self::admits`] for a stored subscription. One stored before keys
    /// were bound to their secret is refused.
    pub(crate) fn admits_subscription(&self, sub: &Subscription, backend: &str) -> bool {
        sub.legacy_api_key_name.is_none() && self.admits(sub.api_key.as_ref(), backend)
    }

    /// Run the response firewall over `data`, redacting in place.
    #[cfg(feature = "firewall")]
    pub(crate) fn scan(&self, data: &mut Value, subject: &Subject<'_>) -> Scan {
        use crate::security::response_policy::{
            ResponseArtifactKind, ResponseCorrelation, ResponseMutationPolicy, ResponsePolicyTarget,
        };
        let Some(firewall) = &self.firewall else {
            return Scan::Pass;
        };
        let targets = [ResponsePolicyTarget {
            server: subject.backend.to_owned(),
            tool: subject.name.to_owned(),
        }];
        let correlation = ResponseCorrelation {
            session_id: subject.event_id,
            caller: subject.principal,
            external_server: subject.backend,
            external_tool: subject.name,
        };
        match firewall.check_response_artifact(
            data,
            &targets,
            &correlation,
            ResponseArtifactKind::EventPayload,
            ResponseMutationPolicy::Redact,
        ) {
            Ok(verdict) if verdict.allowed => Scan::Pass,
            _ => Scan::Block,
        }
    }

    /// Without the firewall feature there is nothing to scan with.
    #[cfg(not(feature = "firewall"))]
    pub(crate) fn scan(&self, data: &mut Value, subject: &Subject<'_>) -> Scan {
        let _ = (self, data, subject);
        Scan::Pass
    }

    /// The hashed tenants `data` names (MIN.1 attribution), sorted.
    pub(crate) fn tenants(&self, data: &Value) -> Vec<String> {
        #[cfg(feature = "firewall")]
        if let Some(firewall) = &self.firewall {
            return firewall
                .response_tenants(data)
                .into_iter()
                .map(|id| crate::security::hash_argument(&Value::String(id)))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
        }
        let _ = (self, data);
        Vec::new()
    }

    /// Charge one attempt to `key`'s budgets under `events:<name>`; `false`
    /// when a budget refuses it (dead-letter `budget`).
    #[cfg(feature = "cost-governance")]
    pub(crate) fn charge(&self, name: &str, key: Option<&str>, cost: f64) -> bool {
        let Some((enforcer, registry)) = &self.budget else {
            return true;
        };
        if cost <= 0.0 {
            return true;
        }
        let tool = format!("events:{name}");
        registry.register_from_capability(&tool, cost);
        let verdict = enforcer.check(&tool, key);
        if verdict.allowed {
            enforcer.record_spend(&tool, key, verdict.cost_usd);
        }
        verdict.allowed
    }

    /// Without cost governance no budget applies.
    #[cfg(not(feature = "cost-governance"))]
    pub(crate) fn charge(&self, name: &str, key: Option<&str>, cost: f64) -> bool {
        let _ = (self, name, key, cost);
        true
    }
}

/// One delivery attempt, as the attributed audit record states it: never
/// the body, the secret or the callback path.
pub(crate) struct Attempt<'a> {
    pub subscription_id: &'a str,
    pub event_id: &'a str,
    pub name: &'a str,
    pub backend: &'a str,
    pub number: u32,
    pub principal: &'a str,
    pub api_key_name: Option<&'a str>,
    pub credential_kind: crate::security::audit::CredentialKind,
    pub tenants: &'a [String],
    pub callback_host: &'a str,
    pub status: &'a str,
    pub body_sha256: &'a str,
    pub delivered: bool,
}

impl Services {
    /// Write one MIN.1 attributed record for `attempt`, on the bounded
    /// blocking pool. Best effort: a down log is logged, not fatal.
    pub(crate) async fn audit_attempt(&self, attempt: &Attempt<'_>) {
        use crate::security::audit::{
            AuditEnvelope, AuditOutcome, AuditWho, InvocationRoute, InvocationTarget,
        };
        use crate::security::transparency_log::{CorrelationKey, CorrelationSource};
        let Some(log) = &self.audit else {
            return;
        };
        let mut extra = Map::new();
        extra.insert("subscription_id".into(), attempt.subscription_id.into());
        extra.insert("event_id".into(), attempt.event_id.into());
        extra.insert("attempt".into(), attempt.number.into());
        extra.insert("principal".into(), attempt.principal.into());
        extra.insert("callback_host".into(), attempt.callback_host.into());
        extra.insert("status".into(), attempt.status.into());
        extra.insert("body_sha256".into(), attempt.body_sha256.into());
        // Present even when empty: the record says it was attributed.
        extra.insert("tenants".into(), json!(attempt.tenants));
        let envelope = AuditEnvelope {
            trace_id: None,
            otel_trace_id: None,
            outcome: if attempt.delivered {
                AuditOutcome::Ok
            } else {
                AuditOutcome::Error(-32015)
            },
            who: AuditWho::from_parts(
                attempt.credential_kind,
                Some(attempt.principal),
                attempt.api_key_name.or(Some(attempt.principal)),
                None,
            ),
        };
        let (event_id, backend, name, body_hash) = (
            attempt.event_id.to_owned(),
            attempt.backend.to_owned(),
            attempt.name.to_owned(),
            attempt.body_sha256.to_owned(),
        );
        let written = log
            .append_bounded(move |log| {
                log.log_invocation_attributed(
                    CorrelationKey {
                        id: &event_id,
                        source: CorrelationSource::TraceId,
                    },
                    &envelope,
                    InvocationTarget {
                        route: InvocationRoute::EventDelivery,
                        server: &backend,
                        tool: Some(&name),
                    },
                    // The request this record is about is the body sent.
                    &body_hash,
                    None,
                    extra,
                )
            })
            .await;
        if let Err(error) = written {
            tracing::warn!(%error, "events: delivery audit record not written");
        }
    }

    /// One governance record per evicted dead letter (design §3.8).
    pub(crate) async fn audit_evictions(&self, evicted: Vec<super::outbox::Evicted>) {
        let Some(log) = &self.audit else {
            return;
        };
        for e in evicted {
            let mut fields = Map::new();
            fields.insert("action".into(), "events.dead_letter_evicted".into());
            fields.insert("timestamp".into(), chrono::Utc::now().to_rfc3339().into());
            fields.insert("event_id".into(), e.event_id.into());
            fields.insert("subscription_id".into(), e.subscription_id.into());
            fields.insert("reason".into(), e.reason.into());
            let envelope = crate::security::audit::AuditEnvelope::gateway();
            let written = log
                .append_bounded(move |log| log.append_event(fields, &envelope).map(|_| ()))
                .await;
            if let Err(error) = written {
                tracing::warn!(%error, "events: eviction audit record not written");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKeyConfig, ApiKeyKind, Config, api_key_digest_spec};

    fn key(
        name: &str,
        secret: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> ApiKeyConfig {
        ApiKeyConfig {
            key: None,
            key_sha256: Some(api_key_digest_spec(secret.as_bytes())),
            expires_at,
            name: name.to_owned(),
            rate_limit: 0,
            backends: vec!["x".to_owned()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: ApiKeyKind::Shared,
        }
    }

    fn services(keys: Vec<ApiKeyConfig>) -> Services {
        let mut config = Config::default();
        config.auth.api_keys = keys;
        Services {
            live: Arc::new(LiveConfig::new(config)),
            #[cfg(feature = "firewall")]
            firewall: None,
            audit: None,
            #[cfg(feature = "cost-governance")]
            budget: None,
        }
    }

    fn presented(name: &str, secret: &str) -> ApiKeyRef {
        ApiKeyRef {
            name: name.to_owned(),
            principal: crate::gateway::auth::principal_of(secret),
        }
    }

    #[test]
    fn the_live_key_must_match_by_secret_be_unexpired_and_grant_the_backend() {
        let alice = presented("alice", "s1");
        assert!(services(vec![key("alice", "s1", None)]).admits(Some(&alice), "x"));
        assert!(
            !services(vec![key("alice", "s1", None)]).admits(Some(&alice), "y"),
            "backend not granted"
        );
        assert!(
            !services(vec![key("alice", "s2", None)]).admits(Some(&alice), "x"),
            "replaced under the same name"
        );
        let past = chrono::Utc::now() - chrono::Duration::seconds(1);
        assert!(
            !services(vec![key("alice", "s1", Some(past))]).admits(Some(&alice), "x"),
            "expired"
        );
        assert!(!services(Vec::new()).admits(Some(&alice), "x"), "removed");
        assert!(
            services(Vec::new()).admits(None, "x"),
            "no API key to re-read"
        );
    }

    #[test]
    fn a_subscription_stored_with_a_bare_key_name_is_refused() {
        let stored = serde_json::json!({
            "v": 1, "id": "s", "principal": "p", "api_key_name": "alice",
            "url": "https://h/x", "name": "e", "arguments": {}, "secret": "whsec_x",
            "previous_secret": null, "previous_until": null,
            "granted_at": "2026-10-01T00:00:00Z", "expires_at": null, "active": true,
            "failed_since": null, "last_delivery_at": null, "last_error": null
        });
        let sub: Subscription = serde_json::from_value(stored).expect("loads");
        let live = services(vec![key("alice", "s1", None)]);
        assert!(!live.admits_subscription(&sub, "x"));
        let rewritten = serde_json::to_value(&sub).expect("serialises");
        assert!(
            rewritten.get("api_key_name").is_none(),
            "never written back"
        );
    }
}
