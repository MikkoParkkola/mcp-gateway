// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway controls every event payload passes (design §3.6-3.7): the
//! live access re-check, the response firewall, tenant attribution, the
//! budget and the attributed audit record. Handed over once at startup.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::records::{ApiKeyRef, LiveBinding, Subscription};
use crate::config_reload::LiveConfig;
use crate::security::TransparencyLogger;

/// What the hub borrows from the rest of the gateway.
pub(crate) struct Services {
    /// The published config: API-key scopes are re-read from it per check.
    pub live: Arc<LiveConfig>,
    #[cfg(feature = "firewall")]
    pub firewall: Option<Arc<crate::security::firewall::Firewall>>,
    pub audit: Option<Arc<TransparencyLogger>>,
    /// The provenance signer, when stamping is on.
    pub provenance: Option<Arc<crate::attestation::BnautAttestationSigner>>,
    #[cfg(feature = "cost-governance")]
    pub budget: Option<(
        Arc<crate::cost_accounting::enforcer::BudgetEnforcer>,
        Arc<crate::cost_accounting::registry::CostRegistry>,
    )>,
    /// What the credentials that are not API keys are re-checked against.
    pub credentials: LiveCredentials,
}

/// The live authorities behind the credentials that are not API keys (design
/// F9, MIK-7769). The key server and the static bearer are fixed at startup
/// (`key_server` is a restart-required section), exactly as the request path
/// sees them.
#[derive(Default)]
pub(crate) struct LiveCredentials {
    pub key_server: Option<Arc<crate::key_server::KeyServer>>,
    /// `principal_of` the resolved static bearer, when one is configured.
    pub bearer_principal: Option<String>,
    /// The SHA-256 of the resolved static bearer (the full digest the
    /// re-check compares; the principal above is only a log fingerprint).
    pub bearer_sha256: Option<String>,
    pub dashboard: Option<Arc<crate::gateway::auth::DashboardBootstrap>>,
}

impl LiveCredentials {
    /// The static-bearer pair for the running bearer: the log fingerprint and
    /// the full digest the re-check compares.
    pub(crate) fn static_bearer(bearer: Option<&str>) -> (Option<String>, Option<String>) {
        (
            bearer.map(crate::gateway::auth::principal_of),
            bearer.map(|token| crate::hashing::sha256_hex(token.as_bytes())),
        )
    }
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
#[cfg_attr(
    not(feature = "firewall"),
    allow(dead_code, reason = "only the firewall reads the labels")
)]
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
        self.admits_grant(key, Some(backend))
    }

    /// As [`Self::admits`]; `None` asks only that the key be live, for
    /// owner-scoped events that need no backend grant.
    fn admits_grant(&self, key: Option<&ApiKeyRef>, backend: Option<&str>) -> bool {
        let Some(key) = key else {
            return true;
        };
        self.live
            .get()
            .auth
            .api_keys
            .iter()
            .find(|k| k.name == key.name)
            .filter(|k| !k.is_expired_now())
            .filter(|k| {
                k.key_sha256
                    .as_deref()
                    .and_then(crate::config::parse_api_key_digest)
                    .is_some_and(|digest| hex::encode(&digest[..6]) == key.principal)
            })
            .is_some_and(|k| {
                backend.is_none_or(|backend| k.backends.iter().any(|b| b == "*" || b == backend))
            })
    }

    /// Whether stored subscription `sub` may still receive an event of
    /// `backend`: the check fan-out and every delivery attempt run. An API
    /// key is re-read from live config; any other credential must still be
    /// live where it was issued (design F9). A row stored before keys were
    /// bound to their secret, or a bound kind without its binding, is
    /// refused.
    pub(crate) async fn admits_subscription(
        &self,
        sub: &Subscription,
        backend: Option<&str>,
    ) -> bool {
        use crate::security::audit::CredentialKind as Kind;
        match sub.credential_kind {
            None | Some(Kind::ApiKey) => {
                sub.legacy_api_key_name.is_none()
                    && sub.api_key.is_some()
                    && self.admits_grant(sub.api_key.as_ref(), backend)
            }
            // No credential was presented: authentication is off.
            Some(Kind::None | Kind::LocalTransport) => true,
            Some(kind) => match &sub.binding {
                // The binding must be the one this kind is re-checked by.
                Some(binding) if binding.kind() == kind => {
                    self.binding_live(binding, sub, backend).await
                }
                _ => false,
            },
        }
    }

    async fn binding_live(
        &self,
        binding: &LiveBinding,
        sub: &Subscription,
        backend: Option<&str>,
    ) -> bool {
        let credentials = &self.credentials;
        match binding {
            LiveBinding::KeyServerToken { jti } => match &credentials.key_server {
                Some(ks) => ks.store.live_jti(jti).await,
                None => false,
            },
            LiveBinding::OidcBearer {
                issuer,
                subject,
                email,
                groups,
                issued_at,
                provider_sha256,
            } => credentials.key_server.as_ref().is_some_and(|ks| {
                let identity = crate::key_server::oidc::VerifiedIdentity {
                    subject: subject.clone(),
                    email: email.clone(),
                    name: None,
                    groups: groups.clone(),
                    issuer: issuer.clone(),
                };
                // The provider must still accept what it accepted, and the
                // bearer must still be young enough for the running max age.
                let provider_same = provider_sha256.is_some()
                    && crate::gateway::auth::live::provider_fingerprint(ks, issuer)
                        == *provider_sha256;
                let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(u64::MAX);
                // The verifier requires `iat`, so a binding without one is
                // refused rather than exempt.
                let young = issued_at
                    .is_some_and(|iat| iat.saturating_add(ks.config.max_oidc_token_age_secs) > now);
                ks.config.delegated_bearer
                    && provider_same
                    && young
                    && ks
                        .policy
                        .resolve_scopes(
                            &identity,
                            &crate::key_server::policy::RequestedScopes::default(),
                        )
                        .is_ok_and(|scopes| {
                            backend.is_none_or(|backend| {
                                scopes.backends.iter().any(|b| b == "*" || b == backend)
                            })
                        })
            }),
            // A row from before the digest was kept: the log fingerprint is all it has.
            LiveBinding::StaticBearer => credentials
                .bearer_principal
                .as_deref()
                .is_some_and(|live| sub.credential_principal.as_deref() == Some(live)),
            LiveBinding::StaticBearerSha256 { bearer_sha256 } => {
                use subtle::ConstantTimeEq as _;
                credentials
                    .bearer_sha256
                    .as_deref()
                    .is_some_and(|live| live.as_bytes().ct_eq(bearer_sha256.as_bytes()).into())
            }
            LiveBinding::DashboardSession { session_sha256 } => {
                credentials.dashboard.as_ref().is_some_and(|dashboard| {
                    let limits = crate::gateway::auth::SessionLimits::from(
                        &self.live.get().auth.dashboard_session,
                    );
                    dashboard.live_digest(
                        session_sha256,
                        crate::gateway::auth::Now::read(),
                        &limits,
                    )
                })
            }
        }
    }

    /// The provenance receipt for one occurrence, as `_meta` carries it:
    /// signed when stamping is on, the bare receipt otherwise (§3.6).
    pub(crate) fn provenance(&self, backend: &str, name: &str) -> Value {
        let receipt = crate::trust::RuntimeProvenanceReceipt::event(
            backend,
            name,
            chrono::Utc::now().to_rfc3339(),
        );
        match &self.provenance {
            Some(signer) => serde_json::to_value(receipt.sign(signer)),
            None => serde_json::to_value(json!({ "receipt": receipt })),
        }
        .unwrap_or(Value::Null)
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
            subject: None,
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

    /// The firewall the read verdict judges deliveries on: the gateway's own,
    /// so an event shares the caller's read history with its answers.
    #[cfg_attr(
        not(feature = "firewall"),
        allow(clippy::unused_self, reason = "only the firewall build reads self")
    )]
    pub(crate) fn guard(&self) -> Option<&crate::gateway::outbound::Guard> {
        #[cfg(feature = "firewall")]
        {
            self.firewall.as_deref()
        }
        #[cfg(not(feature = "firewall"))]
        {
            None
        }
    }

    /// The `arg_keys` an attribution is taken under now.
    pub(crate) fn attribution_keys(&self) -> Vec<String> {
        crate::gateway::outbound::attribution_keys(self.guard())
    }

    /// What `data` names before the event firewall redacts it (MIN.2 E1);
    /// `None` when the verdict is off.
    pub(crate) fn attribute(
        &self,
        data: &Value,
    ) -> Option<crate::security::tenant_reads::ReadAttribution> {
        crate::gateway::outbound::raw_attribution(self.guard(), data)
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
            // Spent and released in one step (MIK-7903).
            enforcer.settle(verdict.hold.as_deref(), &tool, key, verdict.cost_usd);
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

/// The status of the record written before a POST (SAFETY.2): the attempt is
/// on record before its bytes leave; its outcome follows as its own record.
pub(crate) const SENDING: &str = "sending";

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
    pub credential_principal: Option<&'a str>,
    pub tenants: &'a [String],
    pub callback_host: &'a str,
    pub status: &'a str,
    /// SHA-256 of the body on the wire; empty when the attempt ended before
    /// a body was built (no body was sent).
    pub body_sha256: &'a str,
    /// What the firewall decided about the payload at fan-out: `pass`,
    /// `redacted`, `block`, `none`, or `unrecorded` for a record written
    /// before fan-out stamped it.
    pub firewall: &'a str,
    pub delivered: bool,
    /// The read verdict on this delivery (MIN.2), when it had one.
    pub cross_tenant_read: Option<crate::security::tenant_reads::ReadVerdict>,
}

impl Services {
    /// Write one MIN.1 attributed record for `attempt`, on the bounded
    /// blocking pool.
    ///
    /// # Errors
    ///
    /// The log's refusal. A caller about to send writes this record first
    /// and does not send when it fails (SAFETY.2).
    pub(crate) async fn audit_attempt(&self, attempt: &Attempt<'_>) -> std::io::Result<()> {
        use crate::security::audit::{
            AuditEnvelope, AuditOutcome, AuditWho, InvocationRoute, InvocationTarget,
        };
        use crate::security::transparency_log::{CorrelationKey, CorrelationSource};
        // No logger means no record, and so no POST (MIK-7802): delivery
        // needs the audit trail it promises.
        let Some(log) = &self.audit else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no audit log",
            ));
        };
        let mut extra = Map::new();
        extra.insert("subscription_id".into(), attempt.subscription_id.into());
        extra.insert("event_id".into(), attempt.event_id.into());
        extra.insert("attempt".into(), attempt.number.into());
        extra.insert("principal".into(), attempt.principal.into());
        extra.insert("callback_host".into(), attempt.callback_host.into());
        extra.insert("status".into(), attempt.status.into());
        extra.insert("body_sha256".into(), attempt.body_sha256.into());
        extra.insert("firewall_verdict".into(), attempt.firewall.into());
        // Present even when empty: the record says it was attributed.
        extra.insert("tenants".into(), json!(attempt.tenants));
        let envelope = AuditEnvelope {
            trace_id: None,
            otel_trace_id: None,
            outcome: if attempt.delivered || attempt.status == SENDING {
                AuditOutcome::Ok
            } else {
                AuditOutcome::Error(-32015)
            },
            who: AuditWho::from_parts(
                attempt.credential_kind,
                attempt.credential_principal,
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
        if let Err(error) = &written {
            tracing::warn!(%error, "events: delivery audit record not written");
        }
        written
    }

    /// How an attempt already recorded as [`SENDING`] ended. Best effort: the
    /// attempt itself is on record, and the POST has been made.
    pub(crate) async fn audit_outcome(&self, attempt: &Attempt<'_>) {
        let Some(log) = &self.audit else {
            return;
        };
        let mut fields = Map::new();
        fields.insert("action".into(), "events.delivery_outcome".into());
        fields.insert("timestamp".into(), chrono::Utc::now().to_rfc3339().into());
        fields.insert("event_id".into(), attempt.event_id.into());
        fields.insert("subscription_id".into(), attempt.subscription_id.into());
        fields.insert("outcome_of_attempt".into(), attempt.number.into());
        fields.insert("status".into(), attempt.status.into());
        fields.insert("delivered".into(), attempt.delivered.into());
        if let Some(verdict) = attempt.cross_tenant_read {
            fields.insert("cross_tenant_read".into(), json!(verdict));
        }
        let envelope = crate::security::audit::AuditEnvelope {
            outcome: if attempt.delivered {
                crate::security::audit::AuditOutcome::Ok
            } else {
                crate::security::audit::AuditOutcome::Error(-32015)
            },
            ..crate::security::audit::AuditEnvelope::gateway()
        };
        let written = log
            .append_bounded(move |log| log.append_event(fields, &envelope).map(|_| ()))
            .await;
        if let Err(error) = written {
            tracing::warn!(%error, "events: delivery outcome audit record not written");
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
#[path = "services_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "services_audit_tests.rs"]
mod audit_tests;
