// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway operational events (event-sources design §3, MIK-7720): budget
//! thresholds and exhaustion, backend health and the kill switch, each
//! emitted by the producer that made the change through one observer hook.
//!
//! Health and kill-switch events reveal backend topology, so they reach
//! admins only. A budget event reaches admins, and the holder of the API key
//! whose budget it reports (`key:<name>`); a caller without an API key has no
//! budget of its own. Standing is read from the live config at every check,
//! so a key demoted or removed after subscribing stops receiving. Health is
//! reported for each backend's shared slot, not for per-user slots. Budget
//! deliveries are not charged, so exhausting a budget never charges the event
//! that reports it.

use std::sync::{Arc, Weak};

use chrono::Utc;
use serde_json::{Value, json};

use super::fanout::SourceEvent;
use super::types::{EventDescriptor, RpcError, SourceKind, Visibility};
use super::{EventSource, EventsHub, Services};

pub(crate) const BUDGET_THRESHOLD: &str = "gateway.budget.threshold";
pub(crate) const BUDGET_EXHAUSTED: &str = "gateway.budget.exhausted";
pub(crate) const HEALTH_CHANGED: &str = "gateway.backend.health_changed";
pub(crate) const KILL_SWITCH_CHANGED: &str = "gateway.kill_switch.changed";
const BUDGET_PREFIX: &str = "gateway.budget.";

/// Who a principal is now, by the live config.
struct Standing {
    admin: bool,
    /// The name of the API key it presents, whose budget is its own.
    key: Option<String>,
}

/// The live standing of `principal`: the static bearer (an admin), or the
/// one unexpired API key whose digest derives it. `None` for anyone else, and
/// whenever more than one of those credentials derives it: an ambiguous
/// principal fails closed rather than taking whichever matched first
/// (MIK-8062).
fn standing(services: &Services, principal: &str) -> Option<Standing> {
    let bearer = services.credentials.bearer_principal.as_deref() == Some(principal);
    let now = Utc::now();
    let config = services.live.get();
    let mut keys = config.auth.api_keys.iter().filter(|k| {
        !k.is_expired_at(now)
            && k.key_sha256
                .as_deref()
                .and_then(crate::config::parse_api_key_digest)
                .is_some_and(|digest| {
                    crate::gateway::auth::principal_of_digest(&digest) == principal
                })
    });
    match (bearer, keys.next(), keys.next()) {
        (true, None, _) => Some(Standing {
            admin: true,
            key: None,
        }),
        (false, Some(key), None) => Some(Standing {
            admin: key.admin,
            key: Some(key.name.clone()),
        }),
        _ => None,
    }
}

/// The gateway operational events source.
pub(crate) struct OperationalSource {
    hub: Weak<EventsHub>,
}

impl OperationalSource {
    fn standing(&self, principal: &str) -> Option<Standing> {
        let hub = self.hub.upgrade()?;
        let services = hub.runtime.services.get()?;
        standing(services, principal)
    }

    /// Queue one occurrence; never blocks the producer.
    fn emit(&self, name: &str, backend: &str, scope: Visibility, data: Value) {
        let Some(hub) = self.hub.upgrade() else {
            return;
        };
        hub.emit(SourceEvent {
            kind: SourceKind::GatewayOperational,
            name: name.into(),
            backend: backend.into(),
            scope,
            owner: None,
            upstream_id: hex::encode(rand::random::<[u8; 16]>()),
            occurred_at: Utc::now(),
            data,
            lifecycle_key: None,
        });
    }
}

fn descriptor(
    name: &str,
    description: &str,
    payload: &Value,
    scope: Visibility,
) -> EventDescriptor {
    let arguments = if name.starts_with(BUDGET_PREFIX) {
        json!({"scope": {"type": "string"}})
    } else {
        json!({})
    };
    EventDescriptor {
        name: name.into(),
        description: description.into(),
        input_schema: json!({"type": "object", "properties": arguments, "additionalProperties": false}),
        payload_schema: json!({"type": "object", "properties": payload, "additionalProperties": false}),
        scope,
        kind: SourceKind::GatewayOperational,
    }
}

#[async_trait::async_trait]
impl EventSource for OperationalSource {
    fn kind(&self) -> SourceKind {
        SourceKind::GatewayOperational
    }

    fn descriptors(&self) -> Vec<EventDescriptor> {
        let text = || json!({"type": "string"});
        vec![
            descriptor(
                BUDGET_THRESHOLD,
                "A daily budget crossed 50, 80 or 100 %. `scope` is `global`, `tool:<name>` \
                 or `key:<API key name>`. Subscribe with `scope` to receive one budget; \
                 without it you receive every scope, which needs admin standing. Without \
                 admin standing, name your own key's.",
                &json!({"scope": text(), "percent": {"type": "integer"}}),
                Visibility::Owner,
            ),
            descriptor(
                BUDGET_EXHAUSTED,
                "A daily budget was used up. Same scopes and audience as the threshold event.",
                &json!({"scope": text()}),
                Visibility::Owner,
            ),
            descriptor(
                HEALTH_CHANGED,
                "A backend's circuit breaker changed state (closed, open, half_open). Admins only.",
                &json!({"backend": text(), "from": text(), "to": text()}),
                Visibility::Operator,
            ),
            descriptor(
                KILL_SWITCH_CHANGED,
                "A backend was killed or revived. Admins only.",
                &json!({"backend": text(), "state": {"enum": ["killed", "live"]}}),
                Visibility::Operator,
            ),
        ]
    }

    /// Admins hold any of the four. An API-key holder holds the budget
    /// events for its own key's scope, named in the arguments. Read live at
    /// subscribe, at every fan-out and before every delivery, so a refusal
    /// (`-32012`) ends the subscription; the scope travels with it, so a
    /// demoted admin's every-scope subscription ends before a queued event
    /// of another key's budget is sent.
    async fn authorize(
        &self,
        principal: &str,
        name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let Some(standing) = self.standing(principal) else {
            return Err(RpcError::forbidden());
        };
        let own = |key: &str| {
            arguments["scope"]
                .as_str()
                .and_then(|scope| scope.strip_prefix("key:"))
                == Some(key)
        };
        if standing.admin
            || (name.starts_with(BUDGET_PREFIX) && standing.key.as_deref().is_some_and(own))
        {
            Ok(())
        } else {
            Err(RpcError::forbidden())
        }
    }

    /// A budget event reaches the subscriptions to its scope, or to every
    /// scope; `authorize` decides who may hold either.
    fn matches(&self, _principal: &str, arguments: &Value, event: &SourceEvent) -> bool {
        if !event.name.starts_with(BUDGET_PREFIX) {
            return true;
        }
        arguments
            .get("scope")
            .and_then(Value::as_str)
            .is_none_or(|scope| event.data["scope"].as_str() == Some(scope))
    }

    fn charges(&self, name: &str) -> bool {
        !name.starts_with(BUDGET_PREFIX)
    }
}

impl EventsHub {
    /// Offer the operational events and attach the kill-switch and breaker
    /// hooks; budgets attach with [`OperationalSource::report_budgets`].
    pub(crate) fn install_operational_source(
        self: &Arc<Self>,
        kill_switch: &crate::kill_switch::KillSwitch,
        backends: &crate::backend::BackendRegistry,
    ) -> Arc<OperationalSource> {
        let source = Arc::new(OperationalSource {
            hub: Arc::downgrade(self),
        });
        self.register_source(Arc::clone(&source) as Arc<dyn EventSource>);
        let kills = Arc::clone(&source);
        kill_switch.observe(Arc::new(move |change: crate::kill_switch::KillChange| {
            let state = if change.killed { "killed" } else { "live" };
            kills.emit(
                KILL_SWITCH_CHANGED,
                &change.backend,
                Visibility::Operator,
                json!({"backend": change.backend, "state": state}),
            );
        }));
        let health = Arc::clone(&source);
        backends.observe_breakers(Arc::new(move |change: crate::failsafe::HealthChange| {
            health.emit(
                HEALTH_CHANGED,
                &change.backend,
                Visibility::Operator,
                json!({"backend": change.backend, "from": change.from, "to": change.to}),
            );
        }));
        source
    }
}

#[cfg(feature = "cost-governance")]
impl OperationalSource {
    /// Report `budget`'s threshold crossings; at 100 % also its exhaustion.
    pub(crate) fn report_budgets(
        self: &Arc<Self>,
        budget: &crate::cost_accounting::enforcer::BudgetEnforcer,
    ) {
        let source = Arc::clone(self);
        budget.observe(Arc::new(
            move |crossing: crate::cost_accounting::enforcer::crossings::BudgetCrossing| {
                source.emit(
                    BUDGET_THRESHOLD,
                    "gateway",
                    Visibility::Owner,
                    json!({"scope": crossing.scope, "percent": crossing.percent}),
                );
                if crossing.percent >= 100 {
                    source.emit(
                        BUDGET_EXHAUSTED,
                        "gateway",
                        Visibility::Owner,
                        json!({"scope": crossing.scope}),
                    );
                }
            },
        ));
    }
}

#[cfg(test)]
#[path = "operational_source_tests.rs"]
mod tests;
