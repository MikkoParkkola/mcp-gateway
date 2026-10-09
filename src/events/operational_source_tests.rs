// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway operational events (event-sources design §7: U5-U7).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::super::fanout::SourceEvent;
use super::super::{EventSource, EventsHub, LiveCredentials, Services};
use super::*;
use crate::config::{ApiKeyConfig, ApiKeyKind, Config, api_key_digest_spec};
use crate::config_reload::LiveConfig;

fn key(name: &str, secret: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: name.to_owned(),
        rate_limit: 0,
        backends: vec!["*".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        kind: ApiKeyKind::Shared,
    }
}

fn config(keys: Vec<ApiKeyConfig>) -> Config {
    let mut config = Config::default();
    config.auth.api_keys = keys;
    config
}

/// An admin `ops` and a non-admin `dev`.
fn keys(ops_admin: bool) -> Vec<ApiKeyConfig> {
    vec![key("ops", "s-ops", ops_admin), key("dev", "s-dev", false)]
}

fn principal(secret: &str) -> String {
    crate::gateway::auth::principal_of(secret)
}

/// A hub whose controls read `keys` from a live config the test can swap.
fn hub(dir: &std::path::Path, keys: Vec<ApiKeyConfig>) -> (Arc<EventsHub>, Arc<LiveConfig>) {
    hub_with(dir, keys, LiveCredentials::default())
}

/// [`hub`], with the given static credentials.
fn hub_with(
    dir: &std::path::Path,
    keys: Vec<ApiKeyConfig>,
    credentials: LiveCredentials,
) -> (Arc<EventsHub>, Arc<LiveConfig>) {
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir).expect("hub");
    let live = Arc::new(LiveConfig::new(config(keys)));
    let services = Services {
        live: Arc::clone(&live),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials,
    };
    let _ = hub.runtime.services.set(Arc::new(services));
    (hub, live)
}

fn source(hub: &Arc<EventsHub>) -> OperationalSource {
    OperationalSource {
        hub: Arc::downgrade(hub),
    }
}

fn event(name: &str, data: Value) -> SourceEvent {
    SourceEvent {
        kind: SourceKind::GatewayOperational,
        name: name.into(),
        backend: "gateway".into(),
        scope: Visibility::Owner,
        owner: None,
        upstream_id: "u".into(),
        occurred_at: Utc::now(),
        data,
        lifecycle_key: None,
    }
}

fn drained(hub: &EventsHub) -> Vec<(String, Value)> {
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    std::iter::from_fn(|| intake.try_recv().ok())
        .map(|e| (e.name, e.data))
        .collect()
}

/// U5: an admin holds all four; a non-admin holds only budget events and
/// receives only its own key's; a demoted admin loses the rest at once.
#[tokio::test]
async fn operational_events_are_operator_only_except_own_budget() {
    let dir = tempfile::tempdir().expect("dir");
    let (hub, live) = hub(dir.path(), keys(true));
    let source = source(&hub);
    let operator: Vec<String> = source
        .descriptors()
        .into_iter()
        .filter(|d| matches!(d.scope, Visibility::Operator))
        .map(|d| d.name)
        .collect();
    assert_eq!(operator, [HEALTH_CHANGED, KILL_SWITCH_CHANGED]);
    let (ops, dev, stranger) = (principal("s-ops"), principal("s-dev"), principal("x"));
    let none = json!({});
    for name in [HEALTH_CHANGED, KILL_SWITCH_CHANGED] {
        source.authorize(&ops, name, &none).await.expect("admin");
        let refused = source.authorize(&dev, name, &none).await;
        assert_eq!(refused.expect_err("non-admin").code, -32012, "{name}");
    }
    // A budget subscription names its scope; without one it covers every
    // scope, which needs admin standing, re-checked at every delivery.
    let (own, other) = (json!({"scope": "key:dev"}), json!({"scope": "key:ops"}));
    for name in [BUDGET_THRESHOLD, BUDGET_EXHAUSTED] {
        source.authorize(&dev, name, &own).await.expect("own key");
        source
            .authorize(&ops, name, &none)
            .await
            .expect("admin, all");
        source
            .authorize(&ops, name, &own)
            .await
            .expect("admin, any");
        for (who, args) in [(&dev, &none), (&dev, &other), (&stranger, &own)] {
            let refused = source.authorize(who, name, args).await;
            assert_eq!(refused.expect_err("refused").code, -32012, "{name} {args}");
        }
    }
    let budget = |scope: &str| event(BUDGET_THRESHOLD, json!({"scope": scope, "percent": 50}));
    assert!(source.matches(&dev, &own, &budget("key:dev")));
    assert!(!source.matches(&dev, &own, &budget("key:ops")));
    assert!(!source.matches(&dev, &own, &budget("global")));
    assert!(source.matches(&ops, &none, &budget("global")));
    live.set(config(keys(false)));
    for (name, args) in [
        (KILL_SWITCH_CHANGED, &none),
        (BUDGET_THRESHOLD, &none),
        (BUDGET_THRESHOLD, &own),
    ] {
        let refused = source.authorize(&ops, name, args).await;
        assert_eq!(refused.expect_err("demoted").code, -32012, "{name} {args}");
    }
}

/// U6: budget deliveries are exempt from the delivery charge; the rest are
/// charged as usual.
#[test]
fn budget_events_are_not_charged_to_the_budget_they_report() {
    let source = OperationalSource {
        hub: std::sync::Weak::new(),
    };
    assert!(!source.charges(BUDGET_THRESHOLD));
    assert!(!source.charges(BUDGET_EXHAUSTED));
    assert!(source.charges(HEALTH_CHANGED));
    assert!(source.charges(KILL_SWITCH_CHANGED));
}

/// U7: a kill and a revive are two events (a repeat kill is none), and a
/// tripped breaker on a registered backend's shared slot is one.
#[tokio::test]
async fn health_and_kill_switch_transitions_become_events() {
    let dir = tempfile::tempdir().expect("dir");
    let (hub, _) = hub(dir.path(), Vec::new());
    let kill = crate::kill_switch::KillSwitch::new();
    let backends = crate::backend::BackendRegistry::new();
    hub.install_operational_source(&kill, &backends);
    kill.kill("alpha");
    kill.kill("alpha");
    kill.revive("alpha");
    let backend = Arc::new(crate::backend::Backend::new(
        "beta",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    assert!(backends.register(Arc::clone(&backend)));
    backend.trip_circuit_breaker("test");
    assert_eq!(
        drained(&hub),
        [
            (
                KILL_SWITCH_CHANGED.to_owned(),
                json!({"backend": "alpha", "state": "killed"})
            ),
            (
                KILL_SWITCH_CHANGED.to_owned(),
                json!({"backend": "alpha", "state": "live"})
            ),
            (
                HEALTH_CHANGED.to_owned(),
                json!({"backend": "beta", "from": "closed", "to": "open"})
            ),
        ]
    );
}

/// The budget hook end to end: one spend that uses up `dev`'s budget is
/// three threshold events and one exhaustion, all scoped to `key:dev`.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_spent_budget_becomes_threshold_and_exhaustion_events() {
    use crate::cost_accounting::{
        config::CostGovernanceConfig, enforcer::BudgetEnforcer, registry::CostRegistry,
    };
    let dir = tempfile::tempdir().expect("dir");
    let (hub, _) = hub(dir.path(), Vec::new());
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.budgets.per_key.insert("dev".into(), 1.0);
    let enforcer = BudgetEnforcer::new(cfg.clone(), Arc::new(CostRegistry::new(&cfg)));
    let source = hub.install_operational_source(
        &crate::kill_switch::KillSwitch::new(),
        &crate::backend::BackendRegistry::new(),
    );
    source.report_budgets(&enforcer);
    enforcer.record_spend("search", Some("dev"), 1.0);
    let threshold = |p: u8| {
        (
            BUDGET_THRESHOLD.to_owned(),
            json!({"scope": "key:dev", "percent": p}),
        )
    };
    assert_eq!(
        drained(&hub),
        [
            threshold(50),
            threshold(80),
            threshold(100),
            (BUDGET_EXHAUSTED.to_owned(), json!({"scope": "key:dev"})),
        ]
    );
}

/// Admit a live API-key subscription to `name` for the key `key`/`secret`.
fn admit(hub: &EventsHub, key: &str, secret: &str, name: &str) {
    let principal = principal(secret);
    let row: super::super::records::Subscription = serde_json::from_value(json!({
        "v": 1, "principal": principal, "id": format!("sub_{key}"),
        "url": format!("https://h/{key}"), "name": name, "arguments": {},
        "secret": "whsec_x", "previous_secret": null, "previous_until": null,
        "granted_at": Utc::now(), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null,
        "api_key": {"name": key, "principal": principal},
        "credential_kind": serde_json::to_value(crate::security::audit::CredentialKind::ApiKey)
            .expect("kind"),
    }))
    .expect("row");
    let config = crate::config::EventsConfig::default();
    hub.store
        .admit(
            row,
            true,
            super::super::store::Caps {
                per_principal: 100,
                global: 100,
            },
            chrono::Duration::zero(),
            Utc::now(),
            super::super::tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
}

/// Lead condition (2): at fan-out a non-admin's subscription to an operator
/// event ends unoffered, and an admin demoted after subscribing loses it too.
#[tokio::test]
async fn a_non_admin_never_receives_an_operator_event() {
    let dir = tempfile::tempdir().expect("dir");
    let (hub, live) = hub(dir.path(), keys(true));
    hub.install_operational_source(
        &crate::kill_switch::KillSwitch::new(),
        &crate::backend::BackendRegistry::new(),
    );
    admit(&hub, "ops", "s-ops", KILL_SWITCH_CHANGED);
    admit(&hub, "dev", "s-dev", KILL_SWITCH_CHANGED);
    let services = hub.runtime.services.get().cloned().expect("services");
    let killed = || {
        let mut e = event(
            KILL_SWITCH_CHANGED,
            json!({"backend": "a", "state": "killed"}),
        );
        e.scope = Visibility::Operator;
        e
    };
    hub.fan_out(&services, &killed()).await;
    let holders: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.principal)
        .collect();
    assert_eq!(
        holders,
        [principal("s-ops")],
        "the non-admin's subscription ended"
    );
    live.set(config(keys(false)));
    hub.fan_out(&services, &killed()).await;
    assert!(
        hub.store.subscriptions().is_empty(),
        "the demoted admin's ended too"
    );
}

/// A key whose digest shares `secret`'s first 48 bits (its principal) and
/// differs after them: the collision MIK-7973 refuses at load, built here
/// directly so the check below cannot rely on that refusal.
fn twin_of(secret: &str, name: &str, admin: bool) -> ApiKeyConfig {
    let spec = api_key_digest_spec(secret.as_bytes());
    let (head, tail) = spec.split_at("sha256:".len() + 12);
    let flipped: String = tail
        .chars()
        .map(|c| if c == '0' { '1' } else { '0' })
        .collect();
    ApiKeyConfig {
        key_sha256: Some(format!("{head}{flipped}")),
        ..key(name, secret, admin)
    }
}

/// `MIK-8062.PREFIX.1`: when two unexpired keys share a principal, the
/// standing is ambiguous, so it fails closed: no standing for either name,
/// whichever key is configured first.
#[test]
fn a_principal_two_live_keys_share_has_no_standing() {
    // GIVEN: dev, and an admin key whose digest shares dev's first 48 bits
    for twin_first in [false, true] {
        let mut keys = vec![key("dev", "s-dev", false), twin_of("s-dev", "twin", true)];
        if twin_first {
            keys.reverse();
        }
        let dir = tempfile::tempdir().expect("dir");
        let (hub, _live) = hub(dir.path(), keys);
        // WHEN: the shared principal's standing is read
        let standing = source(&hub).standing(&principal("s-dev"));
        // THEN: it has none, so it is neither admin nor either key's holder
        assert!(
            standing.is_none(),
            "twin first {twin_first}: an ambiguous principal resolved to {:?}",
            standing.map(|s| (s.admin, s.key))
        );
    }
}

/// `MIK-8062.PREFIX.1`: a key whose principal is also the static bearer's is
/// just as ambiguous, so it gets neither the bearer's admin standing nor the
/// key's.
#[test]
fn a_principal_the_bearer_and_a_key_share_has_no_standing() {
    let credentials = LiveCredentials {
        bearer_principal: Some(principal("s-dev")),
        ..LiveCredentials::default()
    };
    let dir = tempfile::tempdir().expect("dir");
    let (hub, _live) = hub_with(dir.path(), vec![key("dev", "s-dev", false)], credentials);
    let standing = source(&hub).standing(&principal("s-dev"));
    assert!(
        standing.is_none(),
        "a key sharing the bearer's principal resolved to {:?}",
        standing.map(|s| (s.admin, s.key))
    );
}

/// `MIK-8062.PREFIX.2`: a principal only one unexpired key derives keeps
/// that key's standing, also when an expired key shares the principal.
#[test]
fn a_principal_one_live_key_derives_keeps_its_standing() {
    let mut twin = twin_of("s-dev", "twin", true);
    twin.expires_at = Some(Utc::now() - crate::duration_bound::delta!(hours, 1));
    for keys in [
        vec![key("dev", "s-dev", false)],
        vec![key("dev", "s-dev", false), twin.clone()],
        vec![twin, key("dev", "s-dev", false)],
    ] {
        let dir = tempfile::tempdir().expect("dir");
        let (hub, _live) = hub(dir.path(), keys);
        let standing = source(&hub).standing(&principal("s-dev"));
        let (admin, name) = standing
            .map(|s| (s.admin, s.key))
            .expect("dev has standing");
        assert!(!admin);
        assert_eq!(name.as_deref(), Some("dev"));
    }
}

/// `MIK-8062.PREFIX.2`: the static bearer alone keeps its admin standing, also
/// beside an expired key that shares its principal.
#[test]
fn the_bearer_alone_keeps_its_admin_standing() {
    let mut expired = key("dev", "s-dev", false);
    expired.expires_at = Some(Utc::now() - crate::duration_bound::delta!(hours, 1));
    for keys in [vec![], vec![expired]] {
        let credentials = LiveCredentials {
            bearer_principal: Some(principal("s-dev")),
            ..LiveCredentials::default()
        };
        let dir = tempfile::tempdir().expect("dir");
        let (hub, _live) = hub_with(dir.path(), keys, credentials);
        let standing = source(&hub).standing(&principal("s-dev"));
        let (admin, name) = standing
            .map(|s| (s.admin, s.key))
            .expect("the bearer has standing");
        assert!(admin, "the bearer is an admin");
        assert!(name.is_none(), "the bearer holds no key");
    }
}
