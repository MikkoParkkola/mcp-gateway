// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7907, MIK-7921: what an attempt re-reads after its waits, and how often
//! it waits on a backend's catalogue.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::{
    EventsHub, audit_actions, counting_callback, descriptor, logged_services, queued_with,
};
use crate::config::{ApiKeyConfig, ApiKeyKind, Config, api_key_digest_spec};
use crate::events::records::ApiKeyRef;
use crate::events::types::{RpcError, SourceKind};

const SECRET: &str = "recheck-secret";

fn open_hub(dir: &std::path::Path) -> Arc<EventsHub> {
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        // Priced, so a charge would show in the budget's registry.
        cost_per_delivery_usd: 0.01,
        ..crate::config::EventsConfig::default()
    };
    EventsHub::open(&config, dir).expect("hub")
}

/// A config whose one API key grants backend `b`.
fn keyed() -> Config {
    let mut config = Config::default();
    config.auth.api_keys = vec![ApiKeyConfig {
        key: None,
        key_sha256: Some(api_key_digest_spec(SECRET.as_bytes())),
        expires_at: None,
        name: "k".to_owned(),
        rate_limit: 0,
        backends: vec!["b".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: ApiKeyKind::Shared,
    }];
    config
}

/// A source that admits every ask, and parks its second one until released:
/// the attempt's second verdict, after the records are written.
struct Parking {
    asked: AtomicUsize,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl crate::events::EventSource for Parking {
    fn kind(&self) -> SourceKind {
        SourceKind::RestWatch
    }
    fn descriptors(&self) -> Vec<crate::events::types::EventDescriptor> {
        vec![descriptor("probe.park", SourceKind::RestWatch)]
    }
    fn matches(
        &self,
        _principal: &str,
        _arguments: &serde_json::Value,
        _event: &crate::events::fanout::SourceEvent,
    ) -> bool {
        true
    }
    async fn authorize(&self, _p: &str, _n: &str, _a: &serde_json::Value) -> Result<(), RpcError> {
        if self.asked.fetch_add(1, Ordering::SeqCst) == 1 {
            self.reached.notify_one();
            self.release.notified().await;
        }
        Ok(())
    }
}

/// MIK-7907 WINDOW.2: the subscription's API key loses its grant while the
/// attempt waits on its second source verdict. Access is read again after
/// that wait, so nothing is sent and the attempt ends `access_revoked`. The
/// control keeps the grant and is sent.
#[tokio::test]
async fn access_lost_during_the_second_verdict_is_not_sent() {
    for revoke in [false, true] {
        let dir = tempfile::tempdir().expect("dir");
        let hub = open_hub(dir.path());
        let source = Arc::new(Parking {
            asked: AtomicUsize::new(0),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        hub.register_source(Arc::clone(&source) as Arc<dyn crate::events::EventSource>);
        #[allow(unused_mut, reason = "set only with cost-governance")]
        let mut services = logged_services(dir.path());
        #[cfg(feature = "cost-governance")]
        let registry = super::budgeted(&mut services);
        services.live.set(keyed());
        let (port, accepted) = counting_callback().await;
        queued_with(&hub, port, "evt_key", "probe.park", |sub, _| {
            sub.credential_kind = Some(crate::security::audit::CredentialKind::ApiKey);
            sub.api_key = Some(ApiKeyRef {
                name: "k".to_owned(),
                principal: crate::gateway::auth::principal_of(SECRET),
            });
        });
        let drive = async {
            source.reached.notified().await;
            if revoke {
                services.live.set(Config::default());
            }
            source.release.notify_one();
        };
        tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(hub.attempt(&services, "evt_key"), drive)
        })
        .await
        .expect("the attempt finished");
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(source.asked.load(Ordering::SeqCst), 2, "revoke {revoke}");
        assert_eq!(
            accepted.load(Ordering::SeqCst) >= 1,
            !revoke,
            "sent only while the grant stands (revoke {revoke})"
        );
        #[cfg(feature = "cost-governance")]
        assert_eq!(
            registry.snapshot().contains_key("events:probe.park"),
            !revoke,
            "charged only when sent (revoke {revoke})"
        );
        if revoke {
            let ended = audit_actions(dir.path(), "events.delivery_outcome");
            assert_eq!(ended.len(), 1, "{ended:?}");
            assert_eq!(ended[0]["status"], "access_revoked");
            assert!(
                hub.store.subscriptions().is_empty(),
                "the refused subscription is revoked"
            );
        }
    }
}

/// A backend that accepts connections and never answers, counting them; a
/// `BackendSource` whose listeners know it, registered on `hub`.
async fn silent_backend(hub: &Arc<EventsHub>) -> Arc<AtomicUsize> {
    use crate::backend::{Backend, BackendRegistry};
    use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
    use crate::events::backend_source::{BackendSource, Ineligible, Upstream};
    use crate::events::upstream_listener::UpstreamListeners;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&connections);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            held.push(stream);
        }
    });
    let registry = Arc::new(BackendRegistry::new());
    let config = BackendConfig {
        transport: TransportConfig::Http {
            http_url: format!("http://127.0.0.1:{port}/mcp"),
            streamable_http: Some(true),
            protocol_version: None,
        },
        timeout: Duration::from_secs(1),
        ..BackendConfig::default()
    };
    assert!(registry.register(Arc::new(Backend::new(
        "b",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))));
    let ineligible: Ineligible = Arc::new(std::collections::BTreeSet::new);
    hub.register_source(Arc::new(BackendSource {
        names: Arc::new(|| vec!["b".to_owned()]),
        upstream: Some(Upstream {
            listeners: UpstreamListeners::new(
                registry,
                std::sync::Weak::new(),
                Arc::clone(&ineligible),
            ),
            ineligible,
        }),
    }));
    connections
}

/// MIK-7921 WAIT.2: an attempt for a `resource_updated` subscription whose
/// backend never answers waits on its catalogue once, not once per verdict.
/// The baseline is one direct authorize against the same kind of backend.
#[tokio::test]
async fn an_attempt_waits_on_a_silent_catalogue_once() {
    const NAME: &str = "backend.b.resource_updated";
    let uri = serde_json::json!({"uri": "file:///a"});

    let dir = tempfile::tempdir().expect("dir");
    let probe = open_hub(dir.path());
    let once = silent_backend(&probe).await;
    let source = probe.source_offering(NAME).expect("offered");
    let _ = source.authorize("p", NAME, &uri).await;
    let one_lookup = once.load(Ordering::SeqCst);
    assert!(one_lookup >= 1, "the lookup reached the backend");

    let dir = tempfile::tempdir().expect("dir");
    let hub = open_hub(dir.path());
    let connections = silent_backend(&hub).await;
    let services = logged_services(dir.path());
    let (port, _accepted) = counting_callback().await;
    queued_with(&hub, port, "evt_silent", NAME, |sub, _| {
        sub.arguments = uri.clone();
    });
    tokio::time::timeout(
        Duration::from_secs(60),
        hub.attempt(&services, "evt_silent"),
    )
    .await
    .expect("the attempt finished");
    assert_eq!(
        connections.load(Ordering::SeqCst),
        one_lookup,
        "one catalogue lookup per attempt"
    );
}

/// MIK-7922: with the tenant-read guard on, `admit_delivery` writes its
/// `tenant_read` record before the second verdict; a source that refuses after
/// that record gets no POST, the attempt ends `access_revoked`, and the dropped
/// frame releases its read reservation.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_refusal_after_the_tenant_read_record_releases_the_frame() {
    use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
    use crate::security::firewall::{Firewall, FirewallConfig};

    let dir = tempfile::tempdir().expect("dir");
    let hub = open_hub(dir.path());
    let source = Arc::new(AfterTenantRecord {
        log: dir.path().join("audit.jsonl"),
        asked: AtomicUsize::new(0),
    });
    hub.register_source(Arc::clone(&source) as Arc<dyn crate::events::EventSource>);
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            tenant_guard: TenantGuardConfig {
                arg_keys: vec!["repo".to_owned()],
                cross_tenant_reads: CrossTenantReads::Observe,
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let reads = Arc::clone(firewall.reads());
    let mut services = logged_services(dir.path());
    services.firewall = Some(firewall);
    let (port, accepted) = counting_callback().await;
    queued_with(&hub, port, "evt_tenant", "probe.after", |sub, record| {
        sub.read_key = Some("k".to_owned());
        // {"data":{"repo":"t1"}}: a read the guard attributes to tenant t1.
        record.body_b64 = "eyJkYXRhIjp7InJlcG8iOiJ0MSJ9fQ==".to_owned();
    });
    let held_before = reads.tenants_held("k");
    tokio::time::timeout(
        Duration::from_secs(20),
        hub.attempt(&services, "evt_tenant"),
    )
    .await
    .expect("the attempt finished");
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(source.asked.load(Ordering::SeqCst), 2, "asked again");
    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
    assert!(
        log.contains("\"event\":\"tenant_read\""),
        "the tenant-read record was written before the refusal: {log}"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "no POST");
    let ended = audit_actions(dir.path(), "events.delivery_outcome");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["status"], "access_revoked");
    assert_eq!(
        reads.tenants_held("k").1,
        held_before.1,
        "the refused frame released its reservation"
    );
}

/// MIK-7921: the lookup budget belongs to one attempt. Inside one scope a
/// failed lookup is paid once; the next scope (the next attempt) reads the
/// catalogue again, and outside any scope (subscribe, fan-out) every call reads.
#[tokio::test]
async fn the_lookup_budget_is_per_attempt() {
    use crate::events::upstream_listener::FAILED_LOOKUP;
    const NAME: &str = "backend.b.resource_updated";
    let uri = serde_json::json!({"uri": "file:///a"});
    let dir = tempfile::tempdir().expect("dir");
    let hub = open_hub(dir.path());
    let connections = silent_backend(&hub).await;
    let source = hub.source_offering(NAME).expect("offered");
    let ask = || source.authorize("p", NAME, &uri);

    let _ = ask().await;
    let one = connections.load(Ordering::SeqCst);
    assert!(one >= 1, "the lookup reached the backend");
    let _ = ask().await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2 * one,
        "no scope: reads twice"
    );

    FAILED_LOOKUP
        .scope(std::cell::Cell::new(false), async {
            let _ = ask().await;
            let _ = ask().await;
        })
        .await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        3 * one,
        "one scope: reads once"
    );
    FAILED_LOOKUP
        .scope(std::cell::Cell::new(false), async {
            let _ = ask().await;
        })
        .await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        4 * one,
        "the next attempt reads again"
    );
}

/// Admits until the attempt's `tenant_read` record is in the audit log, then
/// refuses: a check made before `admit_delivery` wrote that record admits, so a
/// second verdict moved ahead of it would send (MIK-7922 TEST.3).
#[cfg(feature = "firewall")]
struct AfterTenantRecord {
    log: std::path::PathBuf,
    asked: AtomicUsize,
}

#[async_trait::async_trait]
#[cfg(feature = "firewall")]
impl crate::events::EventSource for AfterTenantRecord {
    fn kind(&self) -> SourceKind {
        SourceKind::RestWatch
    }
    fn descriptors(&self) -> Vec<crate::events::types::EventDescriptor> {
        vec![descriptor("probe.after", SourceKind::RestWatch)]
    }
    fn matches(
        &self,
        _principal: &str,
        _arguments: &serde_json::Value,
        _event: &crate::events::fanout::SourceEvent,
    ) -> bool {
        true
    }
    async fn authorize(&self, _p: &str, _n: &str, _a: &serde_json::Value) -> Result<(), RpcError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        if log.contains("\"event\":\"tenant_read\"") {
            Err(RpcError::forbidden())
        } else {
            Ok(())
        }
    }
}

/// MIK-8061 L15: the subscription expires while an attempt waits on its
/// second source verdict (a barrier, not a sleep). An expired row is kept for
/// its burials, so the signing row is still found; liveness is read again
/// after that wait, so nothing is sent and the claim settles unsent. The
/// control keeps the row live and is sent.
#[tokio::test]
async fn a_subscription_expiring_during_the_second_verdict_is_not_sent() {
    for expire in [false, true] {
        let dir = tempfile::tempdir().expect("dir");
        let hub = open_hub(dir.path());
        let source = Arc::new(Parking {
            asked: AtomicUsize::new(0),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        hub.register_source(Arc::clone(&source) as Arc<dyn crate::events::EventSource>);
        let services = logged_services(dir.path());
        let (port, accepted) = counting_callback().await;
        queued_with(&hub, port, "evt_exp", "probe.park", |_, _| {});
        let drive = async {
            source.reached.notified().await;
            if expire {
                let now = chrono::Utc::now();
                let mut row = hub.store.subscriptions().remove(0);
                row.expires_at = Some(now - crate::duration_bound::delta!(seconds, 1));
                let caps = crate::events::store::Caps {
                    per_principal: 10,
                    global: 10,
                };
                let tail = crate::events::store::TailPolicy {
                    ttl: Duration::from_secs(3600),
                    max: 10,
                    max_per_principal: 10,
                };
                hub.store
                    .admit(row, true, caps, chrono::Duration::zero(), now, tail)
                    .expect("io")
                    .expect("refreshed to an expiry in the past");
            }
            source.release.notify_one();
        };
        tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(hub.attempt(&services, "evt_exp"), drive)
        })
        .await
        .expect("the attempt finished");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(source.asked.load(Ordering::SeqCst), 2, "expire {expire}");
        assert_eq!(
            accepted.load(Ordering::SeqCst) >= 1,
            !expire,
            "sent only while the subscription is live (expire {expire})"
        );
        if expire {
            assert!(
                hub.store
                    .subscriptions()
                    .iter()
                    .any(|s| hub.store.has_due(&s.id, chrono::Utc::now())),
                "the claim settled unsent: pending again for the expiry pass"
            );
        }
    }
}

#[path = "worker_admission_tests.rs"]
mod admission;
#[path = "worker_detect_gate_tests.rs"]
mod detect_gate;
