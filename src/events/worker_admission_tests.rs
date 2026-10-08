// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7907 `WINDOW.1`: a reload that makes a backend ineligible after an
//! attempt's checks and before its send does not deliver that attempt's
//! event. The attempt stops at its last step before the send; a reload runs
//! and returns; then the attempt resumes.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::super::{counting_callback, descriptor, logged_services, queued_with};
use crate::config::{ApiKeyConfig, ApiKeyKind, BackendConfig, Config, api_key_digest_spec};
use crate::config_reload::LiveConfig;
use crate::events::records::ApiKeyRef;
use crate::events::types::{RpcError, SourceKind};
use crate::events::{EventSource, EventsHub};

const SECRET: &str = "admission-secret";

/// A config whose one API key grants backend `g`, with `g` configured or not.
fn config(with_backend: bool) -> Config {
    let mut config = Config::default();
    config.auth.api_keys = vec![ApiKeyConfig {
        key: None,
        key_sha256: Some(api_key_digest_spec(SECRET.as_bytes())),
        expires_at: None,
        name: "k".to_owned(),
        rate_limit: 0,
        backends: vec!["g".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: ApiKeyKind::Shared,
    }];
    if with_backend {
        config
            .backends
            .insert("g".to_owned(), BackendConfig::default());
    }
    config
}

/// A source whose events need backend `g` in the live config, as a backend
/// source's need their backend eligible.
struct Gated {
    live: Arc<LiveConfig>,
    asked: AtomicUsize,
}

impl Gated {
    fn eligible(&self) -> bool {
        self.live.get().backends.contains_key("g")
    }
}

#[async_trait::async_trait]
impl EventSource for Gated {
    fn kind(&self) -> SourceKind {
        SourceKind::RestWatch
    }
    fn descriptors(&self) -> Vec<crate::events::types::EventDescriptor> {
        vec![descriptor("probe.gate", SourceKind::RestWatch)]
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
        if self.eligible() {
            Ok(())
        } else {
            Err(RpcError::forbidden())
        }
    }
    fn admits_now(&self, _name: &str) -> bool {
        self.eligible()
    }
}

/// One attempt of a queued `probe.gate` event, paused just before its send
/// while a reload publishes `after` and returns; the posts its callback got.
async fn attempt_across_a_reload(after: Config) -> usize {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = logged_services(dir.path());
    services.live.set(self::config(true));
    let source = Arc::new(Gated {
        live: Arc::clone(&services.live),
        asked: AtomicUsize::new(0),
    });
    hub.register_source(Arc::clone(&source) as Arc<dyn EventSource>);
    let (port, accepted) = counting_callback().await;
    queued_with(&hub, port, "evt_gate", "probe.gate", |sub, _| {
        sub.credential_kind = Some(crate::security::audit::CredentialKind::ApiKey);
        sub.api_key = Some(ApiKeyRef {
            name: "k".to_owned(),
            principal: crate::gateway::auth::principal_of(SECRET),
        });
    });
    let (reached, release) = hub.before_send.arm();
    let drive = async {
        reached.notified().await;
        // The reload has returned before the attempt goes on.
        services.live.set(after);
        release.notify_one();
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(hub.attempt(&services, "evt_gate"), drive)
    })
    .await
    .expect("the attempt finished");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(source.asked.load(Ordering::SeqCst) >= 1, "premise: checked");
    accepted.load(Ordering::SeqCst)
}

/// `WINDOW.1`: the reload removes the backend between the attempt's checks
/// and its send: nothing is sent.
#[tokio::test]
async fn a_reload_that_removes_the_backend_before_the_send_sends_nothing() {
    assert_eq!(
        attempt_across_a_reload(config(false)).await,
        0,
        "sent for a backend the reload removed"
    );
}

/// Control: a reload that keeps the backend lets the attempt send.
#[tokio::test]
async fn a_reload_that_keeps_the_backend_before_the_send_still_sends() {
    assert!(
        attempt_across_a_reload(config(true)).await >= 1,
        "not sent though the backend stayed"
    );
}
