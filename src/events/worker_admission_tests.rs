// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7907 `WINDOW.1`: a reload that makes a backend ineligible after an
//! attempt's checks and before its send does not deliver that attempt's
//! event. The attempt stops at its last step before the send; a reload runs
//! and returns; then the attempt resumes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    queued_with(&hub, port, "evt_gate", "probe.gate", |sub, record| {
        // The record's backend is the one the key grants.
        record.backend = "g".into();
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

/// A `backend.x.tools_changed` attempt paused before its send while backend
/// `x` leaves the registry (`remove`) or stays; the posts its callback got.
async fn backend_attempt_across_a_removal(remove: bool) -> usize {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = logged_services(dir.path());
    let names = Arc::new(parking_lot::Mutex::new(vec!["x".to_owned()]));
    let live = Arc::clone(&names);
    hub.install_backend_source(Arc::new(move || live.lock().clone()));
    let (port, accepted) = counting_callback().await;
    queued_with(&hub, port, "evt_x", "backend.x.tools_changed", |_, _| {});
    let (reached, release) = hub.before_send.arm();
    let drive = async {
        reached.notified().await;
        if remove {
            names.lock().clear();
        }
        release.notify_one();
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(hub.attempt(&services, "evt_x"), drive)
    })
    .await
    .expect("the attempt finished");
    tokio::time::sleep(Duration::from_millis(300)).await;
    accepted.load(Ordering::SeqCst)
}

/// A backend no source offers any more at the send is not sent to, though
/// every earlier check saw it (the boundary reads it as `source_verdict` does).
#[tokio::test]
async fn a_backend_removed_before_the_send_sends_nothing() {
    assert!(
        backend_attempt_across_a_removal(false).await >= 1,
        "premise: sent while the backend stays"
    );
    assert_eq!(
        backend_attempt_across_a_removal(true).await,
        0,
        "sent for a backend that left"
    );
}

/// `BackendSource::admits_now`: a removed backend admits nothing; an
/// ineligible one still admits `tools_changed`, which the gateway announces
/// itself, but not the upstream kinds. A removed backend is also refused at
/// `authorize`, so its subscription ends instead of being held forever.
#[tokio::test]
async fn a_backend_source_admits_by_presence_and_eligibility() {
    use crate::events::backend_source::{BackendSource, Ineligible, Upstream};
    let ineligible: Ineligible = Arc::new(|| std::iter::once("i".to_owned()).collect());
    let source = BackendSource {
        names: Arc::new(|| vec!["e".to_owned(), "i".to_owned()]),
        upstream: Some(Upstream {
            listeners: crate::events::upstream_listener::UpstreamListeners::new(
                Arc::new(crate::backend::BackendRegistry::new()),
                std::sync::Weak::new(),
                Arc::clone(&ineligible),
            ),
            ineligible,
        }),
    };
    for (name, admitted) in [
        ("backend.e.tools_changed", true),
        ("backend.e.resources_changed", true),
        ("backend.i.tools_changed", true),
        ("backend.i.resources_changed", false),
        ("backend.gone.tools_changed", false),
        ("probe.other", true),
    ] {
        assert_eq!(source.admits_now(name), admitted, "{name}");
    }
    let none = serde_json::json!({});
    let present = source.authorize("p", "backend.e.tools_changed", &none);
    assert!(present.await.is_ok(), "present");
    let removed = source.authorize("p", "backend.gone.tools_changed", &none);
    assert!(removed.await.is_err(), "removed");
}

/// A source whose admission blocks, inside the live config's gate, until the
/// test lets it go: the pause point `W1.3` needs, since the gate is held only
/// by a synchronous call.
struct Held {
    inside: std::sync::mpsc::SyncSender<()>,
    go: parking_lot::Mutex<std::sync::mpsc::Receiver<()>>,
}

#[async_trait::async_trait]
impl EventSource for Held {
    fn kind(&self) -> SourceKind {
        SourceKind::RestWatch
    }
    fn descriptors(&self) -> Vec<crate::events::types::EventDescriptor> {
        vec![descriptor("probe.held", SourceKind::RestWatch)]
    }
    fn matches(
        &self,
        _principal: &str,
        _arguments: &serde_json::Value,
        _event: &crate::events::fanout::SourceEvent,
    ) -> bool {
        true
    }
    fn admits_now(&self, _name: &str) -> bool {
        let _ = self.inside.send(());
        let _ = self.go.lock().recv_timeout(Duration::from_secs(20));
        true
    }
}

/// A callback that accepts each connection and never answers, so a send
/// stays in flight until the client gives up; the connections it accepted,
/// and whether a client has closed one (the send ended).
async fn silent_callback() -> (u16, Arc<AtomicUsize>, Arc<AtomicBool>) {
    use tokio::io::AsyncReadExt as _;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let ended = Arc::new(AtomicBool::new(false));
    let (seen, closed) = (Arc::clone(&accepted), Arc::clone(&ended));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            let closed = Arc::clone(&closed);
            tokio::spawn(async move {
                let mut buf = [0_u8; 1024];
                while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
                closed.store(true, Ordering::SeqCst);
            });
        }
    });
    (port, accepted, ended)
}

/// Polls `done` every 20 ms for up to `limit`.
async fn within(limit: Duration, done: impl Fn() -> bool) -> bool {
    let until = tokio::time::Instant::now() + limit;
    while !done() {
        if tokio::time::Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

/// `WINDOW.1` `W1.3`: a reload that starts while a send is being admitted
/// returns only after that admission, and no reload waits on a send's
/// network I/O: the gate is released before the POST.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reload_waits_for_an_admission_but_not_for_the_send() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = Arc::new(logged_services(dir.path()));
    let (inside_tx, inside) = std::sync::mpsc::sync_channel(1);
    let (go, go_rx) = std::sync::mpsc::channel();
    hub.register_source(Arc::new(Held {
        inside: inside_tx,
        go: parking_lot::Mutex::new(go_rx),
    }));
    let (port, connections, ended) = silent_callback().await;
    queued_with(&hub, port, "evt_held", "probe.held", |_, _| {});
    let attempt = tokio::spawn({
        let (hub, services) = (Arc::clone(&hub), Arc::clone(&services));
        async move { hub.attempt(&services, "evt_held").await }
    });
    tokio::task::spawn_blocking(move || inside.recv_timeout(Duration::from_secs(20)))
        .await
        .expect("join")
        .expect("the attempt reached its admission");

    let reload = |live: Arc<LiveConfig>| std::thread::spawn(move || live.set(Config::default()));
    let first = reload(Arc::clone(&services.live));
    assert!(
        !within(Duration::from_millis(300), || first.is_finished()).await,
        "a reload returned while a send was being admitted"
    );
    go.send(()).expect("release");
    assert!(
        within(Duration::from_secs(30), || first.is_finished()).await,
        "the reload returned once the admission ended"
    );

    assert!(
        within(Duration::from_secs(10), || connections
            .load(Ordering::SeqCst)
            >= 1)
        .await,
        "premise: the send is in flight"
    );
    // Judged by order, not by a deadline: a gate held across the POST would
    // let this reload return only once the client gave up on the send
    // (`TOTAL_TIMEOUT`, 10 s). The 30 s bound only stops a hang.
    let second = reload(Arc::clone(&services.live));
    assert!(
        within(Duration::from_secs(30), || second.is_finished()).await,
        "a reload never returned"
    );
    assert!(
        !ended.load(Ordering::SeqCst),
        "a reload waited on a send's network I/O"
    );
    attempt.abort();
}
