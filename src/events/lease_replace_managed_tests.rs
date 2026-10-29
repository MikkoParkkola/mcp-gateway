// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ISO-T2 end to end: managed-account (vault) backends on a multi-user
//! gateway, each user's listener running on its own minted credential and
//! fenced on its own grant.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::events::{FenceRead, ListenerGrant, ListenerMint};

/// Two users' minted credentials and grants: user `u1` sends token 0 and
/// `u2` token 1. A rotation moves one user's grant binding, never the token,
/// so the peer sees the same credential before and after.
struct Grants {
    tokens: [String; 2],
    generation: Mutex<[u32; 2]>,
}

impl Grants {
    fn new(tokens: [String; 2]) -> Arc<Self> {
        Arc::new(Self {
            tokens,
            generation: Mutex::new([1, 1]),
        })
    }

    fn index(subject: &str) -> usize {
        usize::from(subject == "u2")
    }

    fn binding(&self, subject: &str) -> String {
        let at = Self::index(subject);
        let generation = self.generation.lock().expect("grants")[at];
        format!("acct:fence:v1:{subject}:{generation}")
    }

    fn rotate(&self, subject: &str) {
        self.generation.lock().expect("grants")[Self::index(subject)] += 1;
    }
}

#[async_trait::async_trait]
impl ListenerMint for Grants {
    async fn mint(&self, _: &str, identity: &VerifiedIdentity) -> crate::Result<ListenerGrant> {
        let subject = identity.subject.as_str();
        Ok(ListenerGrant {
            headers: vec![(
                "authorization".to_owned(),
                self.tokens[Self::index(subject)].clone(),
            )],
            fence: Some(self.binding(subject)),
        })
    }

    async fn fence_binding(
        &self,
        _: &str,
        identity: &VerifiedIdentity,
    ) -> Result<Option<String>, FenceRead> {
        Ok(Some(self.binding(&identity.subject)))
    }
}

/// A callback that counts the connections made to it; the handshake never
/// completes, which is all a test needs to see of a delivery.
async fn counting_callback() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("https://{}/cb", listener.local_addr().expect("addr"));
    let accepted = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (url, accepted)
}

/// A hub whose `pt` is a managed-account backend at `peer`, with an audit
/// log (delivery sends nothing without one) and loopback callbacks allowed.
fn managed_fixture(peer: &TwoTokenPeer) -> Fixture {
    let dir = tempfile::tempdir().expect("dir");
    let events = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&events, dir.path()).expect("hub");
    let config: crate::config::Config =
        crate::yaml::from_str(&managed_yaml(&peer.url)).expect("config");
    let live = Arc::new(crate::config_reload::LiveConfig::new(config));
    let config = live.get();
    let log = crate::security::TransparencyLogger::open(Arc::new(
        crate::security::TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            ..crate::security::TransparencyLogConfig::default()
        },
    ))
    .expect("log");
    let _ = hub.runtime.services.set(Arc::new(Services {
        live,
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: Some(Arc::new(log)),
        provenance: None,
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    }));
    Fixture { hub, config, dir }
}

fn managed_yaml(url: &str) -> String {
    format!(
        "backends:\n  pt:\n    http_url: {url}\n    streamable_http: true\n    account: work\n\
         accounts:\n  schema_version: accounts.v1\n  enabled: true\n  \
         deployment: single_process\n  instance_id: unit\n  store_dir: /unused/store\n  \
         authority_dir: /unused/authority\n  current_key_id: primary\n  keys:\n    \
         primary: env:UNUSED\n  descriptors:\n    \
         work:\n      mode: personal_managed\n      provider: fixture\n      \
         resource: https://api.fixture.test/\n      issuer: https://issuer.fixture.test\n      \
         authorization_endpoint: https://issuer.fixture.test/authorize\n      \
         token_endpoint: https://issuer.fixture.test/token\n      client_id: c\n      \
         redirect_uri: https://gateway.fixture.test/callback\n      scopes: [read]\n      \
         send_resource_parameter: true\n"
    )
}

/// The event id, subscription and lease stamp of every record in `f`'s outbox.
fn queued(f: &Fixture) -> Vec<(String, String, Option<String>)> {
    let entries = std::fs::read_dir(f.dir.path().join("outbox")).expect("outbox");
    entries
        .flatten()
        .map(|e| {
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(e.path()).expect("read")).expect("record");
            let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_owned();
            (
                text(&record["event_id"]),
                text(&record["subscription_id"]),
                record["observed"]["lease"].as_str().map(str::to_owned),
            )
        })
        .collect()
}
