// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What `GET /ui/api/discovery` lists: servers found in other MCP clients'
//! config files on this host, reduced at scan time to what may leave the
//! gateway, and cached for a short while.
//!
//! Nothing cached holds a value. A find's env and header values, its argv
//! and its full paths are dropped as soon as the scan is projected: the
//! cache keeps key names, a program name, a URL origin, a file name, the
//! adopt rule's refusals, the radar's severity and a keyed hash of the raw
//! client entry (`find_id`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use serde::Serialize;

use super::adopt::refusals;
use super::config_scanner::client_scan::{ClientScan, Fingerprint};
use super::shadow::{ShadowAsset, ShadowRiskSeverity, executable_name};
use super::{ConfigScanner, DiscoveredServer, DiscoverySource, REDACTED};
use crate::config::TransportConfig;

/// How long a scan answers GETs while no client file changes.
pub(crate) const CACHE_WINDOW: Duration = Duration::from_secs(30);
/// How long a scan may run while it holds the cache.
pub(crate) const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

/// One refusal, by reason code and client field: never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Refusal {
    pub(crate) reason: &'static str,
    pub(crate) field: String,
}

/// A find as the route may show it. Built once per scan; holds no value.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ListedFind {
    pub(crate) find_id: String,
    pub(crate) name: String,
    pub(crate) source: DiscoverySource,
    pub(crate) config_file: Option<String>,
    pub(crate) transport: &'static str,
    pub(crate) command: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) env: std::collections::BTreeMap<String, &'static str>,
    pub(crate) headers: std::collections::BTreeMap<String, &'static str>,
    /// The adopt rule's refusals, which do not depend on gateway.yaml.
    pub(crate) refusals: Vec<Refusal>,
    /// The radar's severity for this find, judged with no backend registered.
    #[serde(skip)]
    pub(crate) severity: ShadowRiskSeverity,
    /// The radar's row for this find, classified at scan time from the whole
    /// find and holding no value: a file name, a URL origin and a keyed id.
    /// The control-plane radar reads it instead of scanning the files again.
    #[serde(skip)]
    pub(crate) radar: ShadowAsset,
}

/// One cached scan.
#[derive(Debug)]
pub(crate) struct Listing {
    pub(crate) finds: Vec<ListedFind>,
    /// Each unreadable client file by name, reason and keyed path digest.
    pub(crate) unreadable: Vec<crate::decisions::UnreadableFile>,
    /// Counts up with each scan this cache keeps: a newer listing has a
    /// larger one, so a reader holding an older listing can tell.
    pub(crate) generation: u64,
    fingerprint: Fingerprint,
    taken: Instant,
}

/// Where scans, fingerprints and the time come from: the client files and
/// the monotonic clock in production, a fake in tests.
pub(crate) trait ScanSource: Send + Sync {
    /// Stat the client files without reading them.
    fn fingerprint(&self) -> Fingerprint;
    /// Read the client files.
    fn scan(&self) -> BoxFuture<'_, ClientScan>;
    /// Now, on a monotonic clock.
    fn now(&self) -> Instant;
}

/// The client config files on this host.
pub(crate) struct ClientFiles(pub(crate) ConfigScanner);

impl ScanSource for ClientFiles {
    fn fingerprint(&self) -> Fingerprint {
        ConfigScanner::fingerprint(&ConfigScanner::candidates())
    }
    fn scan(&self) -> BoxFuture<'_, ClientScan> {
        Box::pin(self.0.scan_client_configs())
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// The scan timed out with no earlier scan to fall back on.
#[derive(Debug)]
pub(crate) struct ScanTimedOut;

/// The cache behind `GET /ui/api/discovery`.
pub(crate) struct DiscoveryCache {
    source: Arc<dyn ScanSource>,
    /// Drawn once per process: `find_id` is an HMAC under it, so a find id
    /// cannot be used to test guesses at a client's values offline.
    key: [u8; 32],
    /// Keys the radar's asset ids, so they hold across restarts.
    record_key: Arc<crate::gateway::record_principal::RecordPrincipalKey>,
    /// One scan at a time: a GET that misses holds this across its scan, and
    /// one waiting behind it then finds the fresh result.
    current: tokio::sync::Mutex<Cached>,
    /// Who hears of each new listing: the decision set. Set once.
    publisher: std::sync::OnceLock<Publisher>,
}

/// Handed each new listing while the cache still holds its lock.
pub(crate) type Publisher = Arc<dyn Fn(&Arc<Listing>) + Send + Sync>;

/// The last listing, and when the last scan timed out.
#[derive(Default)]
struct Cached {
    listing: Option<Arc<Listing>>,
    /// For one `SCAN_TIMEOUT` after a timed-out scan, reads answer from what
    /// is cached instead of each waiting out another scan.
    timed_out_at: Option<Instant>,
    /// The generation of the last listing kept.
    generation: u64,
}

impl DiscoveryCache {
    /// A cache over `source`, with a fresh process key, for tests.
    #[cfg(test)]
    pub(crate) fn new(source: Arc<dyn ScanSource>) -> Self {
        use rand::RngExt as _;
        Self::with_key(source, rand::rng().random())
    }

    /// A cache whose radar ids are keyed by the gateway's record key.
    pub(crate) fn with_record_key(
        source: Arc<dyn ScanSource>,
        record_key: Arc<crate::gateway::record_principal::RecordPrincipalKey>,
    ) -> Self {
        use rand::RngExt as _;
        Self {
            record_key,
            ..Self::with_key(source, rand::rng().random())
        }
    }

    /// A cache with a given key, for tests that check `find_id`. Its radar
    /// ids are keyed for this cache alone.
    pub(crate) fn with_key(source: Arc<dyn ScanSource>, key: [u8; 32]) -> Self {
        Self {
            source,
            key,
            record_key: Arc::new(crate::gateway::record_principal::one_run_key()),
            current: tokio::sync::Mutex::new(Cached::default()),
            publisher: std::sync::OnceLock::new(),
        }
    }

    /// The current listing, and whether it is stale: a fresh scan when the
    /// window passed or a client file changed, else the cached one. A scan
    /// that times out serves the previous listing marked stale.
    ///
    /// # Errors
    ///
    /// [`ScanTimedOut`] when the scan timed out and nothing was cached.
    pub(crate) async fn listing(&self) -> Result<(Arc<Listing>, bool), ScanTimedOut> {
        let mut current = self.current.lock().await;
        let now = self.source.now();
        if let Some(listing) = current.listing.as_ref()
            && now.duration_since(listing.taken) < CACHE_WINDOW
            && self.source.fingerprint() == listing.fingerprint
        {
            return Ok((Arc::clone(listing), false));
        }
        let stale = |cached: &Cached| {
            cached
                .listing
                .as_ref()
                .map(|listing| (Arc::clone(listing), true))
                .ok_or(ScanTimedOut)
        };
        if current
            .timed_out_at
            .is_some_and(|at| now.duration_since(at) < SCAN_TIMEOUT)
        {
            return stale(&current);
        }
        let Ok(scan) = tokio::time::timeout(SCAN_TIMEOUT, self.source.scan()).await else {
            current.timed_out_at = Some(self.source.now());
            return stale(&current);
        };
        let generation = current.generation + 1;
        let listing = Arc::new(self.project(scan, generation));
        // Published before the lock is released, whoever triggered the
        // rescan: an older listing can then never land after a newer one.
        if let Some(publish) = self.publisher.get() {
            publish(&listing);
        }
        *current = Cached {
            listing: Some(Arc::clone(&listing)),
            timed_out_at: None,
            generation,
        };
        Ok((listing, false))
    }

    /// Hand every new listing to `publish` while this cache still holds its
    /// lock. Set once; a second call is ignored.
    pub(crate) fn set_publisher(&self, publish: Publisher) {
        let _ = self.publisher.set(publish);
    }

    /// The find `find_id` names, from a fresh scan of the client files: the
    /// whole find, values included, for an adopt. Never cached, takes no
    /// cache lock and leaves the listing's time-out back-off alone. A find
    /// without a client entry is never one (ADR-021).
    ///
    /// # Errors
    ///
    /// [`ScanTimedOut`] when the scan outlasts [`SCAN_TIMEOUT`].
    pub(crate) async fn resolve(
        &self,
        find_id: &str,
    ) -> Result<Option<DiscoveredServer>, ScanTimedOut> {
        let scan = tokio::time::timeout(SCAN_TIMEOUT, self.source.scan())
            .await
            .map_err(|_| ScanTimedOut)?;
        Ok(scan.finds.into_iter().find(|server| {
            !server.entry_digest.is_empty()
                && crate::hashing::hmac_sha256_hex(&self.key, server.entry_digest.as_bytes())
                    == find_id
        }))
    }

    /// Reduce a scan to what may be cached, then drop the scan, values and
    /// all. A find without a client entry is not listed (ADR-021).
    fn project(&self, scan: ClientScan, generation: u64) -> Listing {
        let finds = scan
            .finds
            .iter()
            .filter(|server| !server.entry_digest.is_empty())
            .map(|server| self.project_one(server))
            .collect();
        Listing {
            finds,
            unreadable: scan
                .unreadable
                .iter()
                .map(|file| crate::decisions::UnreadableFile {
                    source: file.source.clone(),
                    file: file.file_name(),
                    path_digest: file.path_digest(&self.key),
                    reason: file.reason,
                })
                .collect(),
            generation,
            fingerprint: scan.fingerprint,
            taken: self.source.now(),
        }
    }

    fn project_one(&self, server: &DiscoveredServer) -> ListedFind {
        let (transport, command, url) = match &server.transport {
            TransportConfig::Stdio { command, .. } => ("stdio", executable_name(command), None),
            TransportConfig::Http { http_url, .. } => ("http", None, origin(http_url)),
            TransportConfig::WebSocket { ws_url, .. } => ("ws", None, origin(ws_url)),
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { .. } => ("a2a", None, None),
        };
        let radar = ShadowAsset::from_server(server, None, &self.record_key);
        let severity = radar.severity.clone();
        ListedFind {
            find_id: crate::hashing::hmac_sha256_hex(&self.key, server.entry_digest.as_bytes()),
            name: server.name.clone(),
            source: server.source.clone(),
            config_file: server
                .metadata
                .config_path
                .as_deref()
                .and_then(std::path::Path::file_name)
                .map(|name| name.to_string_lossy().into_owned()),
            transport,
            command,
            url,
            env: server
                .env
                .keys()
                .map(|k| (k.to_string(), REDACTED))
                .collect(),
            headers: server
                .headers
                .keys()
                .map(|k| (k.to_string(), REDACTED))
                .collect(),
            refusals: refusals(server)
                .into_iter()
                .map(|(refusal, field)| Refusal {
                    reason: refusal.code(),
                    field,
                })
                .collect(),
            severity,
            radar,
        }
    }
}

/// Scheme, host and port, or nothing: a URL without a host, or one that does
/// not parse, shows no URL rather than a placeholder.
fn origin(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    parsed.host_str()?;
    Some(crate::security::sanitize::redact_url_for_diagnostics(raw))
}

#[cfg(test)]
#[path = "listing_tests.rs"]
mod tests;
