// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The discovery listing: one scan per cache window, a fresh one when a
//! client file changes, and nothing cached or listed that holds a value, an
//! argument or a path.

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::*;
use crate::discovery::config_scanner::client_scan::{Candidate, Format};

/// A scan source whose finds, file and clock the test controls.
struct Fake {
    scans: AtomicUsize,
    now: Mutex<Instant>,
    finds: Vec<DiscoveredServer>,
    /// The one watched file: writing it changes the fingerprint.
    watched: Vec<Candidate>,
    /// A scan that never ends, to hit the timeout.
    hang: AtomicBool,
}

impl Fake {
    fn new(finds: Vec<DiscoveredServer>, watched: &Path) -> Self {
        Self {
            scans: AtomicUsize::new(0),
            now: Mutex::new(Instant::now()),
            finds,
            watched: vec![Candidate {
                path: watched.to_path_buf(),
                source: DiscoverySource::ClaudeDesktop,
                format: Format::Claude,
            }],
            hang: AtomicBool::new(false),
        }
    }
    fn advance(&self, by: Duration) {
        *self.now.lock().expect("clock") += by;
    }
    fn scans(&self) -> usize {
        self.scans.load(Ordering::SeqCst)
    }
}

impl ScanSource for Fake {
    fn fingerprint(&self) -> Fingerprint {
        ConfigScanner::fingerprint(&self.watched)
    }
    fn scan(&self) -> BoxFuture<'_, ClientScan> {
        self.scans.fetch_add(1, Ordering::SeqCst);
        let hang = self.hang.load(Ordering::SeqCst);
        let scan = ClientScan {
            finds: self.finds.clone(),
            fingerprint: self.fingerprint(),
            unreadable: Vec::new(),
        };
        Box::pin(async move {
            if hang {
                std::future::pending::<()>().await;
            }
            scan
        })
    }
    fn now(&self) -> Instant {
        *self.now.lock().expect("clock")
    }
}

fn find(name: &str, entry: &Value) -> DiscoveredServer {
    crate::discovery::client_entry::parse(
        name,
        entry,
        &DiscoverySource::ClaudeDesktop,
        Path::new("/home/zqhome/Library/claude_desktop_config.json"),
    )
    .expect("the entry parses")
}

fn cache(fake: &Arc<Fake>) -> DiscoveryCache {
    DiscoveryCache::with_key(Arc::clone(fake) as Arc<dyn ScanSource>, [7; 32])
}

#[tokio::test]
async fn twenty_reads_in_a_window_scan_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fake = Arc::new(Fake::new(
        vec![find("srv", &json!({"command": "npx"}))],
        &dir.path().join("w.json"),
    ));
    let cache = cache(&fake);
    for _ in 0..20 {
        cache.listing().await.expect("listing");
    }
    assert_eq!(fake.scans(), 1);
}

#[tokio::test]
async fn a_changed_client_file_or_an_expired_window_rescans() {
    let dir = tempfile::tempdir().expect("tempdir");
    let watched = dir.path().join("w.json");
    let fake = Arc::new(Fake::new(Vec::new(), &watched));
    let cache = cache(&fake);
    cache.listing().await.expect("listing");

    crate::gateway::test_helpers::write_owner_only(&watched, "{}").expect("create");
    cache.listing().await.expect("listing");
    assert_eq!(fake.scans(), 2, "a created file rescans");

    std::fs::remove_file(&watched).expect("delete");
    cache.listing().await.expect("listing");
    assert_eq!(fake.scans(), 3, "a deleted file rescans");

    fake.advance(CACHE_WINDOW);
    cache.listing().await.expect("listing");
    assert_eq!(fake.scans(), 4, "an expired window rescans");
}

/// Each kept scan counts the generation up, and a read the window serves
/// keeps it: the decision set orders listings by it.
#[tokio::test]
async fn a_rescan_raises_the_generation_and_a_cached_read_keeps_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fake = Arc::new(Fake::new(Vec::new(), &dir.path().join("w.json")));
    let cache = cache(&fake);
    let generation = |listing: (Arc<Listing>, bool)| listing.0.generation;
    let first = generation(cache.listing().await.expect("listing"));
    let cached = generation(cache.listing().await.expect("listing"));
    assert_eq!(cached, first, "a cached read changed the generation");
    fake.advance(CACHE_WINDOW);
    let second = generation(cache.listing().await.expect("listing"));
    fake.advance(CACHE_WINDOW);
    let third = generation(cache.listing().await.expect("listing"));
    assert!(
        first < second && second < third,
        "{first}, {second}, {third}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_cold_reads_share_one_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fake = Arc::new(Fake::new(Vec::new(), &dir.path().join("w.json")));
    let cache = Arc::new(cache(&fake));
    let reads: Vec<_> = (0..10)
        .map(|_| {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move { cache.listing().await.map(|_| ()) })
        })
        .collect();
    for read in reads {
        read.await.expect("task").expect("listing");
    }
    assert_eq!(fake.scans(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_scan_that_times_out_serves_the_last_listing_as_stale() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fake = Arc::new(Fake::new(Vec::new(), &dir.path().join("w.json")));
    let warm = cache(&fake);
    let (_, stale) = warm.listing().await.expect("listing");
    assert!(!stale);

    fake.hang.store(true, Ordering::SeqCst);
    fake.advance(CACHE_WINDOW);
    let (_, stale) = warm.listing().await.expect("the last listing");
    assert!(stale, "served stale after the timeout");
    let scans = fake.scans();

    // Within one timeout of the last, a read does not wait out another scan.
    let (_, stale) = warm.listing().await.expect("the last listing");
    assert!(stale);
    assert_eq!(fake.scans(), scans, "no scan while backing off");

    fake.hang.store(false, Ordering::SeqCst);
    fake.advance(SCAN_TIMEOUT);
    let (_, stale) = warm.listing().await.expect("a fresh listing");
    assert!(!stale, "a scan that finishes clears the back-off");
    assert_eq!(fake.scans(), scans + 1);

    let cold = Arc::new(Fake::new(Vec::new(), &dir.path().join("w.json")));
    cold.hang.store(true, Ordering::SeqCst);
    assert!(
        cache(&cold).listing().await.is_err(),
        "nothing to fall back on"
    );
}

/// Canaries one leak would carry: an argument, an env value, a header value,
/// a working directory, the home path, and URL path, query, fragment and
/// userinfo.
const CANARIES: &[&str] = &[
    "zqargtoken",
    "zqenvsecret",
    "zqheadersecret",
    "zqcwd",
    "zqhome",
    "zqpath",
    "zqquery",
    "zqfrag",
    "zquser",
    "zqpass",
];

#[tokio::test]
async fn no_value_argument_or_path_reaches_the_listing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let finds = vec![
        find(
            "stdio",
            &json!({
                "command": "/opt/zqcwd/bin/srv",
                "args": ["--token", "zqargtoken"],
                "env": {"API_KEY": "zqenvsecret"},
                "cwd": "/home/zqcwd/proj",
            }),
        ),
        find(
            "http",
            &json!({
                "url": "https://zquser:zqpass@mcp.example.test:8443/zqpath?zqquery=1#zqfrag",
                "headers": {"Authorization": "Bearer zqheadersecret"},
            }),
        ),
        find(
            "ws",
            &json!({
                "url": "wss://mcp.example.test/zqpath?zqquery=1",
                "headers": {"X-Key": "zqheadersecret"},
            }),
        ),
        find("pathlike", &json!({"command": "/home/zqhome/.."})),
    ];
    let fake = Arc::new(Fake::new(finds, &dir.path().join("w.json")));
    let (listing, _) = cache(&fake).listing().await.expect("listing");

    let json = serde_json::to_string(&listing.finds).expect("serializes");
    let debug = format!("{listing:?}");
    for canary in CANARIES {
        assert!(!json.contains(canary), "{canary} in {json}");
        assert!(!debug.contains(canary), "{canary} cached: {debug}");
    }
    let by_name = |name: &str| {
        listing
            .finds
            .iter()
            .find(|f| f.name == name)
            .expect("listed")
    };
    assert_eq!(by_name("stdio").command.as_deref(), Some("srv"));
    assert_eq!(by_name("stdio").env.get("API_KEY"), Some(&REDACTED));
    assert_eq!(
        by_name("stdio").config_file.as_deref(),
        Some("claude_desktop_config.json")
    );
    assert_eq!(
        by_name("http").url.as_deref(),
        Some("https://mcp.example.test:8443")
    );
    assert_eq!(by_name("ws").url.as_deref(), Some("wss://mcp.example.test"));
    assert_eq!(by_name("pathlike").command, None);
}

#[tokio::test]
async fn a_url_with_no_host_shows_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let finds = vec![find("bad", &json!({"url": "not a url"}))];
    let fake = Arc::new(Fake::new(finds, &dir.path().join("w.json")));
    let (listing, _) = cache(&fake).listing().await.expect("listing");
    assert_eq!(listing.finds[0].url, None);
    assert!(
        !listing.finds[0].refusals.is_empty(),
        "and it is not adoptable"
    );
}

#[tokio::test]
async fn find_id_is_keyed_and_stable_within_a_process() {
    let dir = tempfile::tempdir().expect("tempdir");
    let finds = vec![find("srv", &json!({"command": "npx", "env": {"K": "v"}}))];
    let fake = Arc::new(Fake::new(finds.clone(), &dir.path().join("w.json")));
    let cache_a = cache(&fake);
    let first = cache_a.listing().await.expect("listing").0.finds[0]
        .find_id
        .clone();
    fake.advance(CACHE_WINDOW);
    let again = cache_a.listing().await.expect("listing").0.finds[0]
        .find_id
        .clone();
    assert_eq!(first, again, "a fresh scan keeps the key");
    assert_eq!(
        first,
        crate::hashing::hmac_sha256_hex(&[7; 32], finds[0].entry_digest.as_bytes())
    );

    let other_key = DiscoveryCache::with_key(Arc::clone(&fake) as Arc<dyn ScanSource>, [8; 32]);
    let other = other_key.listing().await.expect("listing").0.finds[0]
        .find_id
        .clone();
    assert_ne!(first, other, "another process key gives another id");
}

#[tokio::test]
async fn a_find_without_a_client_entry_is_not_listed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bare = DiscoveredServer::new(
        "env".to_string(),
        String::new(),
        DiscoverySource::Environment,
        TransportConfig::Http {
            http_url: "https://mcp.example.test".to_string(),
            streamable_http: None,
            protocol_version: None,
        },
        crate::discovery::ServerMetadata::default(),
    );
    let fake = Arc::new(Fake::new(vec![bare], &dir.path().join("w.json")));
    let (listing, _) = cache(&fake).listing().await.expect("listing");
    assert!(listing.finds.is_empty());
}

/// `resolve` gives back the whole find the listing named, values included,
/// and never one without a client entry.
#[tokio::test]
async fn resolve_returns_the_listed_find_with_its_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let listed = find(
        "tool",
        &json!({"command": "npx", "env": {"API_KEY": "zq-value"}}),
    );
    let mut no_entry = listed.clone();
    no_entry.name = "env-find".to_owned();
    no_entry.entry_digest = String::new();
    let fake = Arc::new(Fake::new(
        vec![listed, no_entry],
        &dir.path().join("w.json"),
    ));
    let cache = cache(&fake);
    let (listing, _) = cache.listing().await.expect("listing");
    let id = listing.finds[0].find_id.clone();

    let resolved = cache.resolve(&id).await.expect("scan").expect("found");
    assert_eq!(resolved.name, "tool");
    assert_eq!(resolved.to_backend_config().env["API_KEY"], "zq-value");
    assert!(cache.resolve("not-an-id").await.expect("scan").is_none());
    let unkeyed = crate::hashing::hmac_sha256_hex(&[7; 32], b"");
    assert!(cache.resolve(&unkeyed).await.expect("scan").is_none());
}

/// A `resolve` that times out answers so, and leaves the listing's own
/// time-out back-off alone.
#[tokio::test(start_paused = true)]
async fn a_resolve_time_out_leaves_the_listing_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fake = Arc::new(Fake::new(Vec::new(), &dir.path().join("w.json")));
    let cache = cache(&fake);
    fake.hang.store(true, Ordering::SeqCst);
    assert!(cache.resolve("any").await.is_err());

    fake.hang.store(false, Ordering::SeqCst);
    let (_, stale) = cache.listing().await.expect("a fresh listing");
    assert!(!stale, "the listing scanned instead of backing off");
}

/// R10: a new listing reaches the decision set while the cache still holds
/// its lock, so an older listing can never be published over a newer one.
#[tokio::test]
async fn a_new_listing_is_published_while_the_cache_is_held() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fake = Arc::new(Fake::new(Vec::new(), &dir.path().join("w.json")));
    let cache = Arc::new(cache(&fake));
    let held: Arc<Mutex<Vec<bool>>> = Arc::default();
    let weak = Arc::downgrade(&cache);
    let seen = Arc::clone(&held);
    cache.set_publisher(Arc::new(move |_listing: &Arc<Listing>| {
        let cache = weak.upgrade().expect("the cache is alive");
        seen.lock()
            .expect("seen")
            .push(cache.current.try_lock().is_err());
    }));
    cache.listing().await.expect("listing");
    fake.advance(CACHE_WINDOW);
    cache.listing().await.expect("listing");
    assert_eq!(
        *held.lock().expect("seen"),
        [true, true],
        "each rescan publishes once, with the cache's lock held"
    );
}
