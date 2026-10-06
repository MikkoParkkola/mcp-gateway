// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7940 finding 1: a login that expires with no reload changes the
//! listing, and that change is announced once.

use std::sync::Arc;
use std::time::Duration;

use super::super::CapabilityBackend;
use crate::backend::BackendRegistry;
use crate::capability::CapabilityExecutor;

const PROVIDER: &str = "mik7940";

fn oauth_cap() -> crate::capability::CapabilityDefinition {
    let yaml = format!(
        "name: oauthy\ndescription: Keyed\nproviders:\n  primary:\n    service: rest\n    \
         config:\n      base_url: https://api.invalid\n      path: /k\nauth:\n  required: true\n  \
         type: oauth\n  key: \"oauth:{PROVIDER}\"\n"
    );
    crate::capability::parse_capability(&yaml).unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A backend listing one `oauth:` capability whose cached token's raw expiry
/// is `expires_in` seconds away.
fn backend(expires_in: u64) -> Arc<CapabilityBackend> {
    let executor = Arc::new(CapabilityExecutor::new());
    let mut token: crate::oauth::TokenInfo =
        serde_json::from_value(serde_json::json!({"access_token": "t"})).unwrap();
    token.expires_at = Some(now() + expires_in);
    executor
        .oauth_tokens
        .read()
        .insert(PROVIDER.to_string(), token);
    let backend = Arc::new(CapabilityBackend::new("caps", executor));
    backend.register_capability(oauth_cap()).unwrap();
    backend
}

fn registry_feed() -> (
    Arc<BackendRegistry>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let registry = Arc::new(BackendRegistry::new());
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_change_feed(tx);
    (registry, rx)
}

/// The flip is the raw expiry less `is_expired`'s 60 s buffer.
#[test]
fn a_listed_login_expires_at_its_buffered_deadline() {
    let backend = backend(3600);
    let at = backend.next_listing_expiry().expect("expires");
    assert!(at.abs_diff(now() + 3600 - 60) <= 1, "{at}");
}

/// A token whose raw expiry is 63 s away is listed now and stops being listed
/// three seconds later, under the 60 s buffer: the watch announces that once,
/// with no reload.
#[tokio::test]
async fn an_expiring_login_is_announced_with_no_reload() {
    let backend = backend(63);
    assert_eq!(backend.listed_names(), ["oauthy"], "listed at creation");
    let (registry, mut feed) = registry_feed();
    let (shutdown, rx) = tokio::sync::broadcast::channel(1);
    backend.spawn_listing_watch(Arc::clone(&registry), rx);
    let announced = tokio::time::timeout(Duration::from_secs(10), feed.recv())
        .await
        .expect("announced within the buffered deadline");
    assert_eq!(announced.as_deref(), Some("caps"));
    assert!(backend.listed_names().is_empty(), "no longer listed");
    assert!(
        tokio::time::timeout(Duration::from_secs(3), feed.recv())
            .await
            .is_err(),
        "announced once"
    );
    let _ = shutdown.send(());
}

/// Two observers of one transition (an overlay publish, the expiry watch)
/// announce it once; a call that changes nothing announces nothing.
#[test]
fn one_transition_is_announced_once() {
    let backend = backend(3600);
    let (registry, mut feed) = registry_feed();
    assert!(!backend.announce_listing_change(&registry, || {}));
    backend.executor.oauth_tokens.read().remove(PROVIDER);
    assert!(backend.announce_listing_change(&registry, || {}));
    assert!(!backend.announce_listing_change(&registry, || {}));
    assert_eq!(feed.try_recv().as_deref(), Ok("caps"));
    assert!(feed.try_recv().is_err(), "once");
}

/// A capability loaded after the watch started (the initial scan, a reload)
/// is planned for too: its expiry is announced.
#[tokio::test]
async fn a_capability_loaded_later_has_its_expiry_announced() {
    let executor = Arc::new(CapabilityExecutor::new());
    let backend = Arc::new(CapabilityBackend::new("caps", Arc::clone(&executor)));
    let (registry, mut feed) = registry_feed();
    let (shutdown, rx) = tokio::sync::broadcast::channel(1);
    backend.spawn_listing_watch(Arc::clone(&registry), rx);
    // The watch parks on its empty catalogue first: only the wake plans the
    // later entry's expiry.
    tokio::task::yield_now().await;
    let mut token: crate::oauth::TokenInfo =
        serde_json::from_value(serde_json::json!({"access_token": "t"})).unwrap();
    token.expires_at = Some(now() + 63);
    executor
        .oauth_tokens
        .read()
        .insert(PROVIDER.to_string(), token);
    backend.register_capability(oauth_cap()).unwrap();
    assert_eq!(backend.listed_names(), ["oauthy"]);
    let announced = tokio::time::timeout(Duration::from_secs(10), feed.recv())
        .await
        .expect("the later capability's expiry was announced");
    assert_eq!(announced.as_deref(), Some("caps"));
    let _ = shutdown.send(());
}

/// The startup scan's loads have no reload to announce them: finishing the
/// scan announces once, even when what it ends with lists nothing (a tool shown
/// mid-scan may have been hidden again), and marks it complete.
#[test]
fn a_finished_scan_is_announced_once() {
    let backend = backend(3600);
    backend.begin_initial_scan();
    backend.executor.oauth_tokens.read().remove(PROVIDER);
    assert!(backend.listed_names().is_empty());
    let (registry, mut feed) = registry_feed();
    backend.finish_initial_scan(&registry);
    assert!(backend.initial_scan_complete());
    assert_eq!(feed.try_recv().as_deref(), Ok("caps"));
    assert!(feed.try_recv().is_err(), "once");
}
