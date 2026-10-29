// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend-pin rows on what a cached answer is keyed on: the executor's
//! cache follows the pinned definition, never a replaced or same-named one,
//! and every shipped pinned capability keeps its fingerprint. Moved from
//! `backend_pin_tests.rs` for the file-size ceiling.

use super::*;

/// T2a-T2d now meet admission before the cache, so they would pass without
/// the fingerprint in the key; `two_pinned_definitions_of_one_name_never_share_an_answer`
/// is the test that pins the key itself.
///
/// T2a: an executor with no shared epoch must not serve an unpinned
/// definition the cached answer of a pinned one of the same name.
#[cfg(unix)]
#[tokio::test]
async fn a_standalone_executor_keys_its_cache_on_the_definition() {
    let body = pin_probe_body("Pin probe.");
    let pinned = pinned_from(&body).await;
    let unpinned = crate::capability::parse_capability(&body).unwrap();
    let executor = python_policy_executor();
    let context = CapabilityExecutionContext::default();
    executor
        .execute_with_context(&pinned, json!({}), context.clone())
        .await
        .expect("pinned runs and is cached");
    let err = executor
        .execute_with_context(&unpinned, json!({}), context)
        .await
        .expect_err("the unpinned definition must meet the gate, not the cache");
    assert!(err.to_string().contains("must be pinned"), "{err}");
}

/// T2b: a request snapshot taken before a replacement must not reach the
/// replaced definition's cached answer.
#[cfg(unix)]
#[tokio::test]
async fn a_stale_snapshot_does_not_reach_a_replaced_definitions_cache() {
    use std::sync::atomic::AtomicU64;
    let body = pin_probe_body("Pin probe.");
    let epoch = Arc::new(AtomicU64::new(0));
    let backend = CapabilityBackend::new(
        "test",
        Arc::new(python_policy_executor().with_policy_epoch(Arc::clone(&epoch))),
    );
    backend
        .register_capability(pinned_from(&body).await)
        .unwrap();
    let stale = snapshot(&epoch);
    backend
        .call_tool_with_context("pin_probe", json!({}), stale.clone())
        .await
        .expect("pinned runs and is cached");
    backend
        .register_capability(crate::capability::parse_capability(&body).unwrap())
        .unwrap();
    let err = backend
        .call_tool_with_context("pin_probe", json!({}), stale)
        .await
        .expect_err("a stale snapshot must not be served the old answer");
    assert!(err.to_string().contains("must be pinned"), "{err}");
}

/// T2c: two backends sharing one executor; the second registers an unpinned
/// definition of the same name for the first time.
#[cfg(unix)]
#[tokio::test]
async fn a_first_registration_on_a_shared_executor_meets_the_gate() {
    use std::sync::atomic::AtomicU64;
    let body = pin_probe_body("Pin probe.");
    let epoch = Arc::new(AtomicU64::new(0));
    let executor = Arc::new(python_policy_executor().with_policy_epoch(Arc::clone(&epoch)));
    let first = CapabilityBackend::new("first", Arc::clone(&executor));
    let second = CapabilityBackend::new("second", executor);
    first.register_capability(pinned_from(&body).await).unwrap();
    first
        .call_tool_with_context("pin_probe", json!({}), snapshot(&epoch))
        .await
        .expect("pinned runs and is cached");
    second
        .register_capability(crate::capability::parse_capability(&body).unwrap())
        .unwrap();
    let err = second
        .call_tool_with_context("pin_probe", json!({}), snapshot(&epoch))
        .await
        .expect_err("another backend's unpinned definition must meet the gate");
    assert!(err.to_string().contains("must be pinned"), "{err}");
}

/// The gateway's outer response cache keys on the request's epoch
/// snapshot. A snapshot taken after a replacement must key differently from
/// one taken before it, so it can never read the old definition's answer. (A
/// snapshot taken before is ordered before the replacement and may still read
/// it: staleness from the trusted definition, not an escalation.)
#[test]
fn a_snapshot_after_a_replacement_never_keys_the_old_outer_answer() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let body = "name: outer_probe\ndescription: Outer probe.\nproviders:\n  primary:\n    \
                service: rest\n    config:\n      base_url: https://outer-probe.internal\n      \
                path: /x\n";
    let epoch = Arc::new(AtomicU64::new(0));
    let backend = CapabilityBackend::new(
        "test",
        Arc::new(CapabilityExecutor::new().with_policy_epoch(Arc::clone(&epoch))),
    );
    backend
        .register_capability(crate::capability::parse_capability(body).unwrap())
        .unwrap();
    let key = |snapshot: u64| {
        crate::cache::ResponseCache::response_key(
            "test",
            "outer_probe",
            &json!({}),
            "",
            None,
            crate::cache::KeyContext {
                routing_profile: "default",
                protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
                policy_epoch: snapshot,
            },
        )
    };
    let before = epoch.load(Ordering::SeqCst);
    backend
        .register_capability(crate::capability::parse_capability(body).unwrap())
        .unwrap();
    let after = epoch.load(Ordering::SeqCst);
    assert!(after > before, "a replacement must advance the epoch");
    assert_ne!(
        key(after),
        key(before),
        "an after-snapshot reads a fresh key"
    );
}

/// Every pinned capability shipped in this repository loads with a
/// fingerprint that a second load and a clone reproduce exactly, so the
/// admission check never refuses a pinned file as loaded.
#[tokio::test]
async fn every_shipped_pinned_capability_keeps_its_fingerprint() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let mut pending = vec![root];
    let mut checked = 0;
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "yaml") {
                continue;
            }
            let pinned = std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .any(|line| line.starts_with("sha256: "));
            let first = match crate::capability::parse_capability_file(&path).await {
                Ok(first) => first,
                // A pinned file that fails to load is a failure, not a skip.
                Err(err) => {
                    assert!(!pinned, "pinned {path:?} failed to load: {err}");
                    continue;
                }
            };
            if first.providers.integrity() != crate::capability::Integrity::Verified {
                assert!(!pinned, "pinned {path:?} loaded unverified");
                continue;
            }
            let second = crate::capability::parse_capability_file(&path)
                .await
                .unwrap();
            assert_eq!(first.providers.pinned, second.providers.pinned, "{path:?}");
            assert!(
                first.providers.pinned.is_some(),
                "{path:?} has no fingerprint"
            );
            assert_eq!(
                first.clone().fingerprint(),
                first.providers.pinned,
                "{path:?}"
            );
            checked += 1;
        }
    }
    assert!(checked > 100, "only {checked} pinned files found");
}

/// Two verified definitions of one name, both pinned, that differ
/// only in their arguments. Admission passes both, so only the fingerprint in
/// the cache key keeps the second from reading the first's answer.
#[cfg(unix)]
#[tokio::test]
async fn two_pinned_definitions_of_one_name_never_share_an_answer() {
    let first = pinned_from(&pin_probe_body("Pin probe.")).await;
    let second = pinned_from(&pin_probe_body("Pin probe.").replace("echo, '1'", "echo, '2'")).await;
    assert_ne!(first.providers.pinned, second.providers.pinned);
    let executor = python_policy_executor();
    let context = CapabilityExecutionContext::default();
    let one = executor
        .execute_with_context(&first, json!({}), context.clone())
        .await
        .expect("the first runs and is cached");
    let two = executor
        .execute_with_context(&second, json!({}), context)
        .await
        .expect("the second runs");
    assert!(one.to_string().contains("\"1\""), "{one}");
    assert!(
        two.to_string().contains("\"2\""),
        "the second read the first's answer: {two}"
    );
}
