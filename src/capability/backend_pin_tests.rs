// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7814: a process provider runs only from the definition its pin was
//! checked on, and no other definition reads that one's cached answers.

use super::*;
use serde_json::json;

/// MIK-7814: `register_capability` replacing a pinned definition with an
/// unpinned one under the same name must strand the original's cached
/// answers, so the next call meets the process gate instead of the cache.
#[cfg(unix)]
#[tokio::test]
async fn re_registering_a_capability_strands_its_cached_answers() {
    use std::sync::atomic::{AtomicU64, Ordering};

    // Bare, as the shipped `gws` entry is: the gate compares the name and the
    // runner resolves it on PATH.
    let python = "python3".to_owned();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/argv_echo.py")
        .display()
        .to_string();
    let body = format!(
        "name: pin_probe\ndescription: Pin probe.\ncache:\n  ttl: 60\n  strategy: memory\n\
         providers:\n  primary:\n    service: cli\n    config:\n      command: '{python}'\n      \
         args: ['{script}', echo, '1']\n"
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pin_probe.yaml");
    std::fs::write(
        &path,
        crate::capability::rewrite_with_pin(
            &body,
            &crate::capability::compute_capability_hash(&body),
        ),
    )
    .unwrap();
    let pinned = crate::capability::parse_capability_file(&path)
        .await
        .expect("pinned file loads");
    let unpinned = crate::capability::parse_capability(&body).expect("unpinned parses");
    assert_eq!(
        unpinned.providers.integrity(),
        crate::capability::Integrity::Unpinned
    );

    let epoch = Arc::new(AtomicU64::new(0));
    let mut executor = CapabilityExecutor::new().with_policy_epoch(Arc::clone(&epoch));
    executor.process_policy.commands = vec![crate::config::ProcessCommand {
        command: python,
        args_prefix: Vec::new(),
    }];
    let backend = CapabilityBackend::new("test", Arc::new(executor));
    // The gateway snapshots the epoch, revision and profile per request.
    let request = || CapabilityExecutionContext {
        policy_epoch: Some(epoch.load(Ordering::SeqCst)),
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION.to_owned()),
        routing_profile: Some("default".to_owned()),
        ..CapabilityExecutionContext::default()
    };

    backend.register_capability(pinned).unwrap();
    backend
        .call_tool_with_context("pin_probe", json!({}), request())
        .await
        .expect("the pinned definition runs and is cached");

    backend.register_capability(unpinned).unwrap();
    let err = backend
        .call_tool_with_context("pin_probe", json!({}), request())
        .await
        .expect_err("an unpinned replacement must not be answered from cache");
    assert!(err.to_string().contains("must be pinned"), "{err}");
}

// ── MIK-7814 rev 2: the pin is bound to the whole definition ────────────────

#[cfg(unix)]
fn pin_probe_body(description: &str) -> String {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/argv_echo.py")
        .display()
        .to_string();
    format!(
        "name: pin_probe\ndescription: {description}\ncache:\n  ttl: 60\n  strategy: memory\n\
         providers:\n  primary:\n    service: cli\n    config:\n      command: 'python3'\n      \
         args: ['{script}', echo, '1']\n"
    )
}

#[cfg(unix)]
async fn pinned_from(body: &str) -> CapabilityDefinition {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe.yaml");
    std::fs::write(
        &path,
        crate::capability::rewrite_with_pin(
            body,
            &crate::capability::compute_capability_hash(body),
        ),
    )
    .unwrap();
    crate::capability::parse_capability_file(&path)
        .await
        .expect("pinned file loads")
}

#[cfg(unix)]
fn python_policy_executor() -> CapabilityExecutor {
    let mut executor = CapabilityExecutor::new();
    executor.process_policy.commands = vec![crate::config::ProcessCommand {
        command: "python3".to_owned(),
        args_prefix: Vec::new(),
    }];
    executor
}

#[cfg(unix)]
fn snapshot(epoch: &std::sync::atomic::AtomicU64) -> CapabilityExecutionContext {
    CapabilityExecutionContext {
        policy_epoch: Some(epoch.load(std::sync::atomic::Ordering::SeqCst)),
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION.to_owned()),
        routing_profile: Some("default".to_owned()),
        ..CapabilityExecutionContext::default()
    }
}

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

/// T3: replacing an mcp definition stops the children started under it.
#[cfg(unix)]
#[tokio::test]
async fn replacing_an_mcp_definition_stops_its_children() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/fake_mcp.py")
        .display()
        .to_string();
    let body = |description: &str| {
        format!(
            "name: mcp_pin_probe\ndescription: {description}\nschema:\n  input:\n    type: object\n    \
             properties:\n      operation:\n        type: string\n      text:\n        type: string\n\
             providers:\n  primary:\n    service: mcp\n    timeout: 20\n    config:\n      \
             command: 'python3'\n      args: ['{script}']\n      transport: stdio\n      \
             tool_selector:\n        param: operation\n        tools:\n          \
             say: {{ tool: echo, arguments: {{ message: \"{{text}}\" }} }}\n          \
             spawn: {{ tool: grandchild }}\n"
        )
    };
    let backend = CapabilityBackend::new("test", Arc::new(python_policy_executor()));
    backend
        .register_capability(pinned_from(&body("Probe one.")).await)
        .unwrap();
    let out = backend
        .call_tool("mcp_pin_probe", json!({"operation": "spawn"}))
        .await
        .expect("the pinned mcp definition starts a child");
    let rendered = serde_json::to_value(&out).unwrap();
    let text = rendered["content"][0]["text"].as_str().unwrap_or_default();
    let pid = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v["pid"].as_i64())
        .expect("grandchild pid")
        .to_string();
    assert_eq!(backend.executor.mcp_children.len(), 1);
    // Replaced from a plain thread with no Tokio runtime, as an embedder may.
    let replacement = pinned_from(&body("Probe two.")).await;
    let backend = Arc::new(backend);
    let registering = Arc::clone(&backend);
    std::thread::spawn(move || registering.register_capability(replacement).unwrap())
        .join()
        .unwrap();
    assert_eq!(
        backend.executor.mcp_children.len(),
        0,
        "the replaced definition's child is stopped"
    );
    let mut alive = true;
    for _ in 0..50 {
        let status = std::process::Command::new("kill")
            .args(["-0", &pid])
            .status()
            .unwrap();
        if !status.success() {
            alive = false;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(!alive, "grandchild {pid} outlived the replaced definition");
}

/// T2d: the exact pinned document parsed without the pin check (so it is
/// identical in content but `Unpinned`) must not reach the verified one's
/// cached answer.
#[cfg(unix)]
#[tokio::test]
async fn an_unpinned_copy_of_the_pinned_document_meets_the_gate() {
    let body = pin_probe_body("Pin probe.");
    let pinned_text = crate::capability::rewrite_with_pin(
        &body,
        &crate::capability::compute_capability_hash(&body),
    );
    let pinned = pinned_from(&body).await;
    let unpinned = crate::capability::parse_capability(&pinned_text).unwrap();
    assert_eq!(
        unpinned.providers.integrity(),
        crate::capability::Integrity::Unpinned
    );
    let executor = python_policy_executor();
    let context = CapabilityExecutionContext::default();
    executor
        .execute_with_context(&pinned, json!({}), context.clone())
        .await
        .expect("pinned runs and is cached");
    let err = executor
        .execute_with_context(&unpinned, json!({}), context)
        .await
        .expect_err("an unpinned copy must meet the gate, not the cache");
    assert!(err.to_string().contains("must be pinned"), "{err}");
}

/// MIK-7814 cost probe, run by hand on the benchmark host:
/// `cargo test --release --lib -- --ignored --nocapture fingerprint_cost`.
/// Prints the mean time of one definition fingerprint for the largest
/// shipped REST capability and the largest shipped process capability.
#[test]
#[ignore = "timing probe, not a check"]
fn fingerprint_cost() {
    for file in [
        "capabilities/google/calendar_create_event.yaml",
        "capabilities/security/pyghidra_reverse.yaml",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        let cap =
            crate::capability::parse_capability(&std::fs::read_to_string(path).unwrap()).unwrap();
        let rounds = 20_000u32;
        let start = std::time::Instant::now();
        for _ in 0..rounds {
            std::hint::black_box(cap.fingerprint());
        }
        let mean = start.elapsed() / rounds;
        println!("fingerprint {file}: {} ns", mean.as_nanos());
    }
}

/// MIK-7814: the gateway's outer response cache keys on the request's epoch
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
