// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! P1-idem rows FP5 and ADM-SWEEP (MIK-8192, MIK-8193): one admission
//! identity per call, whatever path admits it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::json;

use crate::gateway::meta_mcp::admission::{OPERATION_DEFINING_META, operation_arguments};

/// FP5 (`MIK-8192`): the allow-list is the only door a `_meta` key has into
/// an operation fingerprint. Shipped empty, a call differing only in `_meta`
/// fingerprints alike; a key on a list fingerprints apart.
#[test]
fn fp5_only_the_allow_list_puts_meta_into_the_fingerprint() {
    let call =
        |token: &str| json!({"chain": [], "_meta": {"progressToken": token, "io.example/x": 1}});
    assert!(
        OPERATION_DEFINING_META.is_empty(),
        "a key was added: review FP5"
    );
    assert_eq!(
        operation_arguments(&call("a"), OPERATION_DEFINING_META),
        operation_arguments(&call("b"), OPERATION_DEFINING_META),
        "per-request _meta changed the fingerprint"
    );
    assert_eq!(
        operation_arguments(&call("a"), OPERATION_DEFINING_META),
        json!({"chain": []}),
        "nothing allowed remains, so no _meta is kept"
    );
    let listed = ["progressToken"];
    assert_ne!(
        operation_arguments(&call("a"), &listed),
        operation_arguments(&call("b"), &listed),
        "an allow-listed key must change the fingerprint"
    );
}

/// The non-test Rust sources under `src/`, as (path relative to it, text).
fn sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(&root) {
        let entry = entry.expect("src is readable");
        if entry.path().extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let rel = entry.path().strip_prefix(&root).expect("under src");
        let rel = rel.to_string_lossy().replace('\\', "/");
        let in_test_dir = rel
            .split('/')
            .rev()
            .skip(1)
            .any(|dir| dir.ends_with("tests"));
        if rel.ends_with("tests.rs") || rel.ends_with("_test.rs") || in_test_dir {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).expect("readable source");
        out.push((rel, text));
    }
    out
}

/// ADM-SWEEP (`MIK-8193`): every production admission of a call goes through
/// one owner spelling. The synchronous lease is entered only through
/// `admit_meta_sync` and the direct route's `direct_route_admission`
/// (MIK-8154), each call site naming its `AdmissionOwner` (HTTP and the direct
/// route: the routed task owner; stdio: the reserved local owner);
/// `admit_sync` is called only from those two; and an execution admission
/// request is built only at the reviewed sites. A new path fails here until it
/// is reviewed into the lists.
#[test]
fn adm_sweep_every_admission_uses_one_owner_spelling() {
    let failures = adm_sweep(&sources());
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A1 (MIK-8154): the sweep is not vacuous. An `admit_sync` call planted in
/// an unreviewed file, and the direct route's site naming a free-standing
/// owner, each fail it.
#[test]
fn a1_the_sweep_fails_a_planted_site_and_a_free_standing_owner() {
    let mut planted = sources();
    planted.push((
        "gateway/router/planted.rs".to_owned(),
        "meta.admit_sync(true, None, Some(\"owner\"), r, s, t, a, || x, id)".to_owned(),
    ));
    assert!(
        !adm_sweep(&planted).is_empty(),
        "a planted admit_sync passed"
    );
    let mut free = sources();
    let site = free
        .iter_mut()
        .find(|(rel, _)| rel == "gateway/router/backend_handlers/direct_idempotency.rs")
        .expect("the direct route's admission site");
    site.1 = site.1.replace(
        "AdmissionOwner::routed(&admission_owner)",
        "AdmissionOwner::routed(\"anyone\")",
    );
    assert!(!adm_sweep(&free).is_empty(), "a free-standing owner passed");
}

/// The sweep over `sources`: every failure found, empty when it holds.
fn adm_sweep(sources: &[(String, String)]) -> Vec<String> {
    let expected_sync: BTreeMap<&str, &str> = [
        (
            "gateway/router/handlers/dispatch_tools_call.rs",
            "AdmissionOwner::routed(admission_owner)",
        ),
        (
            "gateway/server/stdio_dispatch.rs",
            "AdmissionOwner::local_operator()",
        ),
        (
            "gateway/router/backend_handlers/direct_idempotency.rs",
            "AdmissionOwner::routed(&admission_owner)",
        ),
    ]
    .into_iter()
    .collect();
    let expected_modes: BTreeSet<&str> = [
        "gateway/meta_mcp/admission.rs",
        "gateway/task_service/execution/context.rs",
        "idempotency/admission_tasks.rs",
    ]
    .into_iter()
    .collect();
    let expected_admit_sync: BTreeSet<&str> = [
        "gateway/meta_mcp/admission.rs",
        "gateway/meta_mcp/direct_route.rs",
    ]
    .into_iter()
    .collect();
    let mut sync_sites = BTreeMap::new();
    let mut mode_sites = BTreeSet::new();
    let mut admit_sync_sites = BTreeSet::new();
    for (rel, text) in sources {
        for entry in [".admit_meta_sync(", ".direct_route_admission("] {
            for (at, _) in text.match_indices(entry) {
                let owner = text[at..]
                    .split(',')
                    .next()
                    .map(|first| first.trim_start_matches(entry).trim().to_owned())
                    .unwrap_or_default();
                sync_sites.insert(rel.clone(), owner);
            }
        }
        if text.contains(".admit_sync(") {
            admit_sync_sites.insert(rel.clone());
        }
        if text.contains("mode: Mode::Sync") || text.contains("mode: Mode::Task") {
            mode_sites.insert(rel.clone());
        }
    }
    let mut failures = Vec::new();
    for (file, owner) in &sync_sites {
        let want = expected_sync
            .get(file.as_str())
            .copied()
            .unwrap_or("<unreviewed site>");
        if !owner.ends_with(want) {
            failures.push(format!(
                "{file}: the lease entry must name the reviewed owner {want}, got {owner}"
            ));
        }
    }
    let sync_files: BTreeSet<&str> = sync_sites.keys().map(String::as_str).collect();
    let expected_files: BTreeSet<&str> = expected_sync.keys().copied().collect();
    if sync_files != expected_files {
        failures.push(format!("lease entry sites changed: {sync_files:?}"));
    }
    let admit_sync: BTreeSet<&str> = admit_sync_sites.iter().map(String::as_str).collect();
    if admit_sync != expected_admit_sync {
        failures.push(format!(
            "admit_sync called outside the two owner-spelling entry points: {admit_sync:?}"
        ));
    }
    let modes: BTreeSet<&str> = mode_sites.iter().map(String::as_str).collect();
    if modes != expected_modes {
        failures.push(format!(
            "execution admission requests built elsewhere: {modes:?}"
        ));
    }
    failures
}
