// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Capability pin policy enforcement (`MIK-7235.PIN.1`).
//!
//! Two standing checks over the whole shipped catalogue:
//!
//! 1. **Coverage** — every high-privilege capability in the production
//!    catalogue carries a `sha256:` pin, unless it is on [`PIN_EXCLUSIONS`].
//! 2. **Drift** — every file that carries a pin still matches its recomputed
//!    hash, i.e. re-pinning it would be a no-op.
//!
//! The privilege rule and the exclusion reasons are written up in
//! `docs/capability-pin-policy.md`; this file is their single machine-readable
//! source of truth.

use std::path::{Path, PathBuf};

use mcp_gateway::capability::compute_capability_hash;
use serde_yaml::Value;

/// Catalogue subtree holding copy-and-edit templates rather than shipped
/// capabilities. `capabilities/README.md` and the frozen ranking baseline use
/// the same boundary when counting the shipped inventory.
const TEMPLATE_PREFIX: &str = "capabilities/examples/";

/// High-privilege capabilities that deliberately carry no `sha256:` pin.
///
/// Every entry must be justified by something other than "pinning it was
/// inconvenient". See `docs/capability-pin-policy.md`.
const PIN_EXCLUSIONS: &[(&str, &str)] = &[
    (
        "capabilities/examples/github_graphql.yaml",
        "copy-and-edit template for the GraphQL provider; edited in place by the reader",
    ),
    (
        "capabilities/examples/github_integration.yaml",
        "copy-and-edit template for a multi-tool integration",
    ),
    (
        "capabilities/examples/github_user.yaml",
        "copy-and-edit template; the simplest REST example in the docs",
    ),
    (
        "capabilities/examples/jsonrpc_example.yaml",
        "copy-and-edit template for the JSON-RPC provider",
    ),
    (
        "capabilities/examples/linear_integration.yaml",
        "copy-and-edit template for the Linear integration",
    ),
];

/// Privilege class of a capability, per `docs/capability-pin-policy.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Privilege {
    /// Reaches a credential, an outbound write, or local process execution.
    High,
    /// Unauthenticated read-only `GET` against a public endpoint.
    Low,
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every `*.yaml` / `*.yml` file under `capabilities/`, as repo-relative
/// forward-slash paths paired with their absolute path.
fn catalogue_files() -> Vec<(String, PathBuf)> {
    let root = repo_root();
    let mut files: Vec<(String, PathBuf)> = walkdir::WalkDir::new(root.join("capabilities"))
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
        .map(|entry| {
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .replace('\\', "/");
            (rel, entry.path().to_path_buf())
        })
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no capability YAMLs found under {}",
        root.join("capabilities").display()
    );
    files
}

/// Provider blocks, whether `providers:` is a mapping or a sequence.
fn providers(doc: &Value) -> Vec<&Value> {
    match doc.get("providers") {
        Some(Value::Mapping(map)) => map.values().collect(),
        Some(Value::Sequence(seq)) => seq.iter().collect(),
        _ => Vec::new(),
    }
}

/// Classify one capability document. Fails closed: anything that does not
/// parse, or that omits the fields the rule reads, is [`Privilege::High`].
fn classify(content: &str) -> Privilege {
    let Ok(doc) = serde_yaml::from_str::<Value>(content) else {
        return Privilege::High;
    };

    // P1 — holds a credential. Only an explicit `auth.required: false` clears it.
    let holds_credential = doc
        .get("auth")
        .and_then(|auth| auth.get("required"))
        .and_then(Value::as_bool)
        != Some(false);

    // P2 — declares an outbound write. Only an explicit `read_only: true` clears it.
    let declares_write = doc
        .get("metadata")
        .and_then(|meta| meta.get("read_only"))
        .and_then(Value::as_bool)
        != Some(true);

    // P3 — writes by verb, whatever the metadata label claims.
    // P4 — spawns a local process, so a rewritten file is arbitrary code.
    let mut writes_by_verb = false;
    let mut spawns_process = false;
    for provider in providers(&doc) {
        let config = provider.get("config");
        if let Some(method) = config
            .and_then(|config| config.get("method"))
            .and_then(Value::as_str)
        {
            writes_by_verb |= method != "GET";
        }
        let service = provider.get("service").and_then(Value::as_str);
        spawns_process |= matches!(service, Some("cli" | "mcp"))
            || config.and_then(|config| config.get("command")).is_some();
    }

    if holds_credential || declares_write || writes_by_verb || spawns_process {
        Privilege::High
    } else {
        Privilege::Low
    }
}

/// The top-level `sha256:` pin, if the file carries one. Nested `sha256:`
/// keys are indented and therefore ignored, matching `capability::hash`.
fn embedded_pin(content: &str) -> Option<&str> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("sha256:"))
        .map(str::trim)
}

// ── Coverage ────────────────────────────────────────────────────────────────

#[test]
fn every_high_privilege_production_capability_is_pinned() {
    let excluded: Vec<&str> = PIN_EXCLUSIONS.iter().map(|(path, _)| *path).collect();

    let mut unpinned = Vec::new();
    for (rel, abs) in catalogue_files() {
        if rel.starts_with(TEMPLATE_PREFIX) || excluded.contains(&rel.as_str()) {
            continue;
        }
        let content = std::fs::read_to_string(&abs).expect("capability file must be readable");
        if classify(&content) == Privilege::High && embedded_pin(&content).is_none() {
            unpinned.push(rel);
        }
    }

    assert!(
        unpinned.is_empty(),
        "{} high-privilege capabilities carry no sha256: pin. Run `mcp-gateway cap pin <file>` \
         on each, or record it in PIN_EXCLUSIONS with a reason \
         (see docs/capability-pin-policy.md):\n  {}",
        unpinned.len(),
        unpinned.join("\n  "),
    );
}

// ── Drift ───────────────────────────────────────────────────────────────────

#[test]
fn every_pinned_capability_matches_its_recomputed_hash() {
    let mut drifted = Vec::new();
    let mut checked = 0usize;

    for (rel, abs) in catalogue_files() {
        let content = std::fs::read_to_string(&abs).expect("capability file must be readable");
        let Some(pin) = embedded_pin(&content) else {
            continue;
        };
        checked += 1;
        let actual = compute_capability_hash(&content);
        if !pin.eq_ignore_ascii_case(&actual) {
            drifted.push(format!("{rel}: pinned {pin}, actual {actual}"));
        }
    }

    assert!(
        drifted.is_empty(),
        "{} pinned capabilities no longer match their contents. Re-pin with \
         `mcp-gateway cap pin <file>`:\n  {}",
        drifted.len(),
        drifted.join("\n  "),
    );
    assert!(
        checked > 0,
        "no pinned capabilities found — the drift check would be vacuous"
    );
}

// ── The exclusion list itself ───────────────────────────────────────────────

#[test]
fn every_exclusion_names_a_real_high_privilege_file_with_a_reason() {
    for (rel, reason) in PIN_EXCLUSIONS {
        let abs = repo_root().join(rel);
        let content = std::fs::read_to_string(&abs)
            .unwrap_or_else(|e| panic!("excluded capability {rel} must exist: {e}"));
        assert_eq!(
            classify(&content),
            Privilege::High,
            "{rel} is low-privilege, so it needs no exclusion — drop the entry"
        );
        assert!(
            reason.len() > 20,
            "{rel} needs a real reason, not '{reason}'"
        );
    }
}

// ── The classifier ──────────────────────────────────────────────────────────

#[test]
fn classifier_flags_each_privilege_disjunct_independently() {
    let low = "auth:\n  required: false\nmetadata:\n  read_only: true\nproviders:\n  primary:\n    service: rest\n    config:\n      method: GET\n";
    assert_eq!(classify(low), Privilege::Low, "baseline must be low");

    let credential = low.replace("required: false", "required: true");
    assert_eq!(classify(&credential), Privilege::High, "P1 credential");

    let write = low.replace("read_only: true", "read_only: false");
    assert_eq!(classify(&write), Privilege::High, "P2 declared write");

    let verb = low.replace("method: GET", "method: POST");
    assert_eq!(classify(&verb), Privilege::High, "P3 non-GET verb");

    let local = low.replace("service: rest", "service: cli");
    assert_eq!(classify(&local), Privilege::High, "P4 local process");
}

#[test]
fn classifier_fails_closed_on_missing_or_unparseable_input() {
    assert_eq!(
        classify("name: broken\n  bad indent: ["),
        Privilege::High,
        "unparseable YAML must classify high"
    );
    assert_eq!(
        classify("name: bare\n"),
        Privilege::High,
        "missing auth and metadata must classify high"
    );
}
