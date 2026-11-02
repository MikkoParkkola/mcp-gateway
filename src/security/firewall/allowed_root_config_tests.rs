// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config-level rows: the design's section 1 example, a name clash present
//! at load, and one finding per rule and argument across candidate keys
//! (D4, D4b, R23e, R34c). Batch 4b.

use std::sync::Arc;

use serde_json::json;

use super::super::*;
use super::tree::{Fx, Seen, backend, root_rule, seen, stdio};
use crate::backend::BackendRegistry;
use crate::security::firewall::{Firewall, ScanType};
use crate::security::response_policy::{KeyOf, RuleTarget, ServerOf};

/// Design section 1's example, verbatim but for its two roots, which a row
/// points at temporary folders. D1 checks UPGRADING carries the same text.
pub(super) const EXAMPLE: &str = r#"security:
  firewall:
    rules:
      - match: "read_text_file"
        servers: ["filesystem"]
        action: block
        reason: "files stay in the project folder"
        allowed_roots: ["/srv/data", "~/projects"]
        path_args: ["path"]
      - match: "read_multiple_files"
        servers: ["filesystem"]
        action: block
        allowed_roots: ["/srv/data", "~/projects"]
        path_args: ["paths[]"]
      - match: "move_file"
        servers: ["filesystem"]
        action: block
        allowed_roots: ["/srv/data", "~/projects"]
        path_args: ["source", "destination"]
"#;

fn load(yaml: &str) -> Result<crate::config::Config, String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    crate::config::Config::load(Some(&path)).map_err(|e| e.to_string())
}

fn on(tool: &str) -> RuleTarget<'_> {
    RuleTarget {
        server: ServerOf::Backend("filesystem"),
        tool,
        key: KeyOf::NoKey,
    }
}

/// D4 [keep]: the example parses; D4b: its compiled rules allow inside
/// calls to `read_text_file` and `move_file` and refuse an outside one.
#[test]
fn d4_d4b_section_one_example_loads_and_confines() {
    let (a, b, out) = (tempdir(), tempdir(), tempdir());
    let (a_path, b_path) = (a.path().to_string_lossy(), b.path().to_string_lossy());
    // Single-quoted scalars: a Windows path's `\` is an escape in a
    // double-quoted one.
    let quoted = |p: &str| format!("'{}'", p.replace('\'', "''"));
    let yaml = EXAMPLE
        .replace("\"/srv/data\"", &quoted(&a_path))
        .replace("\"~/projects\"", &quoted(&b_path));
    let config = load(&yaml).expect("D4: the example loads");
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend("filesystem", stdio())));
    let fw = Firewall::from_config(config.security.firewall, None).with_registries(
        Arc::clone(&registry),
        Arc::new(parking_lot::RwLock::new(None)),
    );
    let sender = registry.get("filesystem");
    let check = |tool: &str, args: serde_json::Value| {
        seen(&fw.rescan(
            fw.startup_policy(),
            on(tool),
            &args,
            ScanSubject::Arguments,
            sender.as_deref(),
        ))
    };
    let inside = json!({"path": format!("{a_path}/notes.md")});
    assert_eq!(check("read_text_file", inside), Seen::Allowed, "D4b");
    let moved = json!({"source": format!("{a_path}/x"), "destination": format!("{b_path}/x")});
    assert_eq!(check("move_file", moved), Seen::Allowed, "D4b");
    let outside = json!({"path": format!("{}/x", out.path().to_string_lossy())});
    assert_eq!(
        check("read_text_file", outside),
        Seen::Outside(FirewallAction::Block),
        "D4b"
    );
}

fn tempdir() -> tempfile::TempDir {
    crate::test_tempdir::tempdir()
}

/// R23e [keep]: a backend named like the capabilities backend at load is
/// refused by the existing validation, naming both.
#[test]
fn r23e_name_clash_at_load_is_refused() {
    let err = load("capabilities:\n  name: fs\nbackends:\n  fs:\n    command: \"true\"\n")
        .expect_err("a clash at load is refused");
    assert!(err.contains("capabilities.name"), "{err}");
    assert!(err.contains("backends.fs"), "{err}");
}

/// R34c: under `NotKnown` with two named candidate keys, an outside path gives
/// exactly one root finding for the rule and argument.
#[test]
fn r34c_one_finding_per_rule_and_argument() {
    let fx = Fx::with_rules(|safe| {
        let mut rule = root_rule("read_file", &[safe], &["path"], FirewallAction::Block);
        rule.keys = Some(vec!["k1".to_string(), "k2".to_string()]);
        vec![rule]
    });
    let target = RuleTarget {
        server: ServerOf::Backend("fs"),
        tool: "read_file",
        key: KeyOf::NotKnown,
    };
    let args = json!({"path": fx.path("outside/f")});
    let sender = fx.sender();
    let verdict = fx.fw.rescan(
        fx.fw.startup_policy(),
        target,
        &args,
        ScanSubject::Arguments,
        sender.as_deref(),
    );
    let found = verdict
        .findings
        .iter()
        .filter(|f| f.scan_type == ScanType::PathOutsideRoot)
        .count();
    assert_eq!(found, 1, "{verdict:?}");
}
