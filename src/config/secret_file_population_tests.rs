// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F18: every non-test source file that reads or writes a file directly is
//! triaged here. A new raw read fails this test until someone decides whether
//! the file it opens holds a secret or decides whom the gateway trusts.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// (path, why its raw file I/O needs no mode check, or where the check is).
const SECRET_FILE_POPULATION: &[(&str, &str)] = &[
    (
        "src/bin/provenance-eval.rs",
        "evaluation tool input; not a gateway file",
    ),
    (
        "src/capability/backend.rs",
        "capability YAML; public definitions",
    ),
    (
        "src/capability/openapi/convert.rs",
        "OpenAPI spec input; public",
    ),
    (
        "src/capability/openapi/generated.rs",
        "writes generated capability YAML; public",
    ),
    (
        "src/capability/parser.rs",
        "capability YAML; public definitions",
    ),
    (
        "src/chains/checkpoint.rs",
        "chain checkpoints; no secret, not a trust decision",
    ),
    ("src/cli/invoke.rs", "reads stdin, not a file"),
    ("src/commands/cap.rs", "capability YAML pinning; public"),
    (
        "src/commands/kubernetes.rs",
        "Kubernetes manifests input; public",
    ),
    (
        "src/commands/mod.rs",
        "init writes owner-only via config_persistence; CA cert is public (CA key goes through load_private_key)",
    ),
    (
        "src/commands/protocol_import.rs",
        "protocol import input; public",
    ),
    ("src/commands/ranking.rs", "ranking data; public"),
    (
        "src/commands/trust.rs",
        "trust report input/output; no secret",
    ),
    (
        "src/commands/upgrade.rs",
        "version stamp, 3.x pattern notice and config backup (fs::copy keeps the mode)",
    ),
    (
        "src/commands/upgrade_webhook_notice.rs",
        "empty marker file",
    ),
    (
        "src/config/mod.rs",
        "probes that the config opens; the read goes through read_secret_file",
    ),
    ("src/config/secret_file.rs", "the checked reader itself"),
    ("src/config_persistence.rs", "owner-only atomic writer"),
    (
        "src/control_plane/export.rs",
        "audit export cursor and log; no secret, append-only",
    ),
    (
        "src/control_plane/store.rs",
        "collections read through read_guarded_file (I4); raw opens are the generation probe, the 0600 writer and a dir sync",
    ),
    (
        "src/cost_accounting/persistence.rs",
        "cost ledger; no secret",
    ),
    (
        "src/discovery/config_scanner.rs",
        "other MCP clients' configs; not the gateway's files",
    ),
    ("src/fs_lock.rs", "lock files; empty"),
    (
        "src/gateway/server/control_plane_store.rs",
        "writability probe",
    ),
    ("src/gateway/ui/capabilities.rs", "capability YAML; public"),
    (
        "src/mtls/cert_manager.rs",
        "reads through read_secret_file (R1, I1, I2); writes keys 0600 (W1) and public certs",
    ),
    (
        "src/oauth/storage.rs",
        "tokens read through token_file (R2) and written 0600 (W2); client_id is public",
    ),
    (
        "src/personal_accounts/migration_source.rs",
        "own stricter check: fstat, exactly 0600 (R5)",
    ),
    (
        "src/personal_accounts/storage.rs",
        "own stricter check: O_NOFOLLOW, fstat, no group or world bits (R4)",
    ),
    (
        "src/registry/marketplace/mod.rs",
        "marketplace manifests; public",
    ),
    ("src/registry/mod.rs", "installs capability YAML; public"),
    (
        "src/runtime/provision.rs",
        "runtime provisioning manifest; public",
    ),
    (
        "src/security/firewall/audit.rs",
        "append-only audit log; no secret",
    ),
    ("src/skills/installer.rs", "skill bundles; public"),
    ("src/skills/parser.rs", "skill files; public"),
    ("src/skills/registry.rs", "skill registry; public"),
    (
        "src/tool_profiles/persistence.rs",
        "tool usage profiles; no secret",
    ),
    ("src/transition.rs", "transition state; no secret"),
    (
        "src/trust/claim_capture.rs",
        "append-only claim log; no secret",
    ),
    (
        "src/validator/cli_handler.rs",
        "capability YAML being validated; public",
    ),
];

fn is_test_path(path: &Path) -> bool {
    path.components()
        .any(|part| part.as_os_str().to_string_lossy().contains("test"))
        || path.file_name().is_some_and(|name| {
            let name = name.to_string_lossy();
            name.contains("e2e") || name.contains("fixture")
        })
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Files whose non-test code has a raw read or write. The body is cut at the
/// first `#[cfg(test)]`, and comment lines are skipped.
fn population(root: &Path) -> BTreeSet<String> {
    let raw = regex::Regex::new(
        r"fs::read\b|read_to_string|File::open|OpenOptions::new|fs::write|fs::copy|from_pem",
    )
    .expect("pattern");
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files
        .into_iter()
        .filter_map(|path| {
            let rel = path.strip_prefix(root).expect("under root").to_path_buf();
            if is_test_path(&rel) {
                return None;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            let body = text.split("#[cfg(test)]").next().unwrap_or_default();
            body.lines()
                .any(|line| !line.trim_start().starts_with("//") && raw.is_match(line))
                .then(|| rel.to_string_lossy().replace('\\', "/"))
        })
        .collect()
}

#[test]
fn fs_read_population() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let found = population(root);
    let listed: BTreeSet<String> = SECRET_FILE_POPULATION
        .iter()
        .map(|(path, _)| (*path).to_string())
        .collect();
    let untriaged: Vec<_> = found.difference(&listed).collect();
    let stale: Vec<_> = listed.difference(&found).collect();
    assert!(
        untriaged.is_empty() && stale.is_empty(),
        "untriaged raw file I/O (add a row, or route the read through read_guarded_file): \
         {untriaged:?}; rows whose file no longer has raw I/O (delete them): {stale:?}"
    );
}
