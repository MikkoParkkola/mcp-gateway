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
        "src/capability/backend_rug_pull.rs",
        "capability YAML; public definitions",
    ),
    (
        "src/capability/file_writer.rs",
        "capability YAML; public definitions; written under the directory lock",
    ),
    (
        "src/capability/pin_file.rs",
        "capability YAML; public definitions; written under the directory lock",
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
        "src/capability/executor/save_file.rs",
        "writes a fetched attachment, create-new at 0600 under the downloads root; reads none",
    ),
    (
        "src/chains/checkpoint.rs",
        "chain checkpoints; no secret, not a trust decision",
    ),
    ("src/cli/invoke.rs", "reads stdin, not a file"),
    (
        "src/commands/doctor/lease_custody.rs",
        "doctor reads /proc/swaps and /sys/block/dm-*/dm/uuid; kernel tables, no secret",
    ),
    (
        "src/commands/doctor/lease_custody.rs",
        "doctor reads /proc/swaps and /sys/block/dm-*/dm/uuid; kernel tables, no secret",
    ),
    (
        "src/commands/config_export/mod.rs",
        "third-party MCP client config JSON edited to add the gateway entry; no gateway secret",
    ),
    (
        "src/commands/dashboard_link.rs",
        "operator-named client cert, key and CA for one request (#1832); the mode-checked read is lib-internal, widening it was declined",
    ),
    (
        "src/commands/regular_file.rs",
        "gateway.yaml re-read by doctor (after Config::load's mode-checked read; prints key names, never values) and by upgrade (to rename backend url keys; prints line numbers and backend names, never values); opened as the loader opens it (O_NONBLOCK|O_NOCTTY, follows a symlink), regular files only, no size limit (as the guarded reader for config); the mode-checked read is lib-internal, widening it was declined",
    ),
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
        "src/commands/trust/baseline.rs",
        "TrustLab baseline and registry manifest files; no secret",
    ),
    (
        "src/commands/trust/lab.rs",
        "TrustLab active-fixture spec input; no secret",
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
    (
        "src/config/record_key.rs",
        "the record key file: read through read_file_ref (the guarded reader), \
         created at 0600 by create_new_private; File::open only fsyncs its directory",
    ),
    ("src/config/secret_file.rs", "the checked reader itself"),
    ("src/config_persistence.rs", "owner-only atomic writer"),
    (
        "src/config_persistence_scratch.rs",
        "the scratch-and-rename writer: creates its scratch file owner-only (0600 / owner-only DACL)",
    ),
    (
        "src/config_persistence_atomic.rs",
        "the shared atomic writer: creates its own private scratch; opens the target only to probe its ACL, never reads it",
    ),
    (
        "src/config_persistence_atomic_windows.rs",
        "the atomic writer's Windows half: opens the save target with READ_CONTROL only, to read its access list; never reads its bytes",
    ),
    (
        "src/config_persistence_journal.rs",
        "the replace journal (paths, SHA-256 revisions and a state; no secret) and the staged \
         original of gateway.yaml, both created owner-only by create_new_private; the original is \
         checked against the journal's digest before it is written back; File::open only fsyncs \
         its directory",
    ),
    (
        "src/config_persistence_lock.rs",
        "config lock file; opened only to judge its mode, never read",
    ),
    (
        "src/config_reload/grant_audit_plan.rs",
        "grant audit state: journal ids and grant digests; no secret",
    ),
    (
        "src/config_reload/replace.rs",
        "re-reads gateway.yaml under the config lock to check the caller's revision and stage the \
         original; the target is the canonical path this gateway loaded at start, and every write \
         back is owner-only",
    ),
    (
        "src/config_reload/replace_audit.rs",
        "reads gateway.yaml under the config lock only to hash it for a recovery intent's base \
         revision; the bytes are hashed, never kept or logged",
    ),
    (
        "src/control_plane/export.rs",
        "audit export cursor and log; no secret, append-only",
    ),
    (
        "src/control_plane/store/file_io.rs",
        "collections read through read_guarded_file (I4); raw opens are the generation probe, the 0600 writer and a dir sync",
    ),
    (
        "src/cost_accounting/persistence.rs",
        "cost ledger; no secret",
    ),
    (
        "src/counters/persist.rs",
        "call counters and markers; no secret",
    ),
    (
        "src/debug_trust_roots.rs",
        "debug builds only (MIK-8188): a test CA PEM named by MCP_GATEWAY_TEST_TRUST_CA, public certificates and no secret; the binary's copy (dashboard-link) cannot reach the lib-internal mode-checked read, as dashboard_link.rs cannot; release builds compile no read",
    ),
    (
        "src/discovery/config_scanner.rs",
        "other MCP clients' configs; not the gateway's files",
    ),
    (
        "src/discovery/config_scanner_client_scan.rs",
        "other MCP clients' configs, opened to tell a permission refusal from a bad file before the parse; not the gateway's files",
    ),
    ("src/fs_lock.rs", "lock files; empty"),
    ("src/fs_lock_windows.rs", "lock files; empty"),
    (
        "src/events/records.rs",
        "events store records read through read_checked_bytes (EventsRecord, 0600); File::open only opens the store directory to fsync it",
    ),
    (
        "src/gateway/mod.rs",
        "test_helpers fixture writer, not a gateway read",
    ),
    (
        "src/gateway/server/control_plane_store.rs",
        "writability probe",
    ),
    (
        "src/transport/stdio_cache.rs",
        "writability probe for a backend's package cache: creates, writes and removes its own marker; reads nothing",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/packaged.rs",
        "cfg(test) helper reading the repo files the MIK-8387/MIK-8481 pins check (registry-ban clippy.toml, pre-push.sh, the CI workflow); no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/shipped_reads.rs",
        "cfg(test) source scanner reading Cargo.toml and the crate's own sources for the MIK-8481 unshipped-read guard; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/creation_sites.rs",
        "cfg(test) scanner for the file-creation inventory, reading the crate's own sources; its fs::write calls are quoted syntax in a scanner test, never run; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/scan.rs",
        "cfg(test) source scanner reading the crate's own source for the MIK-8387 boundary pins; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/invoke_stages.rs",
        "cfg(test) source scanner reading the invoke stage files for the MIK-8488 stage pin; no secret",
    ),
    (
        "src/gateway/meta_mcp/sealed_hold_guards.rs",
        "cfg(test) source scanner reading the crate's own src/gateway files (MIK-8176 A1); no secret",
    ),
    (
        "src/gateway/task_service/store_unix.rs",
        "task records: O_NOFOLLOW open, fstat mode 0600 checked (RECORD_MODE)",
    ),
    (
        "src/gateway/task_service/execution/pause_hook.rs",
        "debug-build test hook writing a task id marker (#2298); compiled out of release",
    ),
    ("src/gateway/ui/capabilities.rs", "capability YAML; public"),
    (
        "src/identity_grants/journal.rs",
        "grant-change journal append; O_NOFOLLOW, owner-only; no secret",
    ),
    (
        "src/mtls/cert_manager.rs",
        "reads through read_secret_file (R1, I1, I2); writes keys 0600 (W1) and public certs",
    ),
    (
        "src/oauth/storage.rs",
        "tokens read through token_file (R2) and written 0600 (W2); client_id is public",
    ),
    (
        "src/open_nonblocking.rs",
        "the loader's mode-checked read (config_persistence read_text), the guarded secret-file read and the CLI's gateway.yaml re-read (commands/regular_file.rs); opens with O_NONBLOCK|O_NOCTTY so a FIFO is refused, not waited on",
    ),
    (
        "src/personal_accounts/commit.rs",
        "creates a commit's scratch file owner-only (0600, create_new) to write it; reads no secret file",
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
        "src/preview_sandbox/linux/mod.rs",
        "kernel settings under /proc/sys, read to name why a host refuses user namespaces; no secret",
    ),
    (
        "src/preview_sandbox/linux/mounts.rs",
        "inside the sandbox's own mount namespace: empty mountpoint files and /proc/self/mountinfo; no secret",
    ),
    (
        "src/preview_sandbox/mod.rs",
        "the sandboxed child's stderr pipe, capped at 64 KiB, to classify a refusal; not a file",
    ),
    (
        "src/private_fs.rs",
        "Windows store custody: no-follow open, DACL judged on the handle (ADR-016)",
    ),
    (
        "src/playbook/engine/mod.rs",
        "playbook YAML definitions; public",
    ),
    (
        "src/protocol_revision_telemetry/durable.rs",
        "telemetry window counters in a 0700 directory; no secret",
    ),
    (
        "src/protocol_revision_telemetry/window.rs",
        "U1 v2 window counters in the same 0700 directory; no secret",
    ),
    (
        "src/protocol_revision_telemetry/window_decide.rs",
        "operator decision.json beside the U1 window (test-only); no secret",
    ),
    ("src/ranking/ranker.rs", "tool usage counts JSON; no secret"),
    ("src/registry/mod.rs", "installs capability YAML; public"),
    (
        "src/runtime/provision.rs",
        "runtime provisioning manifest; public",
    ),
    (
        "src/secret_store/index.rs",
        "the secret-entry index: names, stores and timestamps, never a value; created owner-only",
    ),
    (
        "src/security/firewall/audit.rs",
        "append-only audit log; no secret",
    ),
    (
        "src/security/transparency_log.rs",
        "the logger's bounded reads of its own audit log files (the tail at open); no secret",
    ),
    (
        "src/security/transparency_log_anchor.rs",
        "reads an operator-copied audit high-water mark, bounded; no secret",
    ),
    (
        "src/security/transparency_log_append.rs",
        "audit log writer; reopens only to cut back a torn tail; no secret",
    ),
    (
        "src/security/transparency_log_hwm_scan.rs",
        "reads audit log segments for a missing-mark finding; no secret",
    ),
    (
        "src/security/transparency_log_pager.rs",
        "reads audit log windows to page it backward; no secret",
    ),
    (
        "src/security/transparency_log_rotation.rs",
        "rotates the audit log: seal, rename, open record, reserve; no secret",
    ),
    (
        "src/security/transparency_log_segments.rs",
        "audit log segments, high-water mark and reserve; no secret",
    ),
    (
        "src/security/transparency_log_session.rs",
        "reads audit log segments for one session's entries; no secret",
    ),
    (
        "src/security/transparency_log_verify.rs",
        "reads audit log segments to verify the chain; no secret",
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
        "src/trust/export_verify.rs",
        "reads an Activity export bundle given to audit verify; no secret",
    ),
    (
        "src/trust/provenance_public_cli.rs",
        "`provenance verify` CLI: the operator-named public-key trust set, receipt and result; public data, read once by an offline command the running gateway never consults",
    ),
    (
        "src/validator/cli_handler.rs",
        "capability YAML being validated; public",
    ),
    (
        "src/win_acl.rs",
        "Windows store custody: reopens a just-created file for delete on the handle (ADR-016)",
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

/// Whether a source file's non-test code has a raw read or write. Each
/// `#[cfg(test)]` item is left out by its own extent (an early test module
/// or test-only `use` never hides the production code after it). Comment
/// lines are skipped.
fn has_raw_io(text: &str) -> bool {
    static RAW: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"fs::read\b|read_to_string|File::open|OpenOptions::new|fs::write|fs::copy|from_pem",
        )
        .expect("pattern")
    });
    crate::test_source_text::production_text(text)
        .lines()
        .any(|line| !line.trim_start().starts_with("//") && RAW.is_match(line))
}

/// Files whose non-test code has a raw read or write ([`has_raw_io`]).
fn population(root: &Path) -> BTreeSet<String> {
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
            has_raw_io(&text).then(|| rel.to_string_lossy().replace('\\', "/"))
        })
        .collect()
}

/// A raw open placed after an early inline test module is production code
/// and counts: the test module's own block is what is left out, not the
/// rest of the file.
#[test]
fn a_raw_open_after_an_early_test_module_counts() {
    let source = "\
fn product() {}

#[cfg(test)]
pub(crate) mod seam {
    pub(crate) fn hook() {}
}

pub fn reader(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}
";
    assert!(
        has_raw_io(source),
        "the open after the test module was not seen"
    );
}

/// The test module's own raw I/O does not count.
#[test]
fn raw_io_inside_an_inline_test_module_does_not_count() {
    let source = "\
fn product() {}

#[cfg(test)]
mod tests {
    fn fixture() -> String {
        std::fs::read_to_string(\"x\").unwrap()
    }
}
";
    assert!(!has_raw_io(source));
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
