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
        "src/cli_support/init.rs",
        "init creates its own config and sample files with create_new and removes them on rollback; the admin token goes through the secret store, never a raw file here; it reads no existing secret file",
    ),
    (
        "src/commands/add_remove.rs",
        "`add --env-file FILE`: the operator-named JSON of env values, read bounded (64 KiB + 1); the values go through the store rule, never echoed; not a gateway secret file",
    ),
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
        "src/commands/api.rs",
        "operator-named request body for one api call (--data @FILE), read size-capped at 16 MiB and sent as given; not a config or secret file",
    ),
    (
        "src/commands/dashboard_link.rs",
        "operator-named client cert, key and CA for one request (#1832); the mode-checked read is lib-internal, widening it was declined",
    ),
    (
        "src/commands/regular_file.rs",
        "gateway.yaml read for reports that write nothing: doctor's key names (after Config::load's mode-checked read; never values) and the upgrade dry run's URL-key report (line numbers and backend names, never values); the upgrade rewrite itself reads under the config lock through the guard; opened as the loader opens it (O_NONBLOCK|O_NOCTTY, follows a symlink), regular files only, no size limit",
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
        "version stamp, the 3.0.0 notice's read-only posture read (prints a notice, writes nothing from it) and the config backup (fs::copy keeps the mode)",
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
        "src/config_persistence.rs",
        "the shared directory sync: File::open on a directory only to fsync it; reads no file bytes",
    ),
    (
        "src/config_persistence_commit.rs",
        "the config commit primitive's read-back: opens gateway.yaml (unix: without waiting; \
         Windows: read-write without write or delete sharing) only to check it is a regular file, \
         flush it and hash its bytes against the revision it just wrote; never parses or returns \
         the bytes",
    ),
    (
        "src/config_persistence_journal_v2_drain_handover.rs",
        "the handover writer: opens the abandoned file (unix: no symlink follow, without waiting) \
         and checks the OPENED handle before any read, on every path (also for a file it created \
         itself): on unix a regular file, owned by this user, one link, no group or other \
         permission bit; elsewhere the handover refuses before it writes or reads anything, until the \
         owner check through win_acl lands (a tracked precondition of the startup caller); reads it only to prove it against the donor journal; it holds frozen \
         journal records, not credentials",
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
        "src/gateway/health_metrics/memory.rs",
        "/proc/self/statm, the process's own memory counters; nothing secret",
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
        "src/security/transparency_log_sigstart.rs",
        "reads the audit log's own files: its signing anchor, `.hwm` and segments, to judge unsigned entries; no secret",
    ),
    (
        "src/health_history/file.rs",
        "the gateway's own health.json in its data directory: numbers and fixed words, never a client's data; nothing secret",
    ),
    (
        "src/transport/stdio_cache.rs",
        "writability probe for a backend's package cache: creates, writes and removes its own marker; reads nothing",
    ),
    (
        "src/transport/stdio_sweep_linux.rs",
        "the descendant sweep's Linux process table: reads /proc/<pid>/stat (pid, parent, state, start time); no file of the operator's, nothing secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/packaged.rs",
        "cfg(test) helper reading the repo files the MIK-8387/MIK-8481 pins check (registry-ban clippy.toml, pre-push.sh, the CI workflow); no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/fragments.rs",
        "cfg(test) loader reading the boundary-pin tables and their fragment files beside them, and writing scratch copies of them for its own tests; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/plain_reads.rs",
        "cfg(test) plain-read inventory: walks the crate's own sources and writes one fixture crate in a temp dir; its fixture text names plain reads; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/shipped_reads.rs",
        "cfg(test) source scanner reading Cargo.toml and the crate's own sources for the MIK-8481 unshipped-read guard; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/email_sinks.rs",
        "cfg(test) scanner for the email-sink inventory, reading the crate's own sources; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/secret_writers.rs",
        "cfg(test) pin reading the repo's own init admin-token test source to check its rows exist; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/creation_sites.rs",
        "cfg(test) scanner for the file-creation inventory, reading the crate's own sources; its fs::write calls are quoted syntax in a scanner test, never run; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/read_history_access.rs",
        "cfg(test) source scanner reading the crate's own sources to find which production files name the read history; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/scan.rs",
        "cfg(test) source scanner reading the crate's own source for the MIK-8387 boundary pins; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/caller_view.rs",
        "cfg(test) source scanner reading the crate's own sources to count unfiltered capability-provider reads; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/identity_sources.rs",
        "cfg(test) identity-source pin: hashes the bytes of the three identity-type source files; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/invoke_stages.rs",
        "cfg(test) source scanner reading the invoke stage files for the MIK-8488 stage pin; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/backend_json_rpc_builders.rs",
        "cfg(test) source scanner for the backend JSON-RPC builder pin; its self-tests write a one-file fixture crate into a tempdir; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/fold_sites.rs",
        "cfg(test) source scanner for the fold and count site pin; its self-tests write a one-file fixture crate into a tempdir; no secret",
    ),
    (
        "src/gateway/meta_mcp/boundary_pins/pinned_role_mapping.rs",
        "cfg(test) source scanner for the role-mapping guard, reading the crate's own sources and writing a fixture crate to a temp dir for its own test; no secret",
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
        "src/mutant_scan.rs",
        "lists and reads tracked .rs source files for mutant! sites (tests and the mutants runner); no secret",
    ),
    (
        "src/oauth/storage.rs",
        "tokens read through token_file (R2) and written 0600 (W2); client_id is public",
    ),
    (
        "src/open_nonblocking.rs",
        "the guarded secret-file read (every gateway.yaml read that feeds a write goes through it), the atomic writer's ACL probe and the CLI's read-only gateway.yaml reports (commands/regular_file.rs); opens with O_NONBLOCK|O_NOCTTY so a FIFO is refused, not waited on",
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
        "src/preview_sandbox/control.rs",
        "the control peer's /proc/<pid>/status (parent pid and uids); the kernel's process table, no secret",
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
        "src/preview_sandbox/proxy/host_addresses.rs",
        "the host's own networks from /proc/net/fib_trie, if_inet6 and ipv6_route; kernel tables, no secret",
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
        "src/security/transparency_log_identity.rs",
        "reads the audit log's active file and sealed segments for its id at recovery; no secret",
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

/// MIK-9387.TCFG.3a: a test module gated on `all(test, ..)` is test code too,
/// so its raw I/O does not count (the #4706 shape); `any(test, ..)` also
/// builds outside tests, so raw I/O under it still counts.
#[test]
fn raw_io_under_a_compound_test_gate_counts_only_when_it_builds_outside_tests() {
    let gated = |gate: &str| {
        format!(
            "fn product() {{}}\n\n#[cfg({gate})]\nmod tests {{\n    fn fixture() -> String {{\n        std::fs::read_to_string(\"x\").unwrap()\n    }}\n}}\n"
        )
    };
    for gate in [
        "all(test, unix)",
        "all(unix, test)",
        "all(test, feature = \"firewall\")",
    ] {
        assert!(!has_raw_io(&gated(gate)), "{gate}: counted");
    }
    for gate in ["any(test, unix)", "not(test)", "reads_token_probe"] {
        assert!(has_raw_io(&gated(gate)), "{gate}: not counted");
    }
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
