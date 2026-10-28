// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 source scans: the production paths that must install or never
//! write the record key (G-META, G-LOGSITES) and the closed-world census of
//! every way to a principal's stored bytes (G-CENSUS), over a scan that
//! classifies test code by its enclosing module.

use std::path::Path;

/// Brace depth outside strings, raw strings, char literals and comments,
/// carried across lines.
#[derive(Default)]
struct Braces {
    depth: usize,
    in_str: bool,
    raw_hashes: Option<usize>,
    in_block_comment: bool,
}

impl Braces {
    fn feed(&mut self, line: &str) {
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if self.in_block_comment {
                if b[i..].starts_with(b"*/") {
                    self.in_block_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if let Some(hashes) = self.raw_hashes {
                let closes = b[i] == b'"'
                    && b.len() > i + hashes
                    && b[i + 1..=i + hashes].iter().all(|&c| c == b'#');
                if closes {
                    self.raw_hashes = None;
                    i += 1 + hashes;
                } else {
                    i += 1;
                }
                continue;
            }
            if self.in_str {
                match b[i] {
                    b'\\' => i += 2,
                    b'"' => {
                        self.in_str = false;
                        i += 1;
                    }
                    _ => i += 1,
                }
                continue;
            }
            let ident_before = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
            match b[i] {
                b'/' if b.get(i + 1) == Some(&b'/') => break,
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    self.in_block_comment = true;
                    i += 2;
                }
                b'r' if !ident_before => {
                    let hashes = b[i + 1..].iter().take_while(|&&c| c == b'#').count();
                    if b.get(i + 1 + hashes) == Some(&b'"') {
                        self.raw_hashes = Some(hashes);
                        i += 2 + hashes;
                    } else {
                        i += 1;
                    }
                }
                b'"' => {
                    self.in_str = true;
                    i += 1;
                }
                // A char literal ('{', '\''); a lifetime has no closing quote.
                b'\'' if b.get(i + 1) == Some(&b'\\') => {
                    i += 3;
                    while i < b.len() && b[i] != b'\'' {
                        i += 1;
                    }
                    i += 1;
                }
                b'\'' if b.get(i + 2) == Some(&b'\'') => i += 3,
                b'{' => {
                    self.depth += 1;
                    i += 1;
                }
                b'}' => {
                    self.depth = self.depth.saturating_sub(1);
                    i += 1;
                }
                _ => i += 1,
            }
        }
    }
}

/// The lines of `text` outside inline test modules, with their 0-based
/// numbers. A test module is `#[cfg(test)]` then `mod NAME {` and runs to its
/// matching `}`: classified by its extent, so production code after it is
/// still scanned. A `#[cfg(test)]` on a field, a fn or an out-of-line
/// `mod x;` marks no section (the lesson of the first cfg(test) line).
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut braces = Braces::default();
    let mut armed = false;
    // The depth the open test module closes back to.
    let mut test_until: Option<usize> = None;
    let mut out = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let opens = armed
            && test_until.is_none()
            && trimmed.split_whitespace().any(|w| w == "mod")
            && trimmed.ends_with('{');
        if opens {
            test_until = Some(braces.depth);
        }
        let in_test = test_until.is_some() || trimmed == "#[cfg(test)]";
        if trimmed == "#[cfg(test)]" {
            armed = true;
        } else if !trimmed.is_empty() && !trimmed.starts_with("#[") && !trimmed.starts_with("//") {
            armed = false;
        }
        braces.feed(line);
        if !in_test {
            out.push((n, *line));
        }
        if test_until.is_some_and(|d| braces.depth == d) && !opens {
            test_until = None;
        }
    }
    out
}

/// The scan classifies by enclosing item: production code after an inline
/// test module's closing brace is production, and braces in strings, char
/// literals and comments inside the module do not end it early.
#[test]
fn production_lines_classify_by_enclosing_item() {
    let src = r##"fn early() {}
#[cfg(test)]
pub(crate) value: u8,
#[cfg(test)]
mod key_tests;
#[cfg(test)]
mod tests {
    fn t() {
        let _ = "}}}";
        let _ = r#"}"#;
        let _ = '}';
        // }
        /* } */
        if true { let _ = 1; }
    }
}
fn after_the_test_module() {}
"##;
    let kept: Vec<&str> = production_lines(src).into_iter().map(|(_, l)| l).collect();
    assert!(kept.contains(&"fn early() {}"), "{kept:?}");
    assert!(kept.contains(&"pub(crate) value: u8,"), "{kept:?}");
    assert!(kept.contains(&"mod key_tests;"), "{kept:?}");
    assert!(kept.contains(&"fn after_the_test_module() {}"), "{kept:?}");
    assert!(
        !kept
            .iter()
            .any(|l| l.contains("fn t()") || l.contains("\"}}}\"")),
        "{kept:?}"
    );
}

// G-META (lead, 2026-10-23): `MetaMcp::record_key` panics when no key was
// installed, which is acceptable only if no production MetaMcp can lack one.
// (1) Outside test code, MetaMcp is constructed only in build_meta_mcp
// (src/gateway/server/build_meta.rs). (2) That function installs the key at
// its top level, never under a condition.
#[test]
fn g_meta_every_production_meta_mcp_gets_the_record_key() {
    // Files included only under `#[cfg(test)]` from elsewhere, so nothing in
    // them marks them as test code; each named with where it is included.
    const TEST_ONLY_INCLUDES: &[&str] = &[
        "src/gateway/meta_mcp/search_disclosure_e2e", // meta_mcp/mod.rs, #[cfg(test)]
        "src/gateway/meta_mcp/list_paging_e2e.rs",    // surface_compaction_tests.rs
        "src/gateway/meta_mcp/account_resolver_",     // account_resolver_fixture (tests)
        "src/gateway/meta_mcp/account_rest_fixture.rs", // meta_mcp/mod.rs, #[cfg(test)]
        "src/gateway/meta_mcp/slot_verdict_fixture.rs", // meta_mcp/mod.rs, #[cfg(test)]
        "src/gateway/router/direct_guards_fixture.rs", // router/mod.rs, #[cfg(test)]
        // #[path] from stored_replay_liveness_token_exchange_tests.rs
        "src/gateway/router/stored_replay_liveness_idp_fixture.rs",
    ];
    const BUILD_META: &str = "src/gateway/server/build_meta.rs";
    fn walk(dir: &Path, root: &Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("src readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, hits);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            if path.extension().is_none_or(|e| e != "rs")
                || rel.contains("_tests")
                || rel.contains("/tests/")
                || rel.ends_with("tests.rs")
                || rel == BUILD_META
                || TEST_ONLY_INCLUDES.iter().any(|p| rel.starts_with(p))
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source readable");
            for (n, line) in production_lines(&text) {
                let constructs = line.contains("MetaMcp::new(")
                    || line.contains("MetaMcp::with_features(")
                    || line.contains("MetaMcp::with_features_and_clock(");
                if constructs && !line.trim_start().starts_with("//") {
                    hits.push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    walk(&root.join("src"), root, &mut hits);
    assert!(
        hits.is_empty(),
        "a production MetaMcp built outside build_meta_mcp could lack the record key: {hits:?}"
    );
    let build_meta = std::fs::read_to_string(root.join(BUILD_META)).expect("build_meta");
    let installs: Vec<&str> = build_meta
        .lines()
        .filter(|l| l.contains("meta_mcp_builder.set_record_key("))
        .collect();
    assert_eq!(
        installs.len(),
        1,
        "build_meta_mcp installs the record key exactly once"
    );
    assert!(
        installs[0].starts_with("        meta_mcp_builder"),
        "the install is at the function's top level, not under a condition: {:?}",
        installs[0]
    );
}

/// Whether any source under `dir` mentions `caller_key`.
fn mentions_caller_key(dir: &Path) -> bool {
    std::fs::read_dir(dir).expect("dir").flatten().any(|e| {
        let p = e.path();
        if p.is_dir() {
            return mentions_caller_key(&p);
        }
        std::fs::read_to_string(&p).is_ok_and(|t| t.contains("caller_key"))
    })
}

// G-LOGSITES (lead, 2026-10-23): a logger opened in test code starts keyed,
// so this proves the production openers by source. Outside test code the
// logger is opened in two places: build_meta_mcp, which installs the record
// key on the logger it opens, and the governance store, whose records never
// carry a `caller_key` (the only field the logger keys), so it needs none.
#[test]
fn g_logsites_every_production_logger_is_keyed_or_never_keys() {
    // Included only under `#[cfg(test)]`, each named with where.
    const TEST_ONLY: &[&str] = &[
        "src/gateway/meta_mcp/account_resolver_", // account_resolver_fixture (tests)
        "src/gateway/meta_mcp/account_rest_fixture.rs", // meta_mcp/mod.rs
        "src/gateway/meta_mcp/grant_audit_fixture.rs", // meta_mcp/mod.rs
        "src/gateway/meta_mcp/slot_verdict_fixture.rs", // meta_mcp/mod.rs
        "src/gateway/router/direct_guards_fixture_quota.rs", // direct_guards_fixture.rs
        "src/gateway/router/stored_replay_liveness_idp_fixture.rs", // its _tests.rs
        "src/gateway/server/tools_changed/audience_fixture.rs", // tools_changed.rs
    ];
    const OPENERS: &[&str] = &[
        "src/gateway/server/build_meta.rs",
        "src/gateway/server/control_plane_store.rs",
    ];
    fn walk(dir: &Path, root: &Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("src readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, hits);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            if path.extension().is_none_or(|e| e != "rs")
                || rel.contains("_tests")
                || rel.contains("/tests/")
                || rel.ends_with("tests.rs")
                || TEST_ONLY.iter().any(|p| rel.starts_with(p))
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source readable");
            for (_, line) in production_lines(&text) {
                if line.contains("TransparencyLogger::open(")
                    && !line.trim_start().starts_with("//")
                {
                    hits.push(rel.clone());
                }
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    walk(&root.join("src"), root, &mut hits);
    hits.sort();
    hits.dedup();
    assert_eq!(hits, OPENERS, "a new production logger opener");
    let build_meta = std::fs::read_to_string(root.join(OPENERS[0])).expect("build_meta");
    assert!(
        build_meta.contains(".with_record_key(Arc::clone(&record_key))"),
        "build_meta_mcp keys the logger it opens"
    );
    assert!(
        !mentions_caller_key(&root.join("src/control_plane")),
        "a governance record now carries caller_key, so its logger needs the record key"
    );
}

/// A census row's class (§16.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// A lookup or store key that never reaches a record, log, span or audit
    /// field (presence tests included).
    Store,
    /// A declaration, or a pass-through into another censused line.
    Decl,
    /// Feeds the keyed record form.
    Keyed,
}
use Class::{Decl, Keyed, Store};

/// Sources included only under `#[cfg(test)]`, each named with where.
const CENSUS_TEST_ONLY: &[&str] = &[
    "src/gateway/meta_mcp/account_resolver_", // account_resolver_fixture (tests)
    "src/gateway/meta_mcp/account_rest_fixture.rs", // meta_mcp/mod.rs
    "src/gateway/meta_mcp/authz_fixture.rs",  // meta_mcp/mod.rs
    "src/gateway/meta_mcp/boundary_pins",     // meta_mcp/mod.rs
    "src/gateway/meta_mcp/grant_audit_fixture.rs", // meta_mcp/mod.rs
    "src/gateway/meta_mcp/list_paging_e2e.rs", // surface_compaction_tests.rs
    "src/gateway/meta_mcp/search_disclosure_e2e", // meta_mcp/mod.rs
    "src/gateway/meta_mcp/slot_verdict_fixture.rs", // meta_mcp/mod.rs
    "src/gateway/meta_mcp/test_callers.rs",   // meta_mcp/mod.rs
    "src/gateway/router/direct_guards_fixture", // router/mod.rs and its child
    "src/gateway/router/stored_replay_liveness_idp_fixture.rs", // its _tests.rs
    "src/gateway/server/tools_changed/audience_fixture.rs", // tools_changed.rs
];

/// G-CENSUS (§16.13): every production line that reaches a principal's stored
/// bytes (`storage_form`), reads a `credential_principal` owner/store key, or
/// builds a `credential:` owner, as `(file, line substring, lines, class,
/// reason)`. A line is covered by the matching row with the longest
/// substring; a tie is ambiguous.
///
/// A Store row's reason covers every value built from its line (a cache or
/// idempotency key, a Debug placeholder), traced to its sinks, not only the
/// line itself (§16.15). The credential canary tests catch what a row misses.
#[rustfmt::skip]
const CENSUS: &[(&str, &str, usize, Class, &str)] = &[
    ("src/events/rpc/subscribe.rs", "credential_principal: Some(caller.credential.principal.clone())", 1, Store, "subscription row field: the store's owner binding"),
    ("src/events/rpc_held.rs", "credential_principal: Some(caller.credential.principal.clone())", 1, Store, "held subscription row field: the store's owner binding"),
    ("src/events/operational_source.rs", "k.principal_for(&digest).storage_form() == principal", 1, Store, "compares a configured key's principal (explicit or digest-derived, ADR-022) to a stored principal"),
    ("src/events/fanout.rs", "row.credential_principal == snapshot.credential_principal", 1, Store, "store row identity comparison"),
    ("src/gateway/router/handlers/session_end.rs", "c.credential_principal().is_none()", 1, Store, "presence test only"),
    ("src/gateway/server/stdio_dispatch.rs", "credential_principal: Some(STDIO_CREDENTIAL_PRINCIPAL)", 1, Decl, "context owner key; the record field beside it is keyed"),
    ("src/gateway/server/stdio_single.rs", "credential_principal: Some(STDIO_CREDENTIAL_PRINCIPAL)", 1, Decl, "cfg(test) stdio fixture context"),
    ("src/gateway/router/handlers/dispatch_tools_call.rs", "credential_principal: client", 1, Decl, "context owner key; record_principal beside it is keyed"),
    ("src/gateway/router/handlers/dispatch_tools_call.rs", ".map(|client| client.principal.storage_form())", 1, Decl, "feeds the context's credential_principal (censused)"),
    ("src/events/records.rs", "pub credential_principal: Option<String>", 1, Decl, "subscription store field"),
    ("src/events/worker.rs", "credential_principal: self.sub.credential_principal.as_deref()", 1, Decl, "into Attempt.credential_principal, keyed at services.rs record_form"),
    ("src/events/services.rs", ".storage_form()", 1, Store, "bearer principal for live-binding comparison"),
    ("src/events/services.rs", "k.principal_for(&digest).storage_form() == key.principal", 1, Store, "a watch's configured key still holds its recorded principal (ADR-022)"),
    ("src/gateway/auth_resolved.rs", "k.principal().storage_form() == principal", 2, Store, "client_for_key and client_for_key_at find a key by its stored principal"),
    ("src/events/services.rs", "sub.credential_principal.as_deref() == Some(live)", 1, Store, "live-binding comparison"),
    ("src/events/services.rs", "pub credential_principal: Option<&'a str>", 1, Decl, "Attempt field, keyed where recorded"),
    ("src/events/services.rs", "attempt.credential_principal.unwrap_or_default().to_owned()", 1, Keyed, "InternalPrincipal::new(..).record_form(key) for who.principal"),
    ("src/gateway/router/handlers/tasks.rs", "credential_principal: caller.client.map(|client| client.principal.storage_form())", 1, Decl, "policy context owner key; record_principal beside it is keyed"),
    ("src/gateway/router/handlers/tasks.rs", ".map(|client| client.principal.storage_form().to_owned())", 1, Store, "the principal a held task was opened as, compared on read"),
    ("src/gateway/router/handlers/tasks.rs", "*opened_as == reader.principal.storage_form()", 1, Store, "held-task reader comparison"),
    ("src/gateway/router/handlers/dispatch_intake_run.rs", ".map(|client| client.principal.storage_form())", 2, Store, "a provenance classification and an admission owner key argument"),
    ("src/gateway/auth.rs", "pub(crate) const CREDENTIAL_OWNER_PREFIX", 1, Decl, "the owner-key prefix"),
    ("src/gateway/auth.rs", "pub(in crate::gateway) fn credential_principal(&self)", 1, Decl, "returns &InternalPrincipal, no bytes"),
    ("src/gateway/router/handlers/events.rs", ".map(|c| c.principal.storage_form().to_owned())", 1, Store, "events Credential.principal: the subscription owner binding"),
    ("src/gateway/router/handlers/events.rs", "principal: c.principal.storage_form().to_owned()", 1, Store, "ApiKeyRef.principal: a key-match store field"),
    ("src/identity_propagation/caller_proof.rs", "pub(crate) fn classify(credential_principal: Option<&str>)", 1, Decl, "presence classification parameter"),
    ("src/identity_propagation/caller_proof.rs", "match credential_principal {", 1, Store, "presence classification only"),
    ("src/gateway/router/handlers/tasks/owner.rs", ".and_then(|c| c.credential_principal())", 1, Decl, "feeds the task owner key below"),
    ("src/gateway/router/handlers/tasks/owner.rs", "crate::gateway::auth::CREDENTIAL_OWNER_PREFIX,", 1, Store, "task owner key: keyed by record_owner where recorded"),
    ("src/gateway/router/handlers/tasks/owner.rs", "principal.storage_form()", 1, Store, "task owner key: keyed by record_owner where recorded"),
    ("src/gateway/router/handlers/owner.rs", "match client.and_then(|c| c.credential_principal())", 1, Decl, "feeds the session owner below"),
    ("src/gateway/ui/preview.rs", ".and_then(|c| c.credential_principal())", 1, Decl, "feeds the preview confirmation owner below"),
    ("src/gateway/ui/preview.rs", "crate::hashing::sha256_hex(p.storage_form().as_bytes())", 1, Store, "preview confirmation owner: a digest sealed in the token, compared on redeem"),
    ("src/gateway/router/handlers/owner.rs", "SessionOwner::Credential(principal.storage_form().to_owned())", 1, Store, "session owner: an in-process lookup key"),
    ("src/gateway/router/watch_poll.rs", "client.principal.storage_form(),", 1, Store, "presence classification only"),
    ("src/gateway/record_principal.rs", "const PREFIX: &str = crate::gateway::auth::CREDENTIAL_OWNER_PREFIX", 1, Keyed, "record_owner: the keying helper"),
    ("src/gateway/router/view_judge.rs", "client.principal.storage_form(),", 1, Store, "presence classification only"),
    ("src/gateway/router/backend_handlers/direct_caller.rs", ".map(|client| client.principal.storage_form())", 2, Store, "a provenance classification and an admission owner key argument"),
    ("src/gateway/router/backend_handlers/key_check.rs", "failed.client.map(|client| client.principal.storage_form())", 1, Store, "presence classification only"),
    ("src/gateway/meta_mcp/direct_route.rs", "credential_principal: Option<&str>,", 1, Decl, "parameter"),
    ("src/gateway/meta_mcp/direct_route.rs", "credential_principal,", 1, Decl, "pass-through argument"),
    ("src/gateway/meta_mcp/direct_route.rs", "(credential_principal, grant_subject, caller_key): (", 1, Decl, "parameter"),
    ("src/gateway/meta_mcp/direct_route.rs", "support::execution_principal(owner, credential_principal", 1, Store, "admission owner key"),
    ("src/gateway/router/backend_handlers/direct_preflight.rs", ".and_then(|client| client.credential_principal())", 1, Decl, "feeds the A2A slot binding below"),
    ("src/gateway/router/backend_handlers/direct_preflight.rs", "format!(\"a2a-client:{}\", principal.storage_form())", 1, Store, "A2A identity_key: an in-process backend slot binding; its pool-key logs dropped (§16.15)"),
    ("src/gateway/router/backend_handlers/direct_idempotency.rs", ".map(|client| client.principal.storage_form())", 2, Store, "idempotency and admission owner key arguments"),
    ("src/gateway/router/handlers.rs", ".map(|client| client.principal.storage_form())", 1, Store, "presence classification only"),
    ("src/gateway/router/identity.rs", ".and_then(|c| c.credential_principal())", 1, Decl, "feeds caller_key below"),
    ("src/gateway/router/identity.rs", "let principal = principal.storage_form();", 1, Keyed, "caller_key: an in-process key; its record field is keyed in TransparencyLogger::append_core (§16.14)"),
    ("src/protocol/continuation/quota.rs", "let prefix = crate::gateway::auth::CREDENTIAL_OWNER_PREFIX", 1, Store, "continuation quota key"),
    ("src/gateway/meta_mcp/admission.rs", "credential_principal: Option<&str>,", 2, Decl, "parameters"),
    ("src/gateway/meta_mcp/admission.rs", "credential_principal,", 1, Decl, "pass-through argument"),
    ("src/gateway/meta_mcp/admission.rs", "credential_principal", 1, Store, "admission owner key fallback"),
    ("src/gateway/meta_mcp/invoke.rs", "mod mcp_credential_principal_tests;", 1, Decl, "a test module's name"),
    ("src/capability/execution_context.rs", "pub(crate) credential_principal: Option<String>", 1, Decl, "MCP child owner key field"),
    ("src/capability/execution_context.rs", "credential_principal: None,", 1, Decl, "anonymous default"),
    ("src/capability/execution_context.rs", "\"credential_principal\",", 1, Decl, "Debug field name; the value prints <redacted>"),
    ("src/capability/execution_context.rs", "&self.credential_principal.as_ref().map(|_| \"<redacted>\")", 1, Decl, "Debug value: presence only, never the principal"),
    ("src/capability/executor/mcp.rs", ".credential_principal", 1, Store, "per-owner MCP child key"),
    ("src/gateway/task_service/execution/context.rs", "credential_principal: String,", 2, Decl, "owned snapshot field and constructor parameter"),
    ("src/gateway/task_service/execution/context.rs", "credential_principal,", 1, Decl, "constructor field init"),
    ("src/gateway/task_service/execution/context.rs", "fn credential_principal_for_test(&self)", 1, Decl, "cfg(test) accessor"),
    ("src/gateway/task_service/execution/context.rs", "&self.credential_principal", 1, Decl, "cfg(test) accessor body"),
    ("src/gateway/task_service/execution/context.rs", "credential_principal: Some(self.credential_principal.as_str())", 1, Decl, "reborrow into the context owner key; record_principal beside it is the snapshot"),
    ("src/gateway/meta_mcp/caller_context.rs", "pub credential_principal: Option<&'a str>", 1, Decl, "context owner key field; never reaches a record"),
    ("src/gateway/meta_mcp/caller_context.rs", "self.credential_principal,", 2, Store, "owner and execution principal: admission keys"),
    ("src/gateway/meta_mcp/caller_context.rs", "CallerProvenance::classify(self.credential_principal)", 1, Store, "presence classification only"),
    ("src/gateway/meta_mcp/caller_context.rs", "credential_principal: self.credential_principal,", 1, Decl, "reborrow copy"),
    ("src/gateway/meta_mcp/events_hook.rs", "caller.credential_principal,", 1, Store, "ApiKeyRef.principal for the subscription store"),
    ("src/gateway/meta_mcp/events_hook.rs", "Visibility::Owner => caller.credential_principal.is_some()", 1, Store, "presence test only"),
    ("src/gateway/meta_mcp/support.rs", "credential_principal: Option<&str>,", 3, Decl, "parameters"),
    ("src/gateway/meta_mcp/support.rs", "credential_principal,", 2, Store, "cache binding and continuation key arguments"),
    ("src/gateway/meta_mcp/support.rs", "caller.credential_principal,", 1, Store, "credential owner key"),
    ("src/gateway/meta_mcp/support.rs", "let prefix = crate::gateway::auth::CREDENTIAL_OWNER_PREFIX", 1, Store, "credential owner key"),
    ("src/gateway/meta_mcp/support.rs", "credential_principal: Option<&'a str>,", 2, Decl, "parameters"),
    ("src/gateway/meta_mcp/support.rs", "credential_principal", 1, Store, "owner key selection"),
    ("src/gateway/meta_mcp/support.rs", "credential_or_subject_owner(credential_principal, grant_subject, caller_key)", 1, Store, "execution principal: an admission key"),
    ("src/gateway/meta_mcp/support.rs", "execution_principal(owner, credential_principal, grant_subject, caller_key)", 1, Store, "intake refusal test of the execution principal"),
    ("src/gateway/meta_mcp/invoke/continuation.rs", "credential_principal: client", 1, Decl, "projection input field"),
    ("src/gateway/meta_mcp/invoke/continuation.rs", ".and_then(|c| c.credential_principal())", 1, Decl, "feeds the quota source below"),
    ("src/gateway/meta_mcp/invoke/continuation.rs", "client.map(|client| client.principal.storage_form())", 1, Store, "continuation key binding"),
    ("src/gateway/meta_mcp/invoke/dispatch.rs", "credential_principal: credential_owner.map(str::to_owned)", 1, Store, "MCP child owner key"),
    ("src/gateway/meta_mcp/invoke/projection.rs", "pub(super) credential_principal: Option<&'q str>", 1, Decl, "projection input field"),
    ("src/gateway/meta_mcp/invoke/projection.rs", "inputs.credential_principal", 1, Store, "continuation quota source"),
    ("src/gateway/meta_mcp/invoke/projection.rs", "credential_principal: crate::gateway::auth::authenticated_principal(", 1, Decl, "projection input"),
    ("src/gateway/meta_mcp/invoke/projection.rs", "self.credential_principal,", 1, Decl, "projection input"),
    ("src/gateway/meta_mcp/caller_forward.rs", "client.map(|c| c.principal.storage_form())", 1, Store, "presence classification only"),
    ("src/gateway/meta_mcp/invoke/continuation.rs", ".map(crate::gateway::record_principal::InternalPrincipal::storage_form)", 1, Store, "continuation quota key"),
];

/// G-CENSUS: a new way to the stored principal fails until it has a row, and a
/// row whose lines changed fails until it is reclassified.
#[test]
fn g_census_every_way_to_the_stored_principal_is_classified() {
    const PATTERNS: &[&str] = &[
        "storage_form",
        "credential_principal",
        "CREDENTIAL_OWNER_PREFIX",
    ];
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut covered = vec![0usize; CENSUS.len()];
    let mut problems = Vec::new();
    let mut dirs = vec![root.join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("src readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            if path.extension().is_none_or(|e| e != "rs")
                || rel.contains("_tests")
                || rel.contains("/tests/")
                || rel.ends_with("tests.rs")
                || CENSUS_TEST_ONLY.iter().any(|p| rel.starts_with(p))
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source readable");
            for (n, line) in production_lines(&text) {
                if line.trim_start().starts_with("//")
                    || line.contains("fn storage_form(")
                    || !PATTERNS.iter().any(|p| line.contains(p))
                {
                    continue;
                }
                let matching: Vec<usize> = (0..CENSUS.len())
                    .filter(|&i| CENSUS[i].0 == rel && line.contains(CENSUS[i].1))
                    .collect();
                let longest = matching.iter().map(|&i| CENSUS[i].1.len()).max();
                let best: Vec<usize> = matching
                    .into_iter()
                    .filter(|&i| Some(CENSUS[i].1.len()) == longest)
                    .collect();
                match best.as_slice() {
                    [i] => covered[*i] += 1,
                    [] => problems.push(format!("unclassified {rel}:{}: {}", n + 1, line.trim())),
                    _ => problems.push(format!("ambiguous {rel}:{}", n + 1)),
                }
            }
        }
    }
    for (row, lines) in CENSUS.iter().zip(&covered) {
        if *lines != row.2 || row.4.is_empty() {
            problems.push(format!(
                "{} {:?} ({:?}): {lines} lines, row says {}",
                row.0, row.1, row.3, row.2
            ));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    assert!(
        CENSUS.iter().any(|row| row.3 == Keyed),
        "the keying sites are censused"
    );
}

#[path = "record_principal_span_tests.rs"]
mod span_tests;
