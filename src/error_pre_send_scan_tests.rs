// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7979: `Error::BackendUnavailable` is on the `is_pre_dispatch` allowlist
//! because it is constructed only before a request is sent. This scan holds
//! that to a reviewed list of files: a new file that constructs the variant
//! fails the build until a reviewer adds it here with its pre-send proof, and
//! a listed file that no longer constructs it fails as stale.
//!
//! Threat model: honest edits, not adversarial ones. It catches a contributor
//! who builds the variant somewhere new without knowing the invariant. It is
//! a text scan, not a parser: comments, string and char literals and
//! `#[cfg(test)]` items are blanked first, and match patterns are told apart
//! from constructions by shape. Someone set on evading it can; review is the
//! control for that.

use crate::test_source_text::{production_text, sanitize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Files (relative to `src/`) allowed to construct `BackendUnavailable`, each
/// raising it only before the request is sent (design MIK-7979, addendum 1).
const PRE_SEND_SITES: &[&str] = &[
    // Cold tools/list timeout and cooldown fast-fail; rebuilds a stored refusal.
    "backend/fill_check.rs",
    // The dispatch's started slot was replaced before its era was read: refused
    // before the wire, to be retried (MIK-8186, `start_judged`).
    "backend/era.rs",
    // Start loop exhausted, connect policy changed, publish refused, and
    // `pre_send_start_error`.
    "backend/lifecycle.rs",
    // Stale tools refresh refused in cooldown.
    "backend/metadata.rs",
    // Start refused: package cache still locked, or its rename timed out.
    "backend/package_cache.rs",
    // Concurrency semaphore closed (request and notify paths).
    "backend/ops.rs",
    // Health probe with no shared transport (not tool dispatch).
    "backend/probe.rs",
    // Warm start (not tool dispatch).
    "gateway/server/warmstart.rs",
    // Credential lease wait (MIK-8619): the lock is taken in the token step,
    // before any byte of the tool request is sent (MCP: `get_oauth_token`
    // inside `build_mcp_headers` before the POST; capability refresh before
    // its HTTP call; token saves send no tool request at all).
    "oauth/client/refresh_flight.rs",
    // A login joiner's replay of the lead's credential-lock busy
    // (`LoginOutcome::Busy`, MIK-8658): the joiner waited in the token step
    // and sent no byte of its tool request.
    "oauth/login_gate.rs",
];

/// How many times `src` constructs `BackendUnavailable`: a call, a function
/// value or an import. A match pattern is not one: `(_)`/`(..)`, a group
/// followed by `=>` or `|`, or one preceded by `|`. The enum's own
/// `BackendUnavailable(String)` declaration is not one either.
fn constructions(src: &str) -> usize {
    constructions_of(src, "BackendUnavailable")
}

/// [`constructions`] for any `NAME`: a variant, or a function whose result
/// `is_pre_dispatch` trusts.
fn constructions_of(src: &str, name: &str) -> usize {
    construction_offsets(&sanitize(&production_text(src)), name).len()
}

/// Where `clean` (sanitized, test items stripped) constructs `name`: the byte
/// offset of each construction, by the rules [`constructions`] states.
fn construction_offsets(clean: &str, name: &str) -> Vec<usize> {
    let b = clean.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let next_non_ws = |from: usize| b[from..].iter().position(|c| !c.is_ascii_whitespace());
    let mut found = Vec::new();
    for (at, _) in clean.match_indices(name) {
        let end = at + name.len();
        if (at > 0 && ident(b[at - 1])) || b.get(end).copied().is_some_and(ident) {
            continue;
        }
        let path_start = b[..at]
            .iter()
            .rposition(|c| !(ident(*c) || *c == b':'))
            .map_or(0, |p| p + 1);
        let before = b[..path_start]
            .iter()
            .rposition(|c| !c.is_ascii_whitespace());
        // A pattern alternative's `|` follows whitespace (`A | B`, or a leading
        // `| B` on its own line). A closure's parameter list ends in a `|` right
        // after its last parameter (`|_| build()`), so a value built there is
        // a construction, not a pattern. Text-based: this holds while rustfmt
        // writes alternatives with a space, which CI enforces.
        let after_alt =
            before.is_some_and(|p| b[p] == b'|' && p > 0 && b[p - 1].is_ascii_whitespace());
        let open = next_non_ws(end).map(|p| end + p);
        // A struct variant: `{ .. }`, an arm, an alternative or a `let`
        // destructure is a pattern; anything else builds the value.
        if let Some(brace) = open.filter(|p| b[*p] == b'{') {
            let mut depth = 0usize;
            let mut close = brace;
            for (j, c) in b.iter().enumerate().skip(brace) {
                match c {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = j;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let inner = clean[brace + 1..close].trim();
            let rest = clean[close + 1..].trim_start();
            let pattern = inner.ends_with("..")
                || rest.starts_with("=>")
                || (rest.starts_with('=') && !rest.starts_with("=="))
                || (rest.starts_with('|') && !rest.starts_with("||"))
                || after_alt;
            if !pattern {
                found.push(at);
            }
            continue;
        }
        let Some(open) = open.filter(|p| b[*p] == b'(') else {
            found.push(at);
            continue;
        };
        let mut depth = 0usize;
        let mut close = open;
        for (j, c) in b.iter().enumerate().skip(open) {
            match c {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = j;
                        break;
                    }
                }
                _ => {}
            }
        }
        let inner = clean[open + 1..close].trim();
        let rest = clean[close + 1..].trim_start();
        let alt_after = rest.starts_with('|') && !rest.starts_with("||");
        let pattern = matches!(inner, "_" | ".." | "String")
            || rest.starts_with("=>")
            || alt_after
            || after_alt;
        if !pattern {
            found.push(at);
        }
    }
    found
}

/// The non-test files under `src/` that construct `name`.
fn files_constructing(name: &str) -> BTreeSet<String> {
    construction_counts(name).into_keys().collect()
}

/// How many times each non-test file under `src/` constructs `name`.
fn construction_counts(name: &str) -> BTreeMap<String, usize> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = BTreeMap::new();
    for entry in walkdir::WalkDir::new(&root) {
        let entry = entry.expect("src is readable");
        let path = entry.path();
        let file = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        // Test-only by the repo's naming: `*tests.rs`, `*_test.rs`, or under a
        // `tests`/`*_tests` directory.
        let in_test_dir = path
            .strip_prefix(&root)
            .ok()
            .and_then(Path::parent)
            .is_some_and(|dir| {
                dir.components()
                    .any(|c| c.as_os_str().to_str().is_some_and(|s| s.ends_with("tests")))
            });
        let test_only = file.ends_with("tests.rs") || file.ends_with("_test.rs") || in_test_dir;
        if test_only || path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let src = std::fs::read_to_string(path).expect("readable source");
        let count = constructions_of(&src, name);
        if count > 0 {
            let rel = path.strip_prefix(&root).expect("under src");
            found.insert(rel.to_string_lossy().replace('\\', "/"), count);
        }
    }
    found
}

#[test]
fn backend_unavailable_is_constructed_only_at_reviewed_pre_send_sites() {
    let found = files_constructing("BackendUnavailable");
    let allowed: BTreeSet<String> = PRE_SEND_SITES.iter().map(|s| (*s).to_string()).collect();
    let unreviewed: Vec<_> = found.difference(&allowed).collect();
    let stale: Vec<_> = allowed.difference(&found).collect();
    assert!(
        unreviewed.is_empty(),
        "BackendUnavailable frees an idempotency key, so it may be built only before \
         the request is sent; an after-send failure is Transport or BackendTimeout. \
         Unreviewed files: {unreviewed:?}"
    );
    assert!(stale.is_empty(), "no longer build it, drop them: {stale:?}");
}

#[test]
fn the_scan_tells_constructions_from_patterns_comments_and_tests() {
    let ignored = r#"
// Error::BackendUnavailable("comment".into())
const S: &str = "Error::BackendUnavailable(x)";
enum E { BackendUnavailable(String), }
fn f(e: &Error) -> bool { matches!(e, Error::BackendUnavailable(_)) }
fn g(e: Error) {
    match e {
        Error::BackendUnavailable(m) => drop(m),
        Error::Transport(m) | Error::BackendUnavailable(m) => drop(m),
        _ => {}
    }
}
#[cfg(test)]
mod tests { fn t() { let _ = Error::BackendUnavailable("test".into()); } }
"#;
    assert_eq!(constructions(ignored), 0);
    let call = r#"fn h() -> Error { Error::BackendUnavailable(format!("{}", 1)) }"#;
    assert_eq!(constructions(call), 1);
    assert_eq!(constructions("let f = Error::BackendUnavailable;"), 1);
    assert_eq!(
        constructions("use crate::Error::BackendUnavailable as Down;"),
        1
    );
}

/// The module path of `file` (relative to `src/`, as
/// [`construction_counts`] gives it): `.rs` stripped, a trailing `/mod`
/// dropped, `/` read as `::`. `lib.rs` and `main.rs` are the crate root, "".
fn module_path(file: &str) -> String {
    if file == "lib.rs" || file == "main.rs" {
        return String::new();
    }
    let stem = file.strip_suffix(".rs").unwrap_or(file);
    let stem = stem.strip_suffix("/mod").unwrap_or(stem);
    stem.replace('/', "::")
}

/// Byte offsets of `word` in `clean` where it stands as a whole keyword: not preceded by an identifier byte, followed by whitespace or `<`.
fn keyword<'a>(clean: &'a str, word: &'a str) -> impl Iterator<Item = usize> + 'a {
    let b = clean.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    clean.match_indices(word).filter_map(move |(k, _)| {
        let end = k + word.len();
        let bounded = (k == 0 || !ident(b[k - 1]))
            && b.get(end)
                .is_some_and(|c| c.is_ascii_whitespace() || *c == b'<');
        bounded.then_some(k)
    })
}

/// The item `at` sits in, in sanitized source: `Type::method` inside an
/// `impl`, `function` outside one, or `<module>` for a construction outside
/// any function (an import), with the enclosing function's keyword offset
/// (`None` for `<module>`). This is the item part of the key
/// [`construction_sites`] builds: the module path from the file plus this
/// `Type::method` or `fn`. A move to another module changes the row, but a
/// row never names a file name (MIK-8498 DISPATCH.3).
fn enclosing_item(clean: &str, at: usize) -> (String, Option<usize>) {
    let b = clean.as_bytes();
    // The span of the block a keyword opens: from the keyword to its matching
    // `}`, or `None` for a body-less item (`;` before any `{`).
    let block = |from: usize| -> Option<usize> {
        let open = from + b[from..].iter().position(|c| *c == b'{' || *c == b';')?;
        if b[open] == b';' {
            return None;
        }
        let mut depth = 0usize;
        for (j, c) in b.iter().enumerate().skip(open) {
            match c {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(j);
                    }
                }
                _ => {}
            }
        }
        None
    };
    // The innermost `fn` whose span holds `at`, its offset and its name.
    let function = keyword(clean, "fn")
        .filter_map(|k| Some((k, block(k)?)))
        .filter(|(k, end)| *k <= at && at <= *end)
        .max_by_key(|(k, _)| *k)
        .map(|(k, _)| {
            let rest = clean[k + 2..].trim_start();
            let name = rest[..rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len())]
                .to_owned();
            (k, name)
        });
    let Some((fn_at, function)) = function else {
        return ("<module>".to_owned(), None);
    };
    // The innermost `impl` whose span holds `at` and whose keyword starts
    // before the enclosing `fn` keyword: its self type's last segment. A
    // signature `impl Trait` sits after the `fn` keyword, so it is not the
    // owner.
    let owner = keyword(clean, "impl")
        .filter_map(|k| Some((k, block(k)?)))
        .filter(|(k, end)| *k < fn_at && *k <= at && at <= *end)
        .max_by_key(|(k, _)| *k)
        .map(|(k, _)| {
            let header =
                &clean[k + 4..k + 4 + b[k + 4..].iter().position(|c| *c == b'{').unwrap_or(0)];
            let header = header.trim_start();
            let header = header.strip_prefix('<').map_or(header, |rest| {
                let mut depth = 1usize;
                let close = rest
                    .char_indices()
                    .find(|(_, c)| {
                        depth = match c {
                            '<' => depth + 1,
                            '>' => depth - 1,
                            _ => depth,
                        };
                        depth == 0
                    })
                    .map_or(rest.len(), |(i, _)| i + 1);
                &rest[close..]
            });
            let self_type = header
                .rsplit_once(" for ")
                .map_or(header, |(_, ty)| ty)
                .trim();
            let path = self_type.split(['<', ' ', '\n']).next().unwrap_or_default();
            path.rsplit("::").next().unwrap_or(path).to_owned()
        });
    (
        owner.map_or(function.clone(), |owner| format!("{owner}::{function}")),
        Some(fn_at),
    )
}

/// One construction site's label for the two-functions message.
fn site_label(file: &str, fn_at: Option<usize>) -> String {
    match fn_at {
        Some(at) => format!("{file}@{at}"),
        None => file.to_owned(),
    }
}

/// Record that `key` was produced by (`file`, `fn_at`). A later site with
/// the same key from a different file or a different fn offset is an error:
/// one key, one function. Several constructions inside one function record
/// the same triple, so they are accepted.
fn record_construction_site(
    owners: &mut BTreeMap<String, (String, Option<usize>)>,
    key: &str,
    file: &str,
    fn_at: Option<usize>,
) -> Result<(), String> {
    if let Some((first_file, first_fn)) = owners.get(key) {
        if first_file != file || *first_fn != fn_at {
            return Err(format!(
                "{key} names two functions ({} and {}): a row must name one reviewed function",
                site_label(first_file, *first_fn),
                site_label(file, fn_at)
            ));
        }
        return Ok(());
    }
    owners.insert(key.to_owned(), (file.to_owned(), fn_at));
    Ok(())
}

/// How many times each non-test item under `src/` constructs `name`, keyed
/// by the module-qualified function: the module path from the file plus
/// [`enclosing_item`] (`Type::method` or `fn`), with just the item at the
/// crate root. A move to another module changes the row, but a row never
/// names a file name. The same qualified key from two files, or from two
/// functions in one file, is an error: a row must name one reviewed
/// function.
fn construction_sites(name: &str) -> BTreeMap<String, usize> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    let mut owners: BTreeMap<String, (String, Option<usize>)> = BTreeMap::new();
    for file in construction_counts(name).into_keys() {
        let src = std::fs::read_to_string(root.join(&file)).expect("readable source");
        let clean = sanitize(&production_text(&src));
        let module = module_path(&file);
        for at in construction_offsets(&clean, name) {
            let (item, fn_at) = enclosing_item(&clean, at);
            let key = if module.is_empty() {
                item
            } else {
                format!("{module}::{item}")
            };
            if let Err(message) = record_construction_site(&mut owners, &key, &file, fn_at) {
                panic!("{message}");
            }
            *found.entry(key).or_default() += 1;
        }
    }
    found
}

/// The items allowed to build the sealed transient, each only before
/// anything reaches the backend (MIK-8428): `is_pre_dispatch` reads its seal,
/// so it frees an idempotency key. Keyed by the module path from the file
/// plus the item that builds it (`Type::method` or `function`,
/// [`enclosing_item`]), so a move to another module changes the row, but a
/// row never names a file name, and a new call in any item fails the scan.
/// A builder's own definition counts as one.
const TRANSIENT_SITES: &[(&str, usize)] = &[
    // `transient_retry_error`'s definition.
    ("personal_accounts::refusal::transient_retry_error", 1),
    // `transient_mint_refusal`'s definition and its one build.
    (
        "identity_propagation::account_strategies_view::AccountStrategyRegistry::transient_mint_refusal",
        2,
    ),
    // A capability mint's resolve or refresh admission.
    (
        "identity_propagation::account_strategies_resolve::AccountStrategyRegistry::resolve",
        1,
    ),
    // The lease recheck before the send, from three callers.
    (
        "identity_propagation::account_strategies_resolve::AccountStrategyRegistry::revalidate",
        1,
    ),
    // A per-user mint's admission, before the dispatch.
    (
        "gateway::meta_mcp::invoke::propagation::MetaMcp::resolve_caller_credential_as",
        1,
    ),
    // The task intake answer: no task, nothing dispatched.
    (
        "gateway::meta_mcp::call_dispatch::task_intake::MetaMcp::task_intake_transient",
        1,
    ),
    // The caller verdict's view Busy, answered before the backend.
    (
        "gateway::meta_mcp::invoke::caller_verdict::MetaMcp::dispatch_resolution",
        1,
    ),
    // A stored task read: no dispatch at all.
    ("gateway::meta_mcp::task_replay::retry_later", 1),
];

#[test]
fn the_sealed_transient_is_built_only_at_reviewed_pre_send_sites() {
    let mut found = construction_sites("transient_retry_error");
    for (item, count) in construction_sites("transient_mint_refusal") {
        *found.entry(item).or_default() += count;
    }
    let allowed: BTreeMap<String, usize> = TRANSIENT_SITES
        .iter()
        .map(|(item, count)| ((*item).to_string(), *count))
        .collect();
    assert_eq!(
        found, allowed,
        "the sealed transient frees an idempotency key, so it may be built only \
         before anything reaches the backend: review every new or removed call \
         site (left: found, right: reviewed)"
    );
}

/// The items allowed to build `Error::AmbiguousBackend`, which
/// `is_pre_dispatch` lists: the name clash is refused at resolve, before any
/// credential, replay, idempotency key, cache or send. Keyed as above.
const CLASH_SITES: &[(&str, usize)] = &[
    // `ambiguous_backend`, called only by `MetaMcp::refuse_name_clash`, the
    // first step of `resolve`.
    ("gateway::meta_mcp::invoke::dispatch::ambiguous_backend", 1),
];

#[test]
fn the_clash_refusal_is_built_only_at_reviewed_pre_send_sites() {
    let allowed: BTreeMap<String, usize> = CLASH_SITES
        .iter()
        .map(|(item, count)| ((*item).to_string(), *count))
        .collect();
    assert_eq!(
        construction_sites("Error::AmbiguousBackend"),
        allowed,
        "the clash refusal frees an idempotency key, so it may be built only \
         before anything reaches the backend: review every new or removed call \
         site (left: found, right: reviewed)"
    );
}

/// A value built right after a closure's parameters is a construction: the
/// closing `|` of `|_|` is not a pattern alternative.
#[test]
fn a_construction_after_a_closures_parameters_is_counted() {
    let src = "fn f(r: Result<(), E>) -> Result<(), Error> {\n\
               r.map_err(|_| crate::Error::BackendUnavailable(String::new()))\n\
               }\n\
               fn g(e: &Error) -> bool {\n\
               matches!(e, Error::Transport(_)\n    | Error::BackendUnavailable(_))\n\
               }\n";
    assert_eq!(constructions(src), 1, "{src}");
}

/// `found` summed over each of `names`: a variant's literal constructions and
/// the calls of every builder that returns it.
fn summed_sites(names: &[&str]) -> BTreeMap<String, usize> {
    let mut found = BTreeMap::new();
    for name in names {
        for (item, count) in construction_sites(name) {
            *found.entry(item).or_default() += count;
        }
    }
    found
}

fn reviewed(sites: &[(&str, usize)]) -> BTreeMap<String, usize> {
    sites
        .iter()
        .map(|(item, count)| ((*item).to_string(), *count))
        .collect()
}

/// The items allowed to build `Error::Forbidden`, or to call a builder that
/// does, which `is_pre_dispatch` lists: each refuses before anything reaches
/// the backend. Keyed as above.
const FORBIDDEN_SITES: &[(&str, usize)] = &[
    // A lent-only slot's dispatch with no credential, before anything is built.
    ("backend::lend::Backend::lend_to_slot", 1),
    // A shared slot refused to a per-user call, before it starts.
    ("backend::pool::Backend::refuse_shared_start", 1),
    // Imports of `step_not_permitted`, not constructions.
    ("gateway::meta_mcp::<module>", 1),
    ("gateway::meta_mcp::support::<module>", 1),
    // A forwarded call outside the caller's scope, before dispatch.
    (
        "gateway::meta_mcp::caller_forward::MetaMcp::scope_refusal",
        1,
    ),
    // The request firewall's verdict on the outbound request, before the send.
    (
        "gateway::meta_mcp::invoke::chokepoint::MetaMcp::rescan_outbound",
        2,
    ),
    (
        "gateway::meta_mcp::invoke::chokepoint::MetaMcp::route_request_scan",
        2,
    ),
    // The call-level policy, judged before dispatch.
    (
        "gateway::meta_mcp::invoke::gate::MetaMcp::check_call_level_policy",
        1,
    ),
    // A relayed catalogue the caller may not read, before any call.
    (
        "gateway::meta_mcp::invoke::relay_catalogue::MetaMcp::catalogue_refusal",
        1,
    ),
    // A playbook step's outcome relabelled to the neutral refusal (A3). A step
    // sent and failed while a grant was revoked is relabelled too, a race
    // tracked on its own; its key is kept by its own send count and the run's
    // lease.
    (
        "gateway::meta_mcp::playbook_invoker::MetaMcpInvoker::invoke",
        1,
    ),
    // The neutral step refusal: its definition and its literal.
    ("gateway::meta_mcp::playbook_invoker::step_not_permitted", 2),
    // A chain step's refusal rebuilt with its index: a step's own refusal.
    ("gateway::meta_mcp::search::chain_exec::step_failure", 1),
    // A stored task's targets judged again before its replay: no send.
    (
        "gateway::meta_mcp::task_replay::judging::MetaMcp::authorize_stored",
        1,
    ),
    // An admin-only capability refused to a non-admin, before dispatch.
    (
        "gateway::meta_mcp::visibility::MetaMcp::admin_capability_rule",
        1,
    ),
    // A match pattern wrapped in `Err(..)`, which the scan counts: no value is
    // built there.
    (
        "gateway::router::handlers::dispatch_tools_call::tools_call",
        1,
    ),
    // The stdio route stage's refusal of a step target, before dispatch.
    ("gateway::server::stdio_route_stage::authorize_targets", 1),
    // The web UI call's gates: before the capability or the send runs.
    ("gateway::ui_call::admit_send", 2),
    ("gateway::ui_call::confirmed", 1),
    ("gateway::ui_call::gate", 1),
    ("gateway::ui_call::task_refused", 1),
    ("gateway::ui_call::ui_call_refused", 2),
    // A playbook refused before its first step, and a step's arguments
    // refused before the step is invoked.
    ("playbook::engine::PlaybookEngine::execute_definition", 1),
    ("playbook::engine::checked_arguments", 1),
    // The lender's refusal while a lent send's headers are built, before the
    // request leaves: the import, the no-lender check, the per-loan checks,
    // and the counted builder and its builder (definitions and calls).
    ("transport::http::requests::<module>", 1),
    ("transport::http::requests::HttpTransport::lent_for", 1),
    ("transport::lender::Lender::lent_for", 4),
    ("transport::lender::counted_refusal", 2),
    ("transport::lender::send_refused", 2),
];

#[test]
fn a_denial_is_built_only_at_reviewed_pre_send_sites() {
    assert_eq!(
        summed_sites(&[
            "Error::Forbidden",
            "step_not_permitted",
            "send_refused",
            "counted_refusal",
            "ui_call_refused",
        ]),
        reviewed(FORBIDDEN_SITES),
        "a denial frees an idempotency key, so it may be built only before \
         anything reaches the backend: review every new or removed site \
         (left: found, right: reviewed)"
    );
}

/// The items allowed to build `Error::GatewayRefused`, or to call its builder,
/// which `is_pre_dispatch` lists: the admission checks, before any send.
const GATEWAY_REFUSED_SITES: &[(&str, usize)] = &[
    // The builder: its definition and its literal.
    ("error::Error::gateway_refused", 2),
    // The admission checks, each before dispatch.
    (
        "gateway::meta_mcp::invoke::dispatch::MetaMcp::admit_spend",
        1,
    ),
    (
        "gateway::meta_mcp::invoke::dispatch_guards::MetaMcp::admit_backend_wide",
        1,
    ),
    (
        "gateway::meta_mcp::invoke::dispatch_guards::MetaMcp::admit_enabled_capability",
        1,
    ),
    (
        "gateway::meta_mcp::invoke::policy::MetaMcp::check_attestation_scoped",
        1,
    ),
    (
        "gateway::meta_mcp::invoke::policy::MetaMcp::refuse_unattested_plan",
        1,
    ),
    // A chain step's refusal rebuilt with its index and its own code.
    ("gateway::meta_mcp::search::chain_exec::step_failure", 1),
];

#[test]
fn a_gateway_refusal_is_built_only_at_reviewed_pre_send_sites() {
    assert_eq!(
        summed_sites(&[
            "Error::GatewayRefused",
            "Self::GatewayRefused",
            "gateway_refused"
        ]),
        reviewed(GATEWAY_REFUSED_SITES),
        "a gateway refusal frees an idempotency key, so it may be built only \
         before anything reaches the backend: review every new or removed \
         site (left: found, right: reviewed)"
    );
}

/// The transport builds a denial only through the lender's refusal, while
/// it builds a lent send's headers, before the request leaves; no transport
/// or agent-to-agent item builds a gateway refusal.
#[test]
fn the_transport_denies_only_while_building_headers() {
    let found = summed_sites(&["Error::Forbidden", "send_refused", "counted_refusal"]);
    let transport: Vec<&String> = found
        .keys()
        .filter(|k| k.starts_with("transport::"))
        .collect();
    assert!(
        transport
            .iter()
            .all(|k| k.starts_with("transport::lender::")
                || k.starts_with("transport::http::requests::")),
        "a transport denial outside the lender's header step: {transport:?}"
    );
    let refused = summed_sites(&["Error::GatewayRefused", "gateway_refused"]);
    assert!(
        refused
            .keys()
            .all(|k| !k.starts_with("transport::") && !k.starts_with("a2a::")),
        "a gateway refusal built in the transport: {refused:?}"
    );
}

/// A value built right after a closure's parameters is a construction: the
/// closing `|` of `|_|` is not a pattern alternative.
#[test]
fn a_construction_after_a_closures_parameters_is_counted() {
    let src = "fn f(r: Result<(), E>) -> Result<(), Error> {\n\
               r.map_err(|_| crate::Error::BackendUnavailable(String::new()))\n\
               }\n\
               fn g(e: &Error) -> bool {\n\
               matches!(e, Error::Transport(_)\n    | Error::BackendUnavailable(_))\n\
               }\n";
    assert_eq!(constructions(src), 1, "{src}");
}

/// A struct variant's patterns are not constructions; a built value is.
#[test]
fn the_scan_tells_a_struct_variant_built_from_its_patterns() {
    let name = "Error::AmbiguousBackend";
    let count = |src: &str| construction_offsets(src, name).len();
    assert_eq!(count("Error::AmbiguousBackend { .. } => 1,"), 0);
    assert_eq!(
        count("matches!(e, Error::AmbiguousBackend { server, .. })"),
        0
    );
    assert_eq!(
        count("let Error::AmbiguousBackend { server, rule } = e else {};"),
        0
    );
    assert_eq!(count("| Error::AmbiguousBackend { .. }"), 0);
    assert_eq!(count("OfflineMigrationError::AmbiguousBackend { n: 1 }"), 0);
    assert_eq!(
        count("Error::AmbiguousBackend { server: s, rule: None }"),
        1
    );
    assert_eq!(count("crate::Error::AmbiguousBackend { server, rule }"), 1);
}

/// The item key is the enclosing method or function, whatever file holds it.
#[test]
fn a_construction_is_keyed_by_its_enclosing_item() {
    let src = "use a::make;\nimpl<T: Clone> Holder<T> {\n    fn build(&self) { make(); }\n}\nimpl Show for Wrapper {\n    fn show() { make(); }\n}\nfn free() { make(); }\n";
    let clean = sanitize(src);
    let items: Vec<String> = construction_offsets(&clean, "make")
        .into_iter()
        .map(|at| enclosing_item(&clean, at).0)
        .collect();
    assert_eq!(
        items,
        ["<module>", "Holder::build", "Wrapper::show", "free"]
    );
}

#[test]
fn a_signature_impl_trait_is_not_the_enclosing_owner() {
    let src = "fn g(x: impl Clone) { make(); }\nfn h() -> impl Clone { make(); }\n";
    let clean = sanitize(src);
    let items: Vec<String> = construction_offsets(&clean, "make")
        .into_iter()
        .map(|at| enclosing_item(&clean, at).0)
        .collect();
    assert_eq!(items, ["g", "h"]);
}

#[test]
fn one_key_names_one_function() {
    let src = "impl A { fn f() { make(); } }\nimpl A { fn f() { make(); } }\n";
    let clean = sanitize(src);
    let sites: Vec<(String, Option<usize>)> = construction_offsets(&clean, "make")
        .into_iter()
        .map(|at| enclosing_item(&clean, at))
        .collect();
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0].0.as_str(), "A::f");
    assert_eq!(sites[0].0.as_str(), sites[1].0.as_str());
    assert_ne!(sites[0].1, sites[1].1);
    let mut owners: BTreeMap<String, (String, Option<usize>)> = BTreeMap::new();
    assert!(record_construction_site(&mut owners, &sites[0].0, "snippet.rs", sites[0].1).is_ok());
    assert!(record_construction_site(&mut owners, &sites[0].0, "snippet.rs", sites[0].1).is_ok());
    let rejected = record_construction_site(&mut owners, &sites[1].0, "snippet.rs", sites[1].1);
    assert!(
        matches!(&rejected, Err(message) if message.contains("names two functions") && message.contains("a row must name one reviewed function")),
        "{rejected:?}"
    );
}

#[test]
fn module_path_follows_the_module_tree() {
    assert_eq!(
        module_path("gateway/meta_mcp/task_replay.rs"),
        "gateway::meta_mcp::task_replay"
    );
    assert_eq!(module_path("gateway/meta_mcp/mod.rs"), "gateway::meta_mcp");
    assert_eq!(module_path("error.rs"), "error");
    assert_eq!(module_path("lib.rs"), "");
}
