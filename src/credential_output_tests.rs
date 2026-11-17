// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! No credential digest or approval field reaches a serializer or a text
//! output, and a whole auth section or config reaches a serializer only at
//! pinned sites. A child of the credential-generation rows, for their
//! production-source walker.

use super::production_sources;

/// Threat model: a credential digest or approval field must not reach a
/// serializer, anything that leaves the process as JSON or text; nor may a
/// whole auth section or config, which holds every key's. Naming a field
/// anywhere else (the loader, validation, authorization) is not the threat.
///
/// Lexical, no syntax tree: a serializer call is one of these names followed
/// by its balanced argument list. A container under another name (auth.rs's
/// restart-only `view`, which drops the keys; a `value`) or a digest copied
/// into a local first is not seen; those spellings stay on register row 805.
const SERIALIZERS: [&str; 12] = [
    "json!(",
    "json![",
    "json!{",
    "to_value(",
    "to_string(",
    "to_string_pretty(",
    "to_vec(",
    "to_vec_pretty(",
    "to_writer(",
    "to_writer_pretty(",
    "canonical_json(",
    "canonical_json_sha256(",
];

/// Text that leaves the process too: log lines, formatted strings and panic
/// messages. A field read in one is barred like a serializer's; a whole
/// container is not, because a key's `Debug` already redacts its digests.
const TEXT_OUTPUTS: [&str; 22] = [
    "info!(",
    "warn!(",
    "error!(",
    "debug!(",
    "trace!(",
    "event!(",
    "format!(",
    "format_args!(",
    "write!(",
    "writeln!(",
    "println!(",
    "eprintln!(",
    "print!(",
    "eprint!(",
    "panic!(",
    "assert!(",
    "assert_eq!(",
    "assert_ne!(",
    "dbg!(",
    "todo!(",
    "unimplemented!(",
    "unreachable!(",
];

/// The credential digest and approval reads no serializer argument may hold.
const DIGEST_READS: [&str; 7] = [
    ".key_sha256",
    ".previous_key_sha256",
    ".digest_tag",
    ".approved_by",
    "resolve_digest(",
    "resolve_previous_digest(",
    "digest_specs_mut(",
];

/// The only sites that serialise an auth section or a whole config, with how
/// many each file holds, so a second site in one of these files fails too.
/// Every one is the config writer or an equality check inside the process.
const CONTAINER_SERIALIZERS: &[(&str, usize, &str)] = &[
    (
        "src/config_persistence.rs",
        1,
        "in-memory equality: the comment-loss check compares the configs before and after as JSON values",
    ),
    (
        "src/config_persistence_splice.rs",
        4,
        "in-memory equality: the spliced text must reload as the config, compared as JSON values",
    ),
    (
        "src/config_persistence_url.rs",
        1,
        "config writer: the whole config rendered to gateway.yaml, keys through AuthConfig's mirror",
    ),
    (
        "src/config_reload/diff.rs",
        1,
        "reload diff: compares the auth section as canonical JSON inside the process, never output",
    ),
    (
        "src/config_reload/live_config.rs",
        2,
        "same-auth check: two auth sections compared as JSON values inside the process, never output",
    ),
];

/// Each balanced argument list in `code` of a call to one of `names`, with
/// where the call starts.
fn call_arguments<'c>(code: &'c str, names: &[&str]) -> Vec<(usize, &'c str)> {
    let mut found = Vec::new();
    for name in names {
        for (at, _) in code.match_indices(name) {
            let open = at + name.len() - 1;
            let mut depth = 0_usize;
            for (offset, c) in code[open..].char_indices() {
                match c {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => {
                        depth -= 1;
                        if depth == 0 {
                            found.push((at, &code[open + 1..open + offset]));
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    found
}

/// The depth-zero arguments of an argument list.
fn top_level(arguments: &str) -> Vec<&str> {
    let (mut depth, mut from, mut args) = (0_usize, 0, Vec::new());
    for (at, c) in arguments.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                args.push(&arguments[from..at]);
                from = at + 1;
            }
            _ => {}
        }
    }
    args.push(&arguments[from..]);
    args
}

/// An auth section or a whole config among a call's arguments: `config` /
/// `auth` alone; a value built by `Config::` or `AuthConfig::`; a closure
/// parameter typed `&Config` or `&AuthConfig` on the call's line or the one
/// above; or a `.auth` (`.auth()`) that is the value itself, cloned or
/// borrowed at most, not a member read such as `.auth().enabled`.
fn is_container(code: &str, at: usize, arguments: &str) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let line_start = code[..at].rfind('\n').map_or(0, |n| n + 1);
    let above = code[..line_start.saturating_sub(1)]
        .rfind('\n')
        .map_or(0, |n| n + 1);
    let near = &code[above..at];
    top_level(arguments).into_iter().any(|argument| {
        // `config` or `auth` borrowed, dereferenced, cloned or converted is
        // still the whole value.
        let mut bare = argument
            .trim()
            .trim_start_matches(['&', '*'])
            .trim_start_matches("mut ")
            .trim();
        while let Some(shorter) = [".clone()", ".to_owned()", ".as_ref()", ".deref()"]
            .iter()
            .find_map(|suffix| bare.strip_suffix(suffix))
        {
            bare = shorter;
        }
        let typed_closure = !bare.is_empty()
            && bare.chars().all(ident)
            && ["Config", "AuthConfig"]
                .iter()
                .any(|ty| near.contains(&format!("|{bare}: &{ty}|")));
        bare == "config"
            || bare == "auth"
            || typed_closure
            || argument.contains("Config::")
            || argument.match_indices(".auth").any(|(at, word)| {
                // Any chain of these, in any order, still yields the section.
                let mut rest = &argument[at + word.len()..];
                while let Some(shorter) = ["()", ".clone()", ".to_owned()", ".as_ref()"]
                    .iter()
                    .find_map(|suffix| rest.strip_prefix(suffix))
                {
                    rest = shorter;
                }
                let rest = rest.trim_start();
                !rest.starts_with(ident) && !rest.starts_with('.')
            })
    })
}

/// Each spelling the review rounds named, through the scan's own helpers on
/// synthetic code: the macro's three delimiters (the `json!({..})` form was
/// always scanned), a text output, a container as a later argument, a cloned
/// auth section, a closure typed on the line above, and a member read that
/// is not a container.
#[test]
fn the_output_scan_sees_each_reviewed_spelling() {
    let outputs = [&SERIALIZERS[..], &TEXT_OUTPUTS[..]].concat();
    let reads = |code: &str| {
        call_arguments(code, &outputs)
            .iter()
            .any(|(_, a)| DIGEST_READS.iter().any(|read| a.contains(read)))
    };
    assert!(
        reads("let v = json!({ d: key.key_sha256 });"),
        "json! object in parentheses"
    );
    assert!(reads("let v = json![key.key_sha256];"), "json! in brackets");
    assert!(reads("let v = json!{ key.key_sha256 };"), "json! in braces");
    assert!(reads("print!(\"{:?}\", key.digest_tag);"), "print!");
    let container = |code: &str| {
        call_arguments(code, &SERIALIZERS)
            .iter()
            .any(|(at, a)| is_container(code, *at, a))
    };
    assert!(
        container("serde_json::to_writer(&mut out, &config)"),
        "a later argument"
    );
    assert!(
        container("serde_json::to_value(&state.auth.clone())"),
        ".auth.clone()"
    );
    assert!(
        container("serde_json::to_value(&state.auth.as_ref().clone())"),
        ".auth.as_ref().clone()"
    );
    assert!(
        container("serde_json::to_value(config.clone())"),
        "config.clone()"
    );
    assert!(
        container("serde_json::to_writer(out, &mut auth)"),
        "&mut auth"
    );
    assert!(
        container("let f = |c: &Config|\n    serde_json::to_value(c);"),
        "a closure typed on the line above"
    );
    assert!(
        !container("json!({ on: live.auth().enabled })"),
        "a member read is not a container"
    );
}

#[test]
fn no_credential_field_reaches_a_serializer() {
    let mut reads = Vec::new();
    let mut containers: Vec<(String, usize)> = Vec::new();
    for (file, code) in production_sources() {
        let arguments = call_arguments(&code, &SERIALIZERS);
        let outputs = call_arguments(&code, &[&SERIALIZERS[..], &TEXT_OUTPUTS[..]].concat());
        for read in DIGEST_READS {
            if outputs.iter().any(|(_, a)| a.contains(read)) {
                reads.push(format!("{file}: {read}"));
            }
        }
        let count = arguments
            .iter()
            .filter(|(at, a)| is_container(&code, *at, a))
            .count();
        if count > 0 {
            containers.push((file, count));
        }
    }
    assert!(
        reads.is_empty(),
        "a credential field reaches a serializer or text output: {reads:?}"
    );
    containers.sort();
    let mut want: Vec<(String, usize)> = CONTAINER_SERIALIZERS
        .iter()
        .map(|(file, count, _)| ((*file).to_owned(), *count))
        .collect();
    want.sort();
    assert_eq!(
        containers, want,
        "an auth section or config reaches a serializer outside the listed sites"
    );
}
