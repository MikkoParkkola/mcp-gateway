// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source scans of spans and log lines: no production `#[instrument]` site
//! records a principal (G-SPAN), and no events log line names a stored
//! subscription id (G-SUBID). A child of the record-principal scan tests, so
//! it shares their production-line classifier and test-only file list.

use std::path::Path;

use super::{CENSUS_TEST_ONLY, production_lines};

/// G-SPAN (§16.13 item 3): the problems in `text`'s `#[instrument]` sites. A
/// parameter whose type names a context, principal, caller or owner must be
/// skipped (`skip(..)` or `skip_all`), and `fields(..)` may not name a
/// principal, caller, owner or credential.
fn span_problems(rel: &str, text: &str) -> Vec<String> {
    const SENSITIVE_TYPES: &[&str] = &["Context", "Principal", "Caller", "Owner"];
    // By name as well as type: an `identity_key: Option<&str>` names no
    // sensitive type and still carries a credential binding.
    const SENSITIVE_NAMES: &[&str] = &[
        "key",
        "principal",
        "owner",
        "caller",
        "credential",
        "binding",
    ];
    const SENSITIVE_FIELDS: &[&str] = &["principal", "caller", "owner", "credential"];
    let lines = production_lines(text);
    let mut problems = Vec::new();
    for (k, (n, line)) in lines.iter().enumerate() {
        let t = line.trim_start();
        if !(t.starts_with("#[instrument") || t.starts_with("#[tracing::instrument")) {
            continue;
        }
        // The attribute and the signature, up to the body's opening brace.
        let mut site = String::new();
        for (_, next) in &lines[k..] {
            site.push_str(next.trim());
            site.push(' ');
            if next.trim_end().ends_with('{') || next.trim_end().ends_with(';') {
                break;
            }
        }
        let Some(fn_at) = site.find("fn ") else {
            problems.push(format!("{rel}:{}: no fn after #[instrument]", n + 1));
            continue;
        };
        let (attr, signature) = site.split_at(fn_at);
        let skip_all = attr.contains("skip_all");
        let skipped: Vec<&str> = attr
            .split_once("skip(")
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(list, _)| list.split(',').map(str::trim).collect())
            .unwrap_or_default();
        if let Some((_, fields)) = attr.split_once("fields(") {
            let fields = fields.to_ascii_lowercase();
            for name in SENSITIVE_FIELDS {
                if fields.contains(name) {
                    problems.push(format!("{rel}:{}: fields(..) names {name}", n + 1));
                }
            }
        }
        let params = signature
            .split_once('(')
            .map(|(_, rest)| {
                let mut depth = 0i32;
                let end = rest
                    .char_indices()
                    .find(|&(_, c)| {
                        match c {
                            '(' | '<' | '[' => depth += 1,
                            ')' | '>' | ']' => depth -= 1,
                            _ => {}
                        }
                        depth < 0
                    })
                    .map_or(rest.len(), |(i, _)| i);
                rest[..end].to_owned()
            })
            .unwrap_or_default();
        let mut depth = 0i32;
        let mut param = String::new();
        let mut all = Vec::new();
        for c in params.chars() {
            match c {
                '(' | '<' | '[' => depth += 1,
                ')' | '>' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    all.push(std::mem::take(&mut param));
                    continue;
                }
                _ => {}
            }
            param.push(c);
        }
        all.push(param);
        for param in all {
            let Some((name, ty)) = param.split_once(':') else {
                continue;
            };
            let name = name.trim().trim_start_matches("mut ").trim();
            let sensitive = SENSITIVE_TYPES.iter().any(|s| ty.contains(s))
                || SENSITIVE_NAMES.iter().any(|s| name.contains(s));
            if sensitive && !skip_all && !skipped.contains(&name) {
                problems.push(format!("{rel}:{}: `{name}` is recorded on the span", n + 1));
            }
        }
    }
    problems
}

/// G-SPAN's checker reports an unskipped context and a principal field.
#[test]
fn span_problems_names_an_unskipped_context_and_a_principal_field() {
    let unskipped = "#[tracing::instrument(skip(self), fields(cap = %c.name))]\n\
                     async fn run(&self, c: &Cap, context: &ExecutionContext) -> R {\n}\n";
    assert_eq!(
        span_problems("f.rs", unskipped).len(),
        1,
        "{:?}",
        span_problems("f.rs", unskipped)
    );
    let skipped = unskipped.replace("skip(self)", "skip(self, context)");
    assert!(span_problems("f.rs", &skipped).is_empty());
    let named = skipped.replace("cap = %c.name", "principal = %p");
    assert_eq!(span_problems("f.rs", &named).len(), 1);
    // A credential binding behind a plain type is caught by its name.
    let by_name = skipped.replace("context: &ExecutionContext", "identity_key: Option<&str>");
    assert_eq!(span_problems("f.rs", &by_name).len(), 1, "{by_name}");
}

/// G-SPAN over the source: no production span records a context, principal,
/// caller or owner.
#[test]
fn g_span_no_production_span_records_a_principal() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (mut problems, mut sites) = (Vec::new(), 0usize);
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
            sites += text.matches("instrument(").count();
            problems.extend(span_problems(&rel, &text));
        }
    }
    assert!(sites >= 9, "the scan found the instrumented sites: {sites}");
    assert!(problems.is_empty(), "{problems:#?}");
}

/// Log macro calls (`problems`, `calls`) in `text` that format a stored
/// subscription id: a `.id` outside an `alias(&..)`/`handle(&..)` call, a
/// field holding a bound `id` or a `subscription_id`, or a record path, which
/// is named by the stored id (§13).
fn subid_problems(rel: &str, text: &str) -> (Vec<String>, usize) {
    let open =
        regex::Regex::new(r"\b(?:tracing::)?(?:trace|debug|info|warn|error)!\(").expect("regex");
    let keyed = regex::Regex::new(r"(?:alias|handle)\(&[\w.]+\)").expect("regex");
    let stored = regex::Regex::new(r"\.id\b|[%?]id\b|\bid\s*=|subscription_id|path\.display\(\)")
        .expect("regex");
    let lines = production_lines(text);
    let (mut problems, mut calls) = (Vec::new(), 0);
    for (i, (number, line)) in lines.iter().enumerate() {
        let Some(start) = open
            .find(line)
            .filter(|_| !line.trim_start().starts_with("//"))
        else {
            continue;
        };
        calls += 1;
        // The call to its closing parenthesis, across lines.
        let (mut call, mut depth) = (String::new(), 0_i32);
        'call: for (j, (_, next)) in lines[i..].iter().enumerate() {
            let from = if j == 0 { start.end() - 1 } else { 0 };
            for c in next[from..].chars() {
                call.push(c);
                depth += match c {
                    '(' => 1,
                    ')' => -1,
                    _ => 0,
                };
                if depth == 0 {
                    break 'call;
                }
            }
        }
        if stored.is_match(&keyed.replace_all(&call, "")) {
            problems.push(format!("{rel}:{number}: {}", line.trim()));
        }
    }
    (problems, calls)
}

/// G-SUBID's checker reports a stored id and a record path, and passes a
/// keyed handle.
#[test]
fn subid_problems_names_a_stored_id_and_a_record_path() {
    let check = |text: &str| subid_problems("f.rs", text).0.len();
    assert_eq!(
        check("fn f() {\n    warn!(subscription = %sub.id, \"x\");\n}\n"),
        1
    );
    assert_eq!(
        check(
            "fn f() {\n    tracing::warn!(\n        a = 1,\n        subscription = %r.id,\n        \"x\"\n    );\n}\n"
        ),
        1
    );
    assert_eq!(
        check("fn f() {\n    tracing::warn!(path = %path.display(), \"x\");\n}\n"),
        1
    );
    assert_eq!(
        check("fn f() {\n    warn!(subscription = %services.alias(&sub.id), \"x\");\n}\n"),
        0
    );
    assert_eq!(
        check("fn f() {\n    warn!(s = %self.handle(&r.id).unwrap_or_default(), \"x\");\n}\n"),
        0
    );
    // A bound id and a record's stored id under its own name.
    for shape in ["%id", "id = %r.subscription_id"] {
        let text = format!("fn f() {{\n    warn!({shape}, \"x\");\n}}\n");
        assert_eq!(check(&text), 1, "{text}");
    }
}

/// G-SUBID over `src/events`: no production log line formats a stored
/// subscription id.
#[test]
fn g_subid_no_events_log_line_names_a_stored_subscription_id() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (mut problems, mut calls) = (Vec::new(), 0usize);
    let mut dirs = vec![root.join("src/events")];
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
                || rel.ends_with("tests.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source readable");
            let (found, seen) = subid_problems(&rel, &text);
            problems.extend(found);
            calls += seen;
        }
    }
    assert!(calls >= 40, "the scan found the events log calls: {calls}");
    assert!(problems.is_empty(), "{problems:#?}");
}
