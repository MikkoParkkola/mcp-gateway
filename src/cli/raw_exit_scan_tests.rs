// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! LERRA.2: command code reaches a non-zero exit only by calling `fail`, `usage` or `verdict`, and never prints its
//! own `Error`-style line. The scan parses every file of the command tree with syn (skipping what only tests
//! compile, by `test_source_text::test_only`), and reads macro bodies as raw tokens because syn does not parse them.
//!
//! What it reports: the `FAILURE` constant of `ExitCode`; any `ExitCode::from(..)` call; a `process::exit` whose
//! argument is not a plain `0`; an `exit` field in a struct being built, written out or shorthand, unless it is a
//! plain `0`; an `eprintln!` opening with `Error` or `error:`; and the first three again when they sit in a macro.
//! What it allows, by file and function: the whole shared exit module (which also holds `Printed`'s two failing
//! constructors); `Printed::emit` in the output module; serve's two start functions with exactly four each (their
//! fatal-line contract); and the remote dashboard-link command's own exit, exactly one. Every other command file
//! is held to the rule; there is no list of files still to convert.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::spanned::Spanned;
use syn::visit::Visit;

/// One raw failing exit or error print.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Hit {
    path: String,
    line: usize,
    owner: String,
    what: &'static str,
}

/// Functions allowed a fixed number of raw exits: (file, function, how many).
const COUNTED: [(&str, &str, usize); 3] = [
    ("src/cli/entry.rs", "run_stdio_server", 4),
    ("src/cli/entry.rs", "run_server", 4),
    (
        "src/commands/dashboard_link.rs",
        "run_dashboard_link_args",
        1,
    ),
];

/// Command files outside the two command directories.
const NAMED: [&str; 3] = [
    "src/trust/provenance_public_cli.rs",
    "src/validator/cli_handler.rs",
    "src/trust/export_verify.rs",
];

fn line_of(span: proc_macro2::Span) -> usize {
    span.start().line
}

/// Whether `path`'s final two segments are `a` then `b`.
fn ends_with(path: &syn::Path, a: &str, b: &str) -> bool {
    let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    segments.len() >= 2 && segments[segments.len() - 2] == a && segments[segments.len() - 1] == b
}

fn is_literal_zero(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(int), .. }) if int.base10_digits() == "0")
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(i) => &i.attrs,
        syn::Item::Enum(i) => &i.attrs,
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Macro(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Static(i) => &i.attrs,
        syn::Item::Struct(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        syn::Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

struct Scan {
    path: String,
    owner: Vec<String>,
    hits: Vec<Hit>,
}

impl Scan {
    fn hit(&mut self, line: usize, what: &'static str) {
        self.hits.push(Hit {
            path: self.path.clone(),
            line,
            owner: self.owner.last().cloned().unwrap_or_default(),
            what,
        });
    }

    /// The exit shapes in a macro body, read token by token (groups too).
    fn tokens(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        for (i, tree) in trees.iter().enumerate() {
            if let TokenTree::Group(group) = tree {
                self.tokens(group.stream());
            }
            let TokenTree::Ident(first) = tree else {
                continue;
            };
            let Some(second) = path_step(&trees, i) else {
                continue;
            };
            let args = match trees.get(i + 4) {
                Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis => {
                    Some(g.stream())
                }
                _ => None,
            };
            match (first.to_string().as_str(), second.as_str(), args) {
                ("ExitCode", "FAILURE", _) => {
                    self.hit(line_of(first.span()), "ExitCode::FAILURE in a macro");
                }
                ("ExitCode", "from", Some(_)) => {
                    self.hit(line_of(first.span()), "ExitCode::from in a macro");
                }
                ("process", "exit", Some(inside)) if inside.to_string() != "0" => {
                    self.hit(line_of(first.span()), "process::exit in a macro");
                }
                _ => {}
            }
        }
    }
}

/// The identifier that follows `trees[i]` across a `::`, if there is one.
fn path_step(trees: &[TokenTree], i: usize) -> Option<String> {
    match (trees.get(i + 1), trees.get(i + 2), trees.get(i + 3)) {
        (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)), Some(TokenTree::Ident(next)))
            if a.as_char() == ':' && b.as_char() == ':' =>
        {
            Some(next.to_string())
        }
        _ => None,
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if crate::test_source_text::test_only(item_attrs(item)) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        self.owner.push(function.sig.ident.to_string());
        syn::visit::visit_item_fn(self, function);
        self.owner.pop();
    }

    fn visit_item_impl(&mut self, block: &'ast syn::ItemImpl) {
        let ty = match block.self_ty.as_ref() {
            syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
            _ => None,
        }
        .unwrap_or_default();
        for item in &block.items {
            if let syn::ImplItem::Fn(method) = item {
                if crate::test_source_text::test_only(&method.attrs) {
                    continue;
                }
                self.owner.push(format!("{ty}::{}", method.sig.ident));
                syn::visit::visit_impl_item_fn(self, method);
                self.owner.pop();
            } else {
                syn::visit::visit_impl_item(self, item);
            }
        }
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if ends_with(&path.path, "ExitCode", "FAILURE") {
            self.hit(line_of(path.span()), "ExitCode::FAILURE");
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(func) = call.func.as_ref() {
            if ends_with(&func.path, "ExitCode", "from") {
                self.hit(line_of(call.span()), "ExitCode::from");
            }
            let zero = call.args.len() == 1 && call.args.first().is_some_and(is_literal_zero);
            if ends_with(&func.path, "process", "exit") && !zero {
                self.hit(line_of(call.span()), "process::exit");
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_struct(&mut self, literal: &'ast syn::ExprStruct) {
        for field in &literal.fields {
            let named_exit = matches!(&field.member, syn::Member::Named(n) if n == "exit");
            if named_exit && (field.colon_token.is_none() || !is_literal_zero(&field.expr)) {
                self.hit(line_of(field.span()), "exit field");
            }
        }
        syn::visit::visit_expr_struct(self, literal);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac.path.is_ident("eprintln")
            && let Some(TokenTree::Literal(lit)) = mac.tokens.clone().into_iter().next()
        {
            let text =
                syn::parse2::<syn::LitStr>(TokenTree::Literal(lit).into()).map(|s| s.value());
            if text.is_ok_and(|t| t.starts_with("Error") || t.starts_with("error:")) {
                self.hit(line_of(mac.path.span()), "Error print");
            }
        }
        self.tokens(mac.tokens.clone());
        syn::visit::visit_macro(self, mac);
    }
}

/// The hits in `text` (the file at `path`). A file syn cannot parse is an error, never a clean result.
fn scan_source(path: &str, text: &str) -> Result<Vec<Hit>, String> {
    let file = syn::parse_file(text).map_err(|e| format!("{path} does not parse: {e}"))?;
    let mut scan = Scan {
        path: path.to_owned(),
        owner: Vec::new(),
        hits: Vec::new(),
    };
    scan.visit_file(&file);
    scan.hits.sort_by_key(|h| h.line);
    Ok(scan.hits)
}

/// Hits outside the allowed places. A counted function keeps its first `count` hits allowed; the rest are hits.
fn unallowed(hits: &[Hit]) -> Vec<Hit> {
    let mut used: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    let mut out = Vec::new();
    for hit in hits {
        if hit.path == "src/commands/cli_exit.rs" {
            continue;
        }
        if hit.path == "src/cli/output.rs" && mutant!("N27", matches!(hit.owner.as_str(), "Printed::emit" | "Printed::error" | "Printed::verdict"), hit.owner == "Printed::emit") {
            continue;
        }
        let place = COUNTED
            .iter()
            .find(|(file, owner, _)| hit.path == *file && hit.owner == *owner);
        if let Some((file, owner, count)) = place {
            let seen = used.entry((file, owner)).or_default();
            *seen += 1;
            if *seen <= *count {
                continue;
            }
        }
        out.push(hit.clone());
    }
    out
}

/// The command tree under `root`, sorted and relative to it: Rust files below the two command directories and the
/// named files, test files left out (a name ending `_tests.rs` or equal to `tests.rs`, a `tests` directory on the
/// way, a name holding `test_support`). A named file that is absent is an error.
fn tree_files(root: &Path) -> Result<Vec<String>, String> {
    let mut found: Vec<PathBuf> = Vec::new();
    crate::test_source_files::rust_files(&root.join("src/commands"), &mut found);
    crate::test_source_files::rust_files(&root.join("src/cli"), &mut found);
    for named in NAMED {
        let path = root.join(named);
        if !path.is_file() {
            return Err(format!("{named} is missing"));
        }
        found.push(path);
    }
    let mut out: Vec<String> = found
        .iter()
        .filter_map(|path| path.strip_prefix(root).ok())
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .filter(|rel| {
            let name = rel.rsplit('/').next().unwrap_or(rel);
            let test_file = name.ends_with("_tests.rs") || name == "tests.rs";
            let test_dir = rel.split('/').any(|part| part == "tests");
            !(test_file || test_dir || name.contains("test_support"))
        })
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// `body` as the inside of a function, so its first line is line 2 of the file.
fn in_fn(body: &str) -> String {
    format!("fn body() {{\n{body}\n}}")
}

fn hits_of(path: &str, text: &str) -> Vec<Hit> {
    scan_source(path, text).unwrap_or_else(|e| panic!("{e}"))
}

/// F1: every refused shape gives exactly one hit, on the expected line.
#[test]
fn each_raw_exit_shape_is_one_hit() {
    let legs: [(&str, String, usize); 13] = [
        ("a", "fn quit() -> ExitCode { ExitCode::FAILURE }".into(), 1),
        (
            "b",
            in_fn("let _code = std::process::ExitCode::FAILURE;"),
            2,
        ),
        ("c", in_fn("let _code = ExitCode :: from\n(7);"), 2),
        ("d", in_fn("std::process::exit(9);"), 2),
        ("e", in_fn("let r = Reply { body, err, exit: worst };"), 2),
        ("f", in_fn("let r = Reply { body, err, exit };"), 2),
        ("g", in_fn("eprintln!(\"Error: disk full\");"), 2),
        ("h", in_fn("eprintln!(\n    \"error: gone\");"), 2),
        (
            "i",
            in_fn("tokio::select! { _ = pending => return ExitCode::FAILURE }"),
            2,
        ),
        ("j", in_fn("let zero = ExitCode::from(0);"), 2),
        (
            "k",
            "#[cfg(any(test, feature = \"webui\"))]\nfn shown() -> ExitCode { ExitCode::FAILURE }"
                .into(),
            2,
        ),
        (
            "l",
            in_fn("tokio::select! { _ = pending => std::process::exit(9) }"),
            2,
        ),
        ("m", in_fn("let codes = vec![ExitCode::from(7)];"), 2),
    ];
    let mut misses = Vec::new();
    for (leg, text, line) in &legs {
        let hits = hits_of("src/commands/x.rs", text);
        let lines: Vec<usize> = hits.iter().map(|h| h.line).collect();
        if lines != [*line] {
            misses.push(format!("({leg}) want one hit at line {line}, got {hits:?}"));
        }
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// F2: the permitted forms give no hit.
#[test]
fn permitted_shapes_are_not_hits() {
    let legs: [(&str, String); 15] = [
        ("a", in_fn("let _c = fail(CliExit::LocalFailure, \"why\", \"next\");")),
        ("b", in_fn("let _c = usage(\"stats\", \"why\");")),
        ("c", in_fn("let _c = verdict(4);")),
        ("d", in_fn("let _c = ExitCode::SUCCESS;")),
        ("e", in_fn("::std::process::exit(0);")),
        ("e2", "macro_rules! bye { () => { ::std::process::exit(0) }; }".into()),
        ("f", in_fn("let r = Reply { body, err, exit: 0 };")),
        ("g", "struct Reply { exit: u8 }".into()),
        ("h", "fn pass(exit: ExitCode) -> ExitCode { exit }".into()),
        ("i", in_fn("// ExitCode::FAILURE in a comment\n/* eprintln!(\"Error\") */")),
        ("j", in_fn("let text = \"ExitCode::FAILURE\";")),
        ("k", in_fn("eprintln!(\"warning: disk\");")),
        ("k2", in_fn("eprintln!(\"{}\", \"Error first word of an argument\");")),
        ("l", "#[cfg(test)]\nmod checks {\n    fn quit() -> ExitCode { ExitCode::FAILURE }\n}".into()),
        (
            "l2",
            "#[cfg(all(unix, test))]\nmod checks {\n    fn quit() -> ExitCode { ExitCode::FAILURE }\n}".into(),
        ),
    ];
    let mut misses = Vec::new();
    for (leg, text) in &legs {
        let hits = hits_of("src/commands/x.rs", text);
        if !hits.is_empty() {
            misses.push(format!("({leg}) want no hit, got {hits:?}"));
        }
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// F3: the same body is allowed or refused by its place alone.
#[test]
fn allowed_places_are_exact() {
    let failing = "ExitCode::FAILURE";
    let count = |path: &str, text: &str| unallowed(&hits_of(path, text)).len();
    let emit = format!(
        "impl Printed {{\n    fn emit(&self) -> ExitCode {{\n        {failing}\n    }}\n}}"
    );
    let other = format!("fn print_document() -> ExitCode {{ {failing} }}");
    assert_eq!(count("src/cli/output.rs", &emit), 0, "(a) Printed::emit");
    assert_eq!(count("src/cli/output.rs", &other), 1, "(a) another fn");
    let plain = format!("fn closes() -> ExitCode {{ {failing} }}");
    assert_eq!(
        count("src/commands/cli_exit.rs", &plain),
        0,
        "(b) the shared module"
    );
    assert_eq!(
        count("src/commands/ranking.rs", &plain),
        1,
        "(b) a command file"
    );
    let serve = |n: usize| {
        let body = vec![format!("let _code = {failing};"); n].join("\n");
        format!("fn run_server() {{\n{body}\n}}")
    };
    assert_eq!(
        count("src/cli/entry.rs", &serve(4)),
        0,
        "(c) 4 in run_server"
    );
    let five = unallowed(&hits_of("src/cli/entry.rs", &serve(5)));
    assert_eq!(five.len(), 1, "(c) a 5th in run_server: {five:?}");
    assert_eq!(five[0].line, 6, "(c) the 5th is the hit");
    let run = format!("fn run() -> ExitCode {{ {failing} }}");
    assert_eq!(count("src/cli/entry.rs", &run), 1, "(c) fn run");
    let link = format!("fn run_dashboard_link_args() -> ExitCode {{ {failing} }}");
    assert_eq!(
        count("src/commands/dashboard_link.rs", &link),
        0,
        "(d) its own fn"
    );
    let elsewhere = format!("fn helper() -> ExitCode {{ {failing} }}");
    assert_eq!(
        count("src/commands/dashboard_link.rs", &elsewhere),
        1,
        "(d) another fn"
    );
    // The two failing constructors live in the shared exit module, so the same names in output.rs are hits.
    for method in ["error", "verdict"] {
        let body = format!(
            "impl Printed {{\n    fn {method}() -> ExitCode {{\n        {failing}\n    }}\n}}"
        );
        assert_eq!(
            count("src/cli/output.rs", &body),
            1,
            "(e) Printed::{method}"
        );
    }
}

/// F4: an unparseable file fails the scan and names the file.
#[test]
fn an_unparseable_file_fails_the_scan() {
    let error =
        scan_source("src/commands/broken.rs", "fn half( {").expect_err("never an empty list");
    assert!(error.contains("src/commands/broken.rs"), "{error}");
}

/// F6: on a fixture tree, exactly the command files are scanned.
#[test]
fn the_scanned_set_is_exact() {
    let root = tempfile::tempdir().expect("tempdir");
    let dropped = [
        "src/other/z.rs",
        "src/commands/tests.rs",
        "src/trust/other.rs",
        "src/commands/a_tests.rs",
        "src/cli/c.txt",
        "src/commands/winacl_test_support.rs",
        "src/validator/other.rs",
        "src/commands/x/tests/y.rs",
    ];
    // `latest.rs` holds "test" in its name and must still be kept.
    let mut kept = [
        "src/validator/cli_handler.rs",
        "src/commands/latest.rs",
        "src/trust/provenance_public_cli.rs",
        "src/commands/sub/b.rs",
        "src/cli/c.rs",
        "src/trust/export_verify.rs",
        "src/commands/a.rs",
    ];
    for file in dropped.iter().chain(kept.iter()) {
        let path = root.path().join(file);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(&path, "fn body() {}\n").expect("write");
    }
    kept.sort_unstable();
    assert_eq!(tree_files(root.path()).expect("the tree"), kept);
    std::fs::remove_file(root.path().join("src/trust/export_verify.rs")).expect("remove");
    let error = tree_files(root.path()).expect_err("a named file is missing");
    assert!(error.contains("src/trust/export_verify.rs"), "{error}");
}

/// S1: the real tree holds no raw failing exit or error print outside the allowed places.
#[test]
fn no_raw_failing_exit_in_command_code() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = tree_files(root).unwrap_or_else(|e| panic!("{e}"));
    for arrival in [
        "src/trust/provenance_public_cli.rs",
        "src/commands/doctor/shadow.rs",
        "src/cli/entry.rs",
        "src/validator/cli_handler.rs",
        "src/commands/mod.rs",
    ] {
        assert!(files.iter().any(|f| f == arrival), "{arrival} not scanned");
    }
    assert!(files.len() >= 80, "only {} files scanned", files.len());
    let mut hits = Vec::new();
    for file in &files {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        hits.extend(scan_source(file, &text).unwrap_or_else(|e| panic!("{e}")));
    }
    let bad: Vec<String> = unallowed(&hits)
        .into_iter()
        .map(|h| format!("{}:{} {} (in {})", h.path, h.line, h.what, h.owner))
        .collect();
    assert!(
        bad.is_empty(),
        "{} raw failing exit(s) or error print(s) in command code; use fail, usage or verdict:\n{}",
        bad.len(),
        bad.join("\n")
    );
    for (file, owner, count) in COUNTED {
        let held = hits
            .iter()
            .filter(|h| h.path == file && h.owner == owner)
            .count();
        assert_eq!(
            held, count,
            "{file} {owner} holds {held} raw exits, want exactly {count}"
        );
    }
}
