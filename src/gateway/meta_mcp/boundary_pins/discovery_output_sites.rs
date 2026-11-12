// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Discovery output sites: client config text (a server name, a key, a
//! command) reaches the operator's terminal only through
//! `cli_support::shown`. Every argument of every output site in scope (a
//! print, write, format, log or assertion macro, a buffer or stream write) is
//! a `shown(..)` call or a literal, or a reviewed row of
//! `discovery_output_sites.tsv` with a class and a reason. Anything the scan
//! does not recognise is a site to review: it refuses by default.

use std::collections::{BTreeMap, BTreeSet};

use syn::ext::IdentExt;
use syn::parse::ParseStream;
use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

#[path = "discovery_output_sites_names.rs"]
mod names;
use names::file_names;

const ROOTS: [&str; 2] = ["src/lib.rs", "src/main.rs"];

/// Macros whose arguments are printed or formatted. The first group takes a
/// format string first; `write`/`writeln` take a destination first; the
/// tracing group takes fields and a format; `assert` a condition first; the
/// `_eq`/`_ne` forms print both compared values; `dbg` prints everything.
const FORMAT_FIRST: &[&str] = &[
    "print",
    "println",
    "eprint",
    "eprintln",
    "format",
    "format_args",
    "panic",
    "unreachable",
    "todo",
    "unimplemented",
];
const WRITE_MACROS: &[&str] = &["write", "writeln"];
const TRACING: &[&str] = &["trace", "debug", "info", "warn", "error", "event"];
const ASSERT_COND: &[&str] = &["assert", "debug_assert"];
const ASSERT_PAIR: &[&str] = &[
    "assert_eq",
    "assert_ne",
    "debug_assert_eq",
    "debug_assert_ne",
];
/// Macros that print nothing themselves; their bodies are still searched.
const INERT: &[&str] = &[
    "vec",
    "matches",
    "concat",
    "stringify",
    "include_str",
    "env",
    "cfg",
    "line",
    "file",
    "column",
    "module_path",
];
/// Method or path calls that write their arguments into a stream or buffer.
const WRITE_METHODS: &[&str] = &[
    "write",
    "write_all",
    "write_str",
    "write_fmt",
    "push",
    "push_str",
    "insert",
    "insert_str",
    "extend",
    "extend_from_slice",
];

/// Whether `file` (and, for `cli_support.rs`, the function) is in scope.
fn in_scope(at: &Place) -> bool {
    at.file.starts_with("src/discovery/")
        || at.file == "src/commands/cap/server_scan.rs"
        || at.file == "src/commands/cap_render.rs"
        || (at.file == "src/cli_support.rs" && at.func.as_deref() == Some("describe_skipped"))
}

/// One argument that is neither shown nor a literal:
/// (file, function, site, argument text).
type Key = (String, String, String, String);

/// What a file's `use` declarations say about names: macro aliases
/// (`use tracing::warn as w`) and whether a bare `shown` is the shared one.
#[derive(Default)]
struct FileNames {
    aliases: BTreeMap<String, String>,
    shown_imported: bool,
    shown_defined: bool,
    /// Functions whose whole body is one `shown(..)` call (`shown_path`).
    helpers: BTreeSet<String>,
    /// Per function, its parameters typed `Shown`: only `shown` builds one.
    shown_params: BTreeMap<String, BTreeSet<String>>,
}

/// The scan's findings: argument counts per key, and parse failures.
#[derive(Default)]
pub(super) struct Sites {
    pub(super) counts: BTreeMap<Key, usize>,
    names: BTreeMap<String, FileNames>,
    /// Escape helpers, by (file, name): a bare call resolves in its own
    /// file, `super::name` in the file that declared the caller's module.
    helpers: BTreeSet<(String, String)>,
    /// Each module file and the file whose `mod` item declared it.
    parents: BTreeMap<String, String>,
    /// The file of the last out-of-line `mod` item: the walk loads that
    /// module next.
    declaring: Option<String>,
    /// Judging a macro found in raw tokens: bindings there are invisible,
    /// so no `Shown` parameter is trusted.
    in_tokens: bool,
}

impl Sites {
    fn note(&mut self, at: &Place, site: &str, arg: String) {
        let key = (
            at.file.clone(),
            at.func.clone().unwrap_or_default(),
            site.to_owned(),
            arg,
        );
        *self.counts.entry(key).or_default() += 1;
    }

    fn names(&self, file: &str) -> Option<&FileNames> {
        self.names.get(file)
    }

    /// Whether `expr` needs no row: a literal, the shared escape or an escape
    /// helper, or a parameter of this function typed `Shown`.
    fn passes(&self, at: &Place, expr: &syn::Expr) -> bool {
        let expr = match expr {
            syn::Expr::Reference(r) => &*r.expr,
            syn::Expr::Paren(p) => &*p.expr,
            other => other,
        };
        let names = self.names(&at.file);
        match expr {
            syn::Expr::Lit(_) => true,
            syn::Expr::Path(p) => self.shown_param(at, &path_text(&p.path)),
            // `shown(..).to_string()`: the escaped text as a `String`.
            syn::Expr::MethodCall(m) if m.method == "to_string" && m.args.is_empty() => {
                self.passes(at, &m.receiver)
            }
            syn::Expr::Call(call) => {
                let syn::Expr::Path(func) = &*call.func else {
                    return false;
                };
                let path = path_text(&func.path);
                calls_shown(&path, &at.file, names) || self.calls_helper(at, &path)
            }
            _ => false,
        }
    }

    /// Whether `path` resolves to an escape helper: `name` in this file, or
    /// `super::name` in the file that declared this module.
    fn calls_helper(&self, at: &Place, path: &str) -> bool {
        let (file, name) = match path.strip_prefix("super::") {
            Some(name) => match self.parents.get(&at.file) {
                Some(parent) => (parent.clone(), name),
                None => return false,
            },
            None => (at.file.clone(), path),
        };
        !name.contains("::") && self.helpers.contains(&(file, name.to_owned()))
    }

    /// Whether `name` is a parameter of this function typed `Shown`.
    fn shown_param(&self, at: &Place, name: &str) -> bool {
        !self.in_tokens
            && self
                .names(&at.file)
                .and_then(|n| n.shown_params.get(at.func.as_deref().unwrap_or_default()))
                .is_some_and(|params| params.contains(name))
    }
}

/// A short, stable text for an expression: enough to key a reviewed row.
fn text(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Path(p) => path_text(&p.path),
        syn::Expr::Field(f) => {
            let member = match &f.member {
                syn::Member::Named(id) => id.to_string(),
                syn::Member::Unnamed(i) => i.index.to_string(),
            };
            format!("{}.{member}", text(&f.base))
        }
        syn::Expr::MethodCall(m) => format!("{}.{}()", text(&m.receiver), m.method),
        syn::Expr::Call(c) => format!("{}(..)", text(&c.func)),
        syn::Expr::Reference(r) => format!("&{}", text(&r.expr)),
        syn::Expr::Paren(p) => text(&p.expr),
        syn::Expr::Unary(u) => format!("unary {}", text(&u.expr)),
        syn::Expr::Index(i) => format!("{}[..]", text(&i.expr)),
        syn::Expr::Lit(_) => "<literal>".to_owned(),
        syn::Expr::Macro(m) => format!("{}!", path_text(&m.mac.path)),
        syn::Expr::If(_) => "<if>".to_owned(),
        syn::Expr::Match(_) => "<match>".to_owned(),
        syn::Expr::Block(_) => "<block>".to_owned(),
        syn::Expr::Closure(_) => "<closure>".to_owned(),
        _ => "<expression>".to_owned(),
    }
}

fn path_text(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.unraw().to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Whether `call` names the shared escape: `crate::cli_support::shown`,
/// `mcp_gateway::cli_support::shown`, a bare `shown` in `cli_support.rs` (its
/// definition) or in a file that imports that one and defines no `shown` of
/// its own.
fn calls_shown(path: &str, file: &str, names: Option<&FileNames>) -> bool {
    match path {
        "crate::cli_support::shown" | "mcp_gateway::cli_support::shown" => true,
        "shown" => {
            file == "src/cli_support.rs"
                || names.is_some_and(|n| n.shown_imported && !n.shown_defined)
        }
        _ => false,
    }
}

/// The `{name}` captures of a format string (positional `{}`, `{0}` and
/// escaped `{{` are not captures).
fn captures(format: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = format;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        if let Some(stripped) = after.strip_prefix('{') {
            rest = stripped;
            continue;
        }
        let Some(close) = after.find('}') else { break };
        let name = after[..close].split(':').next().unwrap_or_default().trim();
        if name
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        {
            out.push(name.trim_start_matches("r#").to_owned());
        }
        rest = &after[close + 1..];
    }
    out
}

/// A parsed macro body: comma-separated expressions.
fn exprs(mac: &syn::Macro) -> Option<Vec<syn::Expr>> {
    mac.parse_body_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated)
        .ok()
        .map(|p| p.into_iter().collect())
}

/// A tracing body: each field's value expression, then the format string and
/// its arguments, in order (`name = %x`, `?x`, `name = x`, a literal).
fn tracing_parts(input: ParseStream) -> syn::Result<Vec<syn::Expr>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        if input.peek(syn::Ident) && input.peek2(syn::Token![=]) && !input.peek2(syn::Token![==]) {
            input.parse::<syn::Ident>()?;
            input.parse::<syn::Token![=]>()?;
        }
        if input.peek(syn::Token![%]) {
            input.parse::<syn::Token![%]>()?;
        } else if input.peek(syn::Token![?]) {
            input.parse::<syn::Token![?]>()?;
        }
        out.push(input.parse::<syn::Expr>()?);
        if !input.is_empty() {
            input.parse::<syn::Token![,]>()?;
        }
    }
    Ok(out)
}

fn is_str_literal(expr: &syn::Expr) -> bool {
    matches!(
        expr,
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(_),
            ..
        })
    )
}

impl Sites {
    /// One output argument: passes when shown or a literal; anything nested
    /// in it is judged too.
    fn argument(&mut self, at: &Place, site: &str, expr: &syn::Expr) {
        let expr = match expr {
            // A named format argument `name = expr`: judge the value.
            syn::Expr::Assign(a) => &*a.right,
            other => other,
        };
        if !self.passes(at, expr) {
            self.note(at, site, text(expr));
        }
        self.nested(at, expr);
    }

    /// The format string at `args[0]`, then its arguments.
    fn formatted(&mut self, at: &Place, site: &str, args: &[syn::Expr]) {
        let Some((first, rest)) = args.split_first() else {
            return;
        };
        if let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) = first
        {
            let named: BTreeSet<String> = rest
                .iter()
                .filter_map(|a| match a {
                    syn::Expr::Assign(a) => Some(text(&a.left)),
                    _ => None,
                })
                .collect();
            for name in captures(&s.value()) {
                if !named.contains(&name) && !self.shown_param(at, &name) {
                    self.note(at, site, format!("{{{name}}}"));
                }
            }
        } else {
            // A format string the scan cannot read hides its captures.
            self.note(at, site, "<format not a literal>".to_owned());
            self.nested(at, first);
        }
        for arg in rest {
            self.argument(at, site, arg);
        }
    }

    /// Search `expr` for output sites inside it (macros, writes).
    fn nested(&mut self, at: &Place, expr: &syn::Expr) {
        let mut visitor = Nested { sites: self, at };
        visitor.visit_expr(expr);
    }

    /// One macro invocation, by family; any other macro is a site to review.
    fn mac(&mut self, at: &Place, mac: &syn::Macro) {
        let written = mac
            .path
            .segments
            .last()
            .map_or_default(|s| s.ident.unraw().to_string());
        let name = self
            .names(&at.file)
            .and_then(|n| n.aliases.get(&written).cloned())
            .unwrap_or(written);
        let site = format!("{name}!");
        let n = name.as_str();
        let parsed = if TRACING.contains(&n) {
            mac.parse_body_with(tracing_parts).ok()
        } else {
            exprs(mac)
        };
        let Some(args) = parsed else {
            // A body the scan cannot parse: reviewed as a whole, and its
            // tokens still searched for the output macros inside it.
            self.note(at, &site, "<body not parsed>".to_owned());
            self.token_macros(at, mac);
            return;
        };
        if FORMAT_FIRST.contains(&n) {
            self.formatted(at, &site, &args);
        } else if WRITE_MACROS.contains(&n) {
            if let Some((dest, rest)) = args.split_first() {
                self.nested(at, dest);
                self.formatted(at, &site, rest);
            }
        } else if TRACING.contains(&n) {
            let start = args.iter().position(is_str_literal).unwrap_or(args.len());
            for field in &args[..start] {
                self.argument(at, &site, field);
            }
            self.formatted(at, &site, &args[start..]);
        } else if ASSERT_COND.contains(&n) {
            if let Some((cond, rest)) = args.split_first() {
                self.nested(at, cond);
                self.formatted(at, &site, rest);
            }
        } else if ASSERT_PAIR.contains(&n) {
            let (pair, rest) = args.split_at(args.len().min(2));
            for value in pair {
                self.argument(at, &site, value);
            }
            self.formatted(at, &site, rest);
        } else if n == "dbg" {
            for arg in &args {
                self.argument(at, &site, arg);
            }
        } else {
            if !INERT.contains(&n) {
                self.note(at, "macro", site.clone());
            }
            for arg in &args {
                self.nested(at, arg);
            }
        }
    }

    /// Judge every `name!(..)` invocation inside `mac`'s raw tokens, for a
    /// body that does not parse as expressions (`select!`, `macro_rules!`).
    fn token_macros(&mut self, at: &Place, mac: &syn::Macro) {
        let buffer = syn::buffer::TokenBuffer::new2(mac.tokens.clone());
        let mut found = Vec::new();
        macros_in(buffer.begin(), &mut found);
        let outer = std::mem::replace(&mut self.in_tokens, true);
        for inner in &found {
            self.mac(at, inner);
        }
        self.in_tokens = outer;
    }

    /// A method or path call that writes: each argument is judged.
    fn write_call(
        &mut self,
        at: &Place,
        method: &str,
        args: &syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>,
    ) {
        if WRITE_METHODS.contains(&method) {
            let site = format!("{method}()");
            for arg in args {
                self.argument(at, &site, arg);
            }
        }
    }
}

/// Visits what the walk cannot see into (a macro's arguments), and judges
/// each node the walk reports.
struct Nested<'a> {
    sites: &'a mut Sites,
    at: &'a Place,
}

impl<'ast> Visit<'ast> for Nested<'_> {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.sites.mac(self.at, mac);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.sites
            .write_call(self.at, &call.method.unraw().to_string(), &call.args);
        if WRITE_METHODS.contains(&call.method.unraw().to_string().as_str()) {
            self.visit_expr(&call.receiver);
        } else {
            syn::visit::visit_expr_method_call(self, call);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let last = match &*call.func {
            syn::Expr::Path(p) => p.path.segments.last().map(|s| s.ident.unraw().to_string()),
            _ => None,
        };
        match last {
            Some(name) if WRITE_METHODS.contains(&name.as_str()) => {
                self.sites.write_call(self.at, &name, &call.args);
            }
            _ => syn::visit::visit_expr_call(self, call),
        }
    }

    fn visit_expr_binary(&mut self, bin: &'ast syn::ExprBinary) {
        if matches!(bin.op, syn::BinOp::AddAssign(_)) {
            self.sites.argument(self.at, "+=", &bin.right);
            self.visit_expr(&bin.left);
        } else {
            syn::visit::visit_expr_binary(self, bin);
        }
    }
}

/// The `name!(..)` invocations in a token stream, at any depth of groups.
fn macros_in(mut cursor: syn::buffer::Cursor<'_>, out: &mut Vec<syn::Macro>) {
    while let Some((tree, next)) = cursor.token_tree() {
        if let Some((inner, _, _, _)) = cursor.any_group() {
            macros_in(inner, out);
        } else if cursor.ident().is_some()
            && let Some((bang, after)) = next.punct()
            && bang.as_char() == '!'
            && after.any_group().is_some()
            && let (Some((bang_tree, _)), Some((group, rest))) =
                (next.token_tree(), after.token_tree())
            && let Ok(mac) =
                syn::parse2::<syn::Macro>([tree, bang_tree, group].into_iter().collect())
        {
            out.push(mac);
            cursor = rest;
            continue;
        }
        cursor = next;
    }
}

impl Sink for Sites {
    fn file(&mut self, at: &Place, file: &syn::File) {
        let names = file_names(file);
        if in_scope(&Place {
            file: at.file.clone(),
            func: None,
        }) {
            self.helpers.extend(
                names
                    .helpers
                    .iter()
                    .map(|name| (at.file.clone(), name.clone())),
            );
        }
        if let Some(parent) = self.declaring.take() {
            self.parents.insert(at.file.clone(), parent);
        }
        self.names.insert(at.file.clone(), names);
    }

    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        if !in_scope(at) {
            return;
        }
        // The walk reports every nested expression itself, so only this
        // node is judged here; a macro's insides are visited by `mac`.
        match expr {
            syn::Expr::Macro(m) => self.mac(at, &m.mac),
            syn::Expr::MethodCall(call) => {
                self.write_call(at, &call.method.unraw().to_string(), &call.args);
            }
            syn::Expr::Call(call) => {
                if let syn::Expr::Path(p) = &*call.func
                    && let Some(last) = p.path.segments.last()
                {
                    self.write_call(at, &last.ident.unraw().to_string(), &call.args);
                }
            }
            syn::Expr::Binary(bin)
                if matches!(bin.op, syn::BinOp::AddAssign(_)) && !self.passes(at, &bin.right) =>
            {
                self.note(at, "+=", text(&bin.right));
            }
            _ => {}
        }
    }

    fn stmt(&mut self, at: &Place, stmt: &syn::Stmt) {
        if in_scope(at)
            && let syn::Stmt::Macro(m) = stmt
        {
            self.mac(at, &m.mac);
        }
    }

    fn item(&mut self, at: &Place, item: &syn::Item) {
        if in_scope(at)
            && let syn::Item::Macro(m) = item
        {
            // `macro_rules!` and any other item-position macro: reviewed,
            // and its body searched for output macros.
            self.note(at, "item macro", path_text(&m.mac.path));
            self.token_macros(at, &m.mac);
        }
        if let syn::Item::Mod(module) = item
            && module.content.is_none()
        {
            self.declaring = Some(at.file.clone());
        }
    }
}

/// The reviewed list: file, function, site, argument, count, class, reason.
const LISTED: &str = include_str!("discovery_output_sites.tsv");
const CLASSES: [&str; 6] = [
    "gateway-owned",
    "structured",
    "internal",
    "error-display",
    "macro-reviewed",
    "review",
];

/// The listed counts, and the rows that are malformed, repeat a key, or are
/// still `review`.
fn listed() -> (BTreeMap<Key, usize>, Vec<String>) {
    let mut counts = BTreeMap::new();
    let mut bad = Vec::new();
    for line in LISTED
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, func, site, arg, n, class, reason] = cols[..] else {
            bad.push(format!("not seven columns: {line}"));
            continue;
        };
        if !CLASSES.contains(&class) || reason.trim().is_empty() {
            bad.push(format!("no class or no reason: {line}"));
        }
        if class == "review" {
            bad.push(format!("still to review (route it through shown): {line}"));
        }
        let Ok(n) = n.parse::<usize>() else {
            bad.push(format!("count is not a number: {line}"));
            continue;
        };
        let key = (
            file.to_owned(),
            func.to_owned(),
            site.to_owned(),
            arg.to_owned(),
        );
        if counts.insert(key, n).is_some() {
            bad.push(format!("listed twice: {line}"));
        }
    }
    (counts, bad)
}

/// What differs between found and listed, as rows to add, fix or remove.
fn differences(found: &BTreeMap<Key, usize>, want: &BTreeMap<Key, usize>) -> Vec<String> {
    let mut wrong = Vec::new();
    for (key, n) in found {
        match want.get(key) {
            Some(m) if m == n => {}
            Some(m) => wrong.push(format!(
                "count {m} -> {n}: {}\t{}\t{}\t{}",
                key.0, key.1, key.2, key.3
            )),
            None => wrong.push(format!(
                "unlisted: {}\t{}\t{}\t{}\t{n}\t<class>\t<reason>",
                key.0, key.1, key.2, key.3
            )),
        }
    }
    for key in want.keys().filter(|k| !found.contains_key(*k)) {
        wrong.push(format!("stale: {}\t{}\t{}\t{}", key.0, key.1, key.2, key.3));
    }
    wrong
}

/// G1: every argument of every discovery output site is shown, a literal,
/// or a reviewed row; a new raw site, a changed count or a stale row fails
/// and prints the row to add, fix or remove.
#[test]
fn every_discovery_output_argument_is_shown_or_listed() {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    let (want, mut wrong) = listed();
    wrong.extend(differences(&sites.counts, &want));
    assert!(
        wrong.is_empty(),
        "discovery output sites differ from discovery_output_sites.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[cfg(test)]
#[path = "discovery_output_sites_fixtures.rs"]
mod fixtures;
