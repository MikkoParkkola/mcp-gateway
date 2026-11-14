// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every delivery-record raise in `src/`, and every plain-error refusal built
//! in `src/gateway`, collected by one walk of the crate.
//!
//! A raise is a reference to a `delivery_facts` function that writes the
//! delivery's effect (or the composite's refused step), called or handed on
//! as a value. A plain-error refusal is a construction of one of [`TWELVE`]
//! (`Error::<V>` called, as a struct literal or as a function value), a call
//! of an error-valued helper that builds one, or a call of a local `refuse`
//! or `refusal` closure. The forms the recogniser cannot see (an alias or an
//! import of the error type, its variants or a helper; a pass-through raise
//! wrapper; a macro definition naming a monitored constructor) are rejected
//! by guards, so the tables stay complete over what can land.

use std::collections::{BTreeSet, HashSet};

use super::delivery_framing::call_args;
use super::scan::{Place, Sink};

/// The plain `crate::Error` variants a gateway decision returns as a refusal
/// without a `*refusal` function or a seal.
pub(super) const TWELVE: [&str; 12] = [
    "Config",
    "Protocol",
    "BackendUnavailable",
    "BackendNotFound",
    "ToolNotFound",
    "AmbiguousBackend",
    "IdentitySlotsExhausted",
    "CircuitOpen",
    "CliCredentialRefused",
    "RateLimited",
    "ProtocolVersionRejected",
    "AuthorizationRequired",
];

/// The `delivery_facts` module, by its last path segment.
pub(super) const FACTS: &str = "delivery_facts";

/// The file whose functions are the raise set.
pub(super) const FACTS_FILE: &str = "src/gateway/delivery_facts.rs";

/// One thing a function does that the tables record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// `Error::<V>`: `call`, `{}` (struct literal) or `as value`; `wrapped`
    /// when it sits inside a raise call's argument.
    Construct {
        variant: String,
        form: &'static str,
        wrapped: bool,
    },
    /// A call (or a value use) of a function by its last segment, with the
    /// segment before it if any; a method call has no owner.
    Call {
        owner: Option<String>,
        name: String,
        value: bool,
        method: bool,
        /// A value handed to a combinator (`.map_err(f)`), the form the
        /// refusal scan in `delivery_framing.rs` reads.
        combinator: bool,
        /// The full path's segments before the name (empty for a method or
        /// a bare name), for resolving `super::`, `self::` and `crate::`.
        prefix: Vec<String>,
    },
    /// A call of a local closure bound to `refuse` or `refusal`.
    Closure(String),
    /// Monitored tokens inside a macro invocation.
    InMacro(String),
    /// In `delivery_facts.rs`: an assignment to `facts.effect`, or a store
    /// of `LastStep::Refused` into `facts.last_step`.
    Writes(&'static str),
}

/// A recorded thing, where it sits.
#[derive(Clone, Debug)]
pub(super) struct Event {
    pub(super) file: String,
    pub(super) func: String,
    pub(super) kind: Kind,
}

/// What the walk collects; the tables are derived from it afterwards, since
/// helpers and raises are only known once every function has been seen.
#[derive(Default)]
pub(super) struct Collect {
    pub(super) events: Vec<Event>,
    /// Functions returning an error value (`Error`, `Option<Error>`), by name.
    pub(super) error_valued: BTreeSet<(String, String)>,
    /// Functions outside `delivery_facts.rs` returning `()`: (file, name).
    /// One that raises is a raise helper ([`Collect::raise_helpers`]).
    unit_fns: BTreeSet<(String, String)>,
    /// Functions with a receiver (`&self`): (file, name). A method call
    /// resolves only to one of these.
    methods: BTreeSet<(String, String)>,
    /// Every import leaf: (file, path segments).
    uses: Vec<(String, Vec<String>)>,
    /// Imports and aliases the recogniser cannot follow: (file, item text).
    pub(super) aliases: Vec<(String, String)>,
    /// `macro_rules!` definitions: (file, macro name, body tokens).
    pub(super) macro_defs: Vec<(String, String, String)>,
    /// Functions outside `delivery_facts.rs` that hand a parameter to a raise.
    pub(super) wrappers: Vec<(String, String)>,
    /// `impl` blocks for a type named `Error` under `src/gateway`.
    pub(super) error_impls: Vec<String>,
    /// Imports renamed with `as`: (file, original name, new name); one that
    /// renames a helper is rejected once helpers are known.
    pub(super) renames: Vec<(String, String, String)>,
    /// Imports through `delivery_facts` (or renaming it): (file, the name
    /// imported, or `*` for a glob or a renamed module, item text).
    pub(super) facts_uses: Vec<(String, String, String)>,
    /// Expressions inside a raise call's argument (by address, this walk).
    wrapped: HashSet<usize>,
    /// Paths that are a call's function (by address, this walk).
    callees: HashSet<usize>,
    /// Arguments of a combinator call (by address, this walk).
    combinator_args: HashSet<usize>,
}

fn addr(expr: &syn::Expr) -> usize {
    std::ptr::from_ref(expr) as usize
}

fn segments(path: &syn::Path) -> Vec<String> {
    path.segments.iter().map(|s| s.ident.to_string()).collect()
}

/// `Error::<V>` for one of the twelve, by the last two segments.
fn twelve_variant(path: &syn::Path) -> Option<String> {
    let segments = segments(path);
    let [.., owner, variant] = segments.as_slice() else {
        return None;
    };
    (owner == "Error" && TWELVE.contains(&variant.as_str())).then(|| variant.clone())
}

/// Whether a type is an error value: `Error` or `Option<Error>`, any path.
fn error_valued(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    let Some(last) = path.path.segments.last() else {
        return false;
    };
    if last.ident == "Error" {
        return true;
    }
    if last.ident != "Option" {
        return false;
    }
    let syn::PathArguments::AngleBracketed(args) = &last.arguments else {
        return false;
    };
    args.args
        .iter()
        .any(|arg| matches!(arg, syn::GenericArgument::Type(inner) if error_valued(inner)))
}

fn returns_error(sig: &syn::Signature) -> bool {
    matches!(&sig.output, syn::ReturnType::Type(_, ty) if error_valued(ty))
}

/// Whether `path` reaches through `delivery_facts` (a raise reference),
/// or is a bare call inside `delivery_facts.rs` itself.
fn facts_path(file: &str, path: &syn::Path) -> Option<String> {
    let segments = segments(path);
    let last = segments.last()?.clone();
    let through = segments.iter().rev().skip(1).any(|s| s == FACTS);
    (through || (file == FACTS_FILE && segments.len() == 1)).then_some(last)
}

/// Whether `expr` names `LastStep::Refused` anywhere (an if-expression too).
fn stores_refused(expr: &syn::Expr) -> bool {
    struct Find(bool);
    impl<'ast> syn::visit::Visit<'ast> for Find {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            let s = segments(path);
            self.0 |= s.ends_with(&["LastStep".to_string(), "Refused".to_string()]);
        }
    }
    let mut find = Find(false);
    syn::visit::Visit::visit_expr(&mut find, expr);
    find.0
}

/// Every expression under `expr` (itself included), by address.
fn all_exprs(expr: &syn::Expr, into: &mut HashSet<usize>) {
    struct Gather<'a>(&'a mut HashSet<usize>);
    impl<'ast> syn::visit::Visit<'ast> for Gather<'_> {
        fn visit_expr(&mut self, expr: &'ast syn::Expr) {
            self.0.insert(addr(expr));
            syn::visit::visit_expr(self, expr);
        }
    }
    syn::visit::Visit::visit_expr(&mut Gather(into), expr);
}

/// Where `word` occurs in `text` as a whole token: no identifier character
/// either side. The one word boundary the macro and caller rows share.
pub(super) fn whole_words<'t>(text: &'t str, word: &'t str) -> impl Iterator<Item = usize> + 't {
    let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    text.match_indices(word)
        .map(|(at, _)| at)
        .filter(move |at| {
            !ident(text[..*at].chars().next_back())
                && !ident(text[at + word.len()..].chars().next())
        })
}

/// How often `word` occurs in `text` as a whole token.
fn word_count(text: &str, word: &str) -> usize {
    whole_words(text, word).count()
}

/// Whether a raise-table needle is a caller row of the helper `name`, naming
/// it as a whole token: a `via {name}` row, or a macro row listing it
/// (`{name} (in macro)`, `{name}*{n} (in macro)`).
pub(super) fn names_caller(needle: &str, name: &str) -> bool {
    let via = needle
        .strip_prefix("via ")
        .is_some_and(|rest| whole_words(rest, name).any(|at| at == 0));
    let in_macro = needle.strip_suffix(" (in macro)").is_some_and(|list| {
        list.split(',')
            .any(|item| item.split('*').next() == Some(name))
    });
    via || in_macro
}

/// The monitored names a macro's tokens hold, for its `(in macro)` row: a
/// construction of one of the twelve, `delivery_facts`, `circuit_open` or a
/// helper's name, each with its count when above one (`Error::Config*2`), so
/// a second construction inside an existing invocation changes the row.
pub(super) fn monitored_tokens(tokens: &str, helpers: &BTreeSet<String>) -> Vec<String> {
    let text = tokens.replace(" :: ", "::");
    let mut found: Vec<String> = TWELVE
        .iter()
        .map(|v| format!("Error::{v}"))
        .chain([FACTS.to_string(), "circuit_open".to_string()])
        .chain(helpers.iter().cloned())
        .filter_map(|word| match word_count(&text, &word) {
            0 => None,
            1 => Some(word),
            n => Some(format!("{word}*{n}")),
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

impl Collect {
    fn push(&mut self, at: &Place, kind: Kind) {
        self.events.push(Event {
            file: at.file.clone(),
            func: at.func.clone().unwrap_or_else(|| "<module>".to_string()),
            kind,
        });
    }

    fn fn_sig(&mut self, at: &Place, sig: &syn::Signature, block: &syn::Block) {
        if returns_error(sig) {
            self.error_valued
                .insert((at.file.clone(), sig.ident.to_string()));
        }
        if sig.receiver().is_some() {
            self.methods
                .insert((at.file.clone(), sig.ident.to_string()));
        }
        if matches!(sig.output, syn::ReturnType::Default)
            && at.file != FACTS_FILE
            && at.file.starts_with("src/")
        {
            self.unit_fns
                .insert((at.file.clone(), sig.ident.to_string()));
        }
        // A pass-through raise wrapper: a parameter handed straight to a
        // raise. Its callers would raise unseen, so it is rejected.
        if at.file != FACTS_FILE && at.file.starts_with("src/") {
            let params: BTreeSet<String> = sig
                .inputs
                .iter()
                .filter_map(|input| match input {
                    syn::FnArg::Typed(typed) => match &*typed.pat {
                        syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
                        _ => None,
                    },
                    syn::FnArg::Receiver(_) => None,
                })
                .collect();
            // The body's last statement, as a tail expression, `return x;` or
            // `x;`: each hands the raise's result (or nothing) back.
            let tail = match block.stmts.last() {
                Some(syn::Stmt::Expr(syn::Expr::Return(ret), _)) => ret.expr.as_deref(),
                Some(syn::Stmt::Expr(expr, _)) => Some(expr),
                _ => None,
            };
            if let Some(syn::Expr::Call(call)) = tail
                && let syn::Expr::Path(func) = &*call.func
                && facts_path(&at.file, &func.path).is_some()
                && call.args.iter().any(|arg| {
                    matches!(arg, syn::Expr::Path(p) if p.path.get_ident().is_some_and(|i| params.contains(&i.to_string())))
                })
            {
                self.wrappers
                    .push((at.file.clone(), sig.ident.to_string()));
            }
        }
    }
}

/// The use-tree leaves an import brings in: (path segments, renamed to).
fn use_leaves(
    prefix: &[String],
    tree: &syn::UseTree,
    into: &mut Vec<(Vec<String>, Option<String>)>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut next = prefix.to_vec();
            next.push(path.ident.to_string());
            use_leaves(&next, &path.tree, into);
        }
        syn::UseTree::Name(name) => {
            let mut full = prefix.to_vec();
            full.push(name.ident.to_string());
            into.push((full, None));
        }
        syn::UseTree::Rename(rename) => {
            let mut full = prefix.to_vec();
            full.push(rename.ident.to_string());
            into.push((full, Some(rename.rename.to_string())));
        }
        syn::UseTree::Glob(_) => {
            let mut full = prefix.to_vec();
            full.push("*".to_string());
            into.push((full, None));
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                use_leaves(prefix, item, into);
            }
        }
    }
}

/// Whether `segments` name the crate's error type: `crate::Error` or
/// `crate::error::Error`.
fn crate_error(segments: &[String]) -> bool {
    matches!(
        segments
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
        ["crate", "Error"] | ["crate", "error", "Error"]
    )
}

/// An alias item's text with the function it sits in, if any: a reviewed
/// function-local alias stays allowed only while it stays there.
fn scoped(at: &Place, text: String) -> String {
    match &at.func {
        Some(func) => format!("{text} (in fn {func})"),
        None => text,
    }
}

/// Whether `segments` reach an `Error` through `crate`, `super` or `self`:
/// the crate's own error type, as the gateway names it.
fn local_error(segments: &[String]) -> bool {
    segments.last().is_some_and(|s| s == "Error")
        && segments
            .first()
            .is_some_and(|s| matches!(s.as_str(), "crate" | "super" | "self"))
}

impl Collect {
    /// An import the recogniser cannot follow: the crate error renamed, one
    /// of the twelve (or a glob of the variants) imported, or a raise name,
    /// `delivery_facts` renamed or globbed. Helper renames are judged once
    /// helpers are known ([`Collect::renames`]).
    fn use_item(&mut self, at: &Place, item: &syn::ItemUse) {
        let gateway = at.file.starts_with("src/gateway/");
        let mut leaves = Vec::new();
        use_leaves(&[], &item.tree, &mut leaves);
        for (path, rename) in leaves {
            self.uses.push((at.file.clone(), path.clone()));
            let (Some(last), parent) = (path.last(), path.len().checked_sub(2).map(|i| &path[i]))
            else {
                continue;
            };
            let text = format!(
                "use {}{}",
                path.join("::"),
                rename.as_ref().map_or_default(|r| format!(" as {r}"))
            );
            let error_variant = parent.is_some_and(|p| p == "Error")
                && (last == "*" || TWELVE.contains(&last.as_str()));
            // The crate's error renamed: by its crate path anywhere, and under
            // the gateway also by a relative path (`super::Error as E`).
            let error_renamed =
                rename.is_some() && (crate_error(&path) || (gateway && local_error(&path)));
            let through_facts = path.iter().rev().skip(1).any(|s| s == FACTS);
            let facts_renamed = last == FACTS && rename.is_some();
            if through_facts || facts_renamed {
                // A glob or a renamed module always hides raises; a named
                // import does only when it names a raise ([`Collect::raise_imports`]).
                let key = if last == "*" || facts_renamed {
                    "*".to_string()
                } else {
                    last.clone()
                };
                self.facts_uses.push((at.file.clone(), key, text));
            } else if error_variant || error_renamed {
                self.aliases.push((at.file.clone(), scoped(at, text)));
            } else if let Some(rename) = rename {
                self.renames.push((at.file.clone(), last.clone(), rename));
            }
        }
    }
}

impl Sink for Collect {
    // The address sets name nodes of one parsed file; a later file's nodes
    // can reuse a freed file's addresses, so each file starts empty.
    fn file(&mut self, _at: &Place, _file: &syn::File) {
        self.wrapped.clear();
        self.callees.clear();
        self.combinator_args.clear();
    }

    fn item(&mut self, at: &Place, item: &syn::Item) {
        if !at.file.starts_with("src/") {
            return;
        }
        match item {
            syn::Item::Fn(func) => self.fn_sig(at, &func.sig, &func.block),
            syn::Item::Impl(block) => {
                let gateway = at.file.starts_with("src/gateway/");
                if gateway
                    && block.trait_.is_none()
                    && matches!(&*block.self_ty, syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Error"))
                {
                    self.error_impls.push(at.file.clone());
                }
                for inner in &block.items {
                    match inner {
                        syn::ImplItem::Fn(func) => self.fn_sig(at, &func.sig, &func.block),
                        syn::ImplItem::Macro(mac) => {
                            let tokens = mac.mac.tokens.to_string();
                            self.push(at, Kind::InMacro(tokens));
                        }
                        _ => {}
                    }
                }
            }
            syn::Item::Use(item) => self.use_item(at, item),
            syn::Item::Type(alias) => {
                if let syn::Type::Path(target) = &*alias.ty
                    && target.path.segments.last().is_some_and(|s| s.ident == "Error")
                    // `crate::Error` anywhere; under the gateway also a bare or
                    // relative `Error` (the gateway imports no other type by
                    // that name).
                    && (crate_error(&segments(&target.path))
                        || (at.file.starts_with("src/gateway/")
                            && (target.path.segments.len() == 1
                                || local_error(&segments(&target.path)))))
                {
                    self.aliases.push((
                        at.file.clone(),
                        scoped(at, format!("type {} = Error", alias.ident)),
                    ));
                }
            }
            syn::Item::Macro(mac) => {
                let tokens = mac.mac.tokens.to_string();
                if mac.mac.path.is_ident("macro_rules") {
                    let name = mac.ident.as_ref().map_or_default(ToString::to_string);
                    self.macro_defs.push((at.file.clone(), name, tokens));
                } else {
                    self.push(at, Kind::InMacro(tokens));
                }
            }
            _ => {}
        }
    }

    fn stmt(&mut self, at: &Place, stmt: &syn::Stmt) {
        if let syn::Stmt::Macro(mac) = stmt {
            self.push(at, Kind::InMacro(mac.mac.tokens.to_string()));
        }
    }

    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        if !at.file.starts_with("src/") {
            return;
        }
        let gateway = at.file.starts_with("src/gateway/");
        match expr {
            syn::Expr::Macro(mac) => self.push(at, Kind::InMacro(mac.mac.tokens.to_string())),
            syn::Expr::Call(call) => {
                if let syn::Expr::Path(func) = &*call.func {
                    self.callees.insert(addr(&call.func));
                    // A raise call: what its argument builds is `wrapped`.
                    if facts_path(&at.file, &func.path).is_some() {
                        for arg in &call.args {
                            all_exprs(arg, &mut self.wrapped);
                        }
                    }
                }
            }
            syn::Expr::MethodCall(call) => {
                for arg in call_args(expr) {
                    self.combinator_args.insert(addr(arg));
                }
                self.push(
                    at,
                    Kind::Call {
                        owner: None,
                        name: call.method.to_string(),
                        value: false,
                        method: true,
                        combinator: false,
                        prefix: Vec::new(),
                    },
                );
            }
            syn::Expr::Struct(literal) if gateway => {
                if let Some(variant) = twelve_variant(&literal.path) {
                    let wrapped = self.wrapped.contains(&addr(expr));
                    self.push(
                        at,
                        Kind::Construct {
                            variant,
                            form: "{}",
                            wrapped,
                        },
                    );
                }
            }
            syn::Expr::Path(path) => {
                let value = !self.callees.contains(&addr(expr));
                if gateway && let Some(variant) = twelve_variant(&path.path) {
                    let wrapped = self.wrapped.contains(&addr(expr));
                    let form = if value { "as value" } else { "call" };
                    self.push(
                        at,
                        Kind::Construct {
                            variant,
                            form,
                            wrapped,
                        },
                    );
                    return;
                }
                let segments = segments(&path.path);
                if let Some(name) = segments.last() {
                    let owner = segments.len().checked_sub(2).map(|i| segments[i].clone());
                    // `refusal` is a refusal name: the refusal scan rows it already.
                    if !value && segments.len() == 1 && name == "refuse" {
                        self.push(at, Kind::Closure(name.clone()));
                        return;
                    }
                    self.push(
                        at,
                        Kind::Call {
                            owner,
                            name: name.clone(),
                            value,
                            method: false,
                            combinator: value && self.combinator_args.contains(&addr(expr)),
                            prefix: segments[..segments.len() - 1].to_vec(),
                        },
                    );
                }
            }
            syn::Expr::Assign(assign) if at.file == FACTS_FILE => {
                if let syn::Expr::Field(field) = &*assign.left {
                    let member = match &field.member {
                        syn::Member::Named(ident) => ident.to_string(),
                        syn::Member::Unnamed(_) => String::new(),
                    };
                    if member == "effect" {
                        self.push(at, Kind::Writes("facts.effect ="));
                    } else if member == "last_step" && stores_refused(&assign.right) {
                        self.push(at, Kind::Writes("facts.last_step = Refused"));
                    }
                }
            }
            _ => {}
        }
    }
}

/// The `impl Error` constructors that build one of the twelve; a call of one
/// from `src/gateway` is a `via` row. Pinned against src/error.rs.
pub(super) const ASSOCIATED: [&str; 1] = ["circuit_open"];

mod derive;

pub(super) use derive::Derived;
