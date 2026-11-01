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

use std::collections::{BTreeMap, BTreeSet, HashSet};

use super::delivery_framing::is_refusal_name;
use super::scan::{Place, Sink};

/// The plain `crate::Error` variants a gateway decision returns as a refusal
/// without a `*refusal` function or a seal (lead ruling B).
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

/// Whether `word` occurs in `text` with no identifier character either side.
fn has_word(text: &str, word: &str) -> bool {
    let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    text.match_indices(word).any(|(at, _)| {
        !ident(text[..at].chars().next_back()) && !ident(text[at + word.len()..].chars().next())
    })
}

/// The monitored names a macro's tokens hold, for its `(in macro)` row: a
/// construction of one of the twelve, `delivery_facts`, `circuit_open` or a
/// helper's name.
pub(super) fn monitored_tokens(tokens: &str, helpers: &BTreeSet<String>) -> Vec<String> {
    let text = tokens.replace(" :: ", "::");
    let mut found: Vec<String> = TWELVE
        .iter()
        .map(|v| format!("Error::{v}"))
        .chain([FACTS.to_string(), "circuit_open".to_string()])
        .chain(helpers.iter().cloned())
        .filter(|word| has_word(&text, word))
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
            if let Some(syn::Stmt::Expr(syn::Expr::Call(call), None)) = block.stmts.last()
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

impl Collect {
    /// An import the recogniser cannot follow: the crate error renamed, one
    /// of the twelve (or a glob of the variants) imported, or a raise name,
    /// `delivery_facts` renamed or globbed. Helper renames are judged once
    /// helpers are known ([`Collect::renames`]).
    fn use_item(&mut self, at: &Place, item: &syn::ItemUse) {
        let mut leaves = Vec::new();
        use_leaves(&[], &item.tree, &mut leaves);
        for (path, rename) in leaves {
            let (Some(last), parent) = (path.last(), path.len().checked_sub(2).map(|i| &path[i]))
            else {
                continue;
            };
            let text = format!(
                "use {}{}",
                path.join("::"),
                rename
                    .as_ref()
                    .map(|r| format!(" as {r}"))
                    .unwrap_or_default()
            );
            let error_variant = parent.is_some_and(|p| p == "Error")
                && (last == "*" || TWELVE.contains(&last.as_str()));
            let error_renamed = rename.is_some() && crate_error(&path);
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
                self.aliases.push((at.file.clone(), text));
            } else if let Some(rename) = rename {
                self.renames.push((at.file.clone(), last.clone(), rename));
            }
        }
    }
}

impl Sink for Collect {
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
                    // `crate::Error` anywhere; a bare `Error` where it is the
                    // crate's (the gateway imports no other type by that name).
                    && (crate_error(&segments(&target.path))
                        || (target.path.segments.len() == 1 && at.file.starts_with("src/gateway/")))
                {
                    self.aliases
                        .push((at.file.clone(), format!("type {} = Error", alias.ident)));
                }
            }
            syn::Item::Macro(mac) => {
                let tokens = mac.mac.tokens.to_string();
                if mac.mac.path.is_ident("macro_rules") {
                    let name = mac
                        .ident
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default();
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
            syn::Expr::MethodCall(call) => self.push(
                at,
                Kind::Call {
                    owner: None,
                    name: call.method.to_string(),
                    value: false,
                    method: true,
                },
            ),
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

/// Effect writers that are not call needles: `step` scopes one composite
/// step and notes its outcome; the step's own raise is the row.
const NOT_A_NEEDLE: [&str; 1] = ["step"];

/// The tables and sets derived from one walk.
pub(super) struct Derived {
    /// `delivery_facts.rs` functions that write the effect, closed under
    /// calls between them.
    pub(super) effect_writers: BTreeSet<String>,
    /// `delivery_facts.rs` functions that store `LastStep::Refused`.
    pub(super) step_writers: BTreeSet<String>,
    /// Error-valued `src/gateway` functions that build one of the twelve,
    /// to a fixed point.
    pub(super) helpers: BTreeSet<String>,
    /// (file, fn, needle) -> count.
    pub(super) raises: BTreeMap<String, usize>,
    /// (file, fn, needle, ordinal), in walk order.
    pub(super) plain: Vec<String>,
}

fn fns_with(events: &[Event], file: &str, hit: impl Fn(&Kind) -> bool) -> BTreeSet<String> {
    events
        .iter()
        .filter(|e| e.file == file && hit(&e.kind))
        .map(|e| e.func.clone())
        .collect()
}

impl Collect {
    /// The effect writers (closed under calls in `delivery_facts.rs`) and
    /// the `LastStep::Refused` writers.
    fn writers(&self) -> (BTreeSet<String>, BTreeSet<String>) {
        let events = &self.events;
        let mut effect_writers =
            fns_with(events, FACTS_FILE, |k| *k == Kind::Writes("facts.effect ="));
        loop {
            let more = fns_with(
                events,
                FACTS_FILE,
                |k| matches!(k, Kind::Call { name, method: false, value: false, .. } if effect_writers.contains(name)),
            );
            let before = effect_writers.len();
            effect_writers.extend(more);
            if effect_writers.len() == before {
                break;
            }
        }
        let step_writers = fns_with(events, FACTS_FILE, |k| {
            *k == Kind::Writes("facts.last_step = Refused")
        });
        (effect_writers, step_writers)
    }

    /// Error-valued `src/gateway` functions that build one of the twelve or
    /// call such a function, to a fixed point.
    fn helper_set(&self) -> BTreeSet<String> {
        let events = &self.events;
        let valued: BTreeSet<&String> = self
            .error_valued
            .iter()
            .filter(|(file, _)| file.starts_with("src/gateway/"))
            .map(|(_, name)| name)
            .collect();
        let mut helpers = BTreeSet::new();
        loop {
            let builds = |k: &Kind| match k {
                Kind::Construct { .. } => true,
                Kind::Call { owner, name, .. } => {
                    helpers.contains(name)
                        || (owner.as_deref() == Some("Error")
                            && ASSOCIATED.contains(&name.as_str()))
                }
                _ => false,
            };
            let more: BTreeSet<String> = events
                .iter()
                .filter(|e| {
                    e.file.starts_with("src/gateway/")
                        && valued.contains(&e.func)
                        && builds(&e.kind)
                })
                .map(|e| e.func.clone())
                .collect();
            let before = helpers.len();
            helpers.extend(more);
            if helpers.len() == before {
                break;
            }
        }
        helpers
    }

    pub(super) fn derive(&self) -> Derived {
        let events = &self.events;
        let (effect_writers, step_writers) = self.writers();
        let needles: BTreeSet<&String> = effect_writers
            .iter()
            .chain(&step_writers)
            .filter(|n| !NOT_A_NEEDLE.contains(&n.as_str()))
            .collect();
        let helpers = self.helper_set();

        let mut raises = BTreeMap::new();
        let mut plain = Vec::new();
        let mut ordinals: BTreeMap<String, usize> = BTreeMap::new();
        for event in events {
            let key = format!("{}\t{}", event.file, event.func);
            let gateway = event.file.starts_with("src/gateway/");
            let mut plain_needle = None;
            match &event.kind {
                Kind::Writes(needle) => {
                    *raises.entry(format!("{key}\t{needle}")).or_insert(0) += 1;
                }
                Kind::Call {
                    owner,
                    name,
                    value,
                    method: false,
                } => {
                    // Inside delivery_facts.rs a bare name is a raise only when
                    // called: a local such as `refused` in `step` is not one.
                    let through = owner.as_deref() == Some(FACTS)
                        || (event.file == FACTS_FILE && owner.is_none() && !*value);
                    let suffix = if *value { " (as value)" } else { "" };
                    if through && needles.contains(name) {
                        *raises.entry(format!("{key}\t{name}{suffix}")).or_insert(0) += 1;
                    }
                    let associated =
                        owner.as_deref() == Some("Error") && ASSOCIATED.contains(&name.as_str());
                    // A helper with a refusal name is rowed by the refusal scan.
                    let helper = helpers.contains(name) && !is_refusal_name(name);
                    if gateway && (associated || helper) {
                        plain_needle = Some(format!("via {name}{suffix}"));
                    }
                }
                Kind::Call {
                    name, method: true, ..
                } => {
                    if gateway && helpers.contains(name) && !is_refusal_name(name) {
                        plain_needle = Some(format!("via {name}"));
                    }
                }
                Kind::Construct {
                    variant,
                    form,
                    wrapped,
                } => {
                    let shape = match *form {
                        "call" => format!("Error::{variant}(..)"),
                        "{}" => format!("Error::{variant}{{}}"),
                        _ => format!("Error::{variant} (as value)"),
                    };
                    let wrap = if *wrapped { " wrapped" } else { "" };
                    plain_needle = Some(format!("{shape}{wrap}"));
                }
                Kind::Closure(name) if gateway => {
                    plain_needle = Some(format!("via {name} (closure)"));
                }
                Kind::InMacro(tokens) => {
                    let names = monitored_tokens(tokens, &helpers);
                    if names.iter().any(|n| n == FACTS) {
                        *raises
                            .entry(format!("{key}\t{FACTS} (in macro)"))
                            .or_insert(0) += 1;
                    }
                    let plain_names: Vec<&str> = names
                        .iter()
                        .filter(|n| *n != FACTS)
                        .map(String::as_str)
                        .collect();
                    if gateway && !plain_names.is_empty() {
                        plain_needle = Some(format!("{} (in macro)", plain_names.join(",")));
                    }
                }
                _ => {}
            }
            if let Some(needle) = plain_needle {
                let row = format!("{key}\t{needle}");
                let n = ordinals.entry(row.clone()).or_insert(0);
                *n += 1;
                plain.push(format!("{row}\t{n}"));
            }
        }
        plain.sort();
        Derived {
            effect_writers,
            step_writers,
            helpers,
            raises,
            plain,
        }
    }

    /// Imports through `delivery_facts` that hide a raise: a glob, a renamed
    /// module, or a raise imported by name.
    pub(super) fn raise_imports(&self, derived: &Derived) -> Vec<String> {
        self.facts_uses
            .iter()
            .filter(|(_, key, _)| {
                key == "*"
                    || derived.effect_writers.contains(key)
                    || derived.step_writers.contains(key)
            })
            .map(|(_, _, text)| text.clone())
            .collect()
    }

    /// Imports that rename a discovered helper (`use x::helper as other`).
    pub(super) fn helper_renames(&self, helpers: &BTreeSet<String>) -> Vec<String> {
        self.renames
            .iter()
            .filter(|(_, from, _)| helpers.contains(from))
            .map(|(file, from, to)| format!("{file}: use {from} as {to}"))
            .collect()
    }
}
