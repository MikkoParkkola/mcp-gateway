// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ISO-T5: the two source rules per-subscriber isolation rests on.
//!
//! - **Keys.** Every backend notification a listener path emits takes its
//!   `lifecycle_key` from `key_of` or `backend_key`, the functions that put a
//!   per-user listener's observation key into it. A literal `None`, a
//!   `backend_key(None, ..)` outside the gateway's own shared view, or a key
//!   from anywhere else, would let fan-out treat a per-user occurrence as the
//!   backend's shared one.
//! - **Credential.** In the listener transports, a request is sent only inside
//!   a `send` helper, and each such helper goes through `with_credential`, so
//!   no listener request leaves without the subscriber's credential seam.
//!
//! The rules read the parsed source (`syn`), so layout, field order and line
//! breaks cannot hide an emit or a send. Both count what they find, so a scan
//! that matches nothing fails, and each is shown failing on a fixture that
//! breaks it. Both fail closed on files: an emit, or a transport that takes
//! the credential seam, outside the scanned files fails. A file that does not
//! parse fails. Stated limit: a `send` helper is judged by reaching
//! `with_credential`, not by the shape of its branches.

use std::path::Path;

use syn::visit::Visit;

/// Files whose backend notifications are emitted by a listener path, relative
/// to `src/events`.
const EMIT_FILES: &[&str] = &["upstream_session_notes.rs", "backend_source.rs"];
/// Backend-notification emits those files hold today.
const EMITS: usize = 3;
/// The one file that also emits the gateway's own shared view, keyed with no
/// observation (`backend_key(None, ..)`); a listener path never may.
const SHARED_VIEW_FILE: &str = "backend_source.rs";
/// The listener transports a per-user listener runs on, relative to
/// `src/transport`.
const SEND_FILES: &[&str] = &[
    "http/listen.rs",
    "http/sse_listen.rs",
    "http/streamable_listen.rs",
];
/// `send` helpers those files hold today.
const SEND_HELPERS: usize = 2;
/// The listener seam's types: a transport naming one is a listener transport.
const SEAM: &[&str] = &["CredentialSource", "ListenerCredential", "UpstreamListen"];
/// Listener-side transport files the credential rule does not scan, and why.
const NOT_PER_USER: &[(&str, &str)] = &[
    ("upstream_tap.rs", "defines CredentialSource; sends nothing"),
    (
        "stdio_listen.rs",
        "identity_propagation requires an http transport (src/config/validation.rs)",
    ),
    (
        "websocket_listen.rs",
        "identity_propagation requires an http transport (src/config/validation.rs)",
    ),
];

/// Test-only: `#[cfg(test)]` or `#[cfg(all(test, ..))]`. Anything else, as
/// `any(test, unix)` or `not(test)`, also builds outside tests and is scanned.
fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    fn test_only(meta: &syn::Meta) -> bool {
        match meta {
            syn::Meta::Path(path) => path.is_ident("test"),
            syn::Meta::List(list) if list.path.is_ident("all") => list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|all| all.iter().any(test_only)),
            _ => false,
        }
    }
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg") && attr.parse_args::<syn::Meta>().is_ok_and(|m| test_only(&m))
    })
}

/// A macro body's tokens with the whitespace `to_string` puts between them
/// removed, so `request . send ()` reads `request.send()`.
fn macro_text(mac: &syn::Macro) -> String {
    mac.tokens.to_string().split_whitespace().collect()
}

fn last_ident(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

fn parse(file: &str, text: &str) -> syn::File {
    syn::parse_file(text).unwrap_or_else(|e| panic!("parse {file}: {e}"))
}

fn field<'a>(s: &'a syn::ExprStruct, name: &str) -> Option<&'a syn::Expr> {
    s.fields.iter().find_map(|f| match &f.member {
        syn::Member::Named(ident) if ident == name => Some(&f.expr),
        _ => None,
    })
}

/// What a name is known to hold, judged where it is bound against the names
/// visible there.
struct Binding {
    name: String,
    /// Why it is not a listener's key, or `None` when it is one.
    verdict: Option<String>,
    /// It holds `None`: as the observation, the gateway's own.
    none: bool,
}

/// The key rule over one file: emits counted, breaches named.
struct Emits<'f> {
    file: &'f str,
    count: usize,
    bad: Vec<String>,
    /// Names bound so far in the current fn and its open blocks, newest last.
    bindings: Vec<Binding>,
}

impl Emits<'_> {
    fn binding(&self, expr: &syn::Expr) -> Option<&Binding> {
        let syn::Expr::Path(p) = expr else {
            return None;
        };
        let name = p.path.get_ident()?.to_string();
        self.bindings.iter().rev().find(|b| b.name == name)
    }

    /// Whether `expr` is `None`, directly or through a name bound to it.
    fn is_none(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Paren(e) => self.is_none(&e.expr),
            syn::Expr::Group(e) => self.is_none(&e.expr),
            syn::Expr::Path(p) if last_ident(&p.path) == "None" => true,
            other => self.binding(other).is_some_and(|b| b.none),
        }
    }

    /// Why a key expression breaks the rule, if it does.
    fn judge_key(&self, expr: &syn::Expr) -> Option<String> {
        const ELSEWHERE: &str = "is not from key_of or backend_key";
        match expr {
            syn::Expr::Paren(e) => self.judge_key(&e.expr),
            syn::Expr::Group(e) => self.judge_key(&e.expr),
            syn::Expr::MethodCall(m) if m.method == "key_of" => None,
            syn::Expr::Call(c) => match &*c.func {
                syn::Expr::Path(p) if last_ident(&p.path) == "backend_key" => {
                    let gateway = c.args.first().is_some_and(|obs| self.is_none(obs));
                    (gateway && self.file != SHARED_VIEW_FILE)
                        .then(|| "is keyed as the gateway (backend_key(None, ..))".to_owned())
                }
                _ => Some(ELSEWHERE.to_owned()),
            },
            syn::Expr::Path(p) => match self.binding(expr) {
                Some(bound) => bound.verdict.clone(),
                None if p.path.get_ident().is_some() => {
                    Some(format!("{} is not bound in this fn", last_ident(&p.path)))
                }
                None => Some(ELSEWHERE.to_owned()),
            },
            _ => Some(ELSEWHERE.to_owned()),
        }
    }

    fn in_fn(&mut self, visit: impl FnOnce(&mut Self)) {
        let outer = std::mem::take(&mut self.bindings);
        visit(self);
        self.bindings = outer;
    }
}

impl<'ast> Visit<'ast> for Emits<'_> {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !is_cfg_test(&m.attrs) {
            syn::visit::visit_item_mod(self, m);
        }
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if !is_cfg_test(&f.attrs) {
            self.in_fn(|me| syn::visit::visit_item_fn(me, f));
        }
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if !is_cfg_test(&f.attrs) {
            self.in_fn(|me| syn::visit::visit_impl_item_fn(me, f));
        }
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        // A binding ends with its block.
        let outer = self.bindings.len();
        syn::visit::visit_block(self, block);
        self.bindings.truncate(outer);
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        if !is_cfg_test(&i.attrs) {
            syn::visit::visit_item_impl(self, i);
        }
    }

    /// A name bound by a pattern (a match arm, a closure or loop variable, a
    /// destructuring `let`) holds what the scan cannot judge.
    fn visit_pat_ident(&mut self, p: &'ast syn::PatIdent) {
        self.bindings.push(Binding {
            name: p.ident.to_string(),
            verdict: Some(format!(
                "{} is bound by a pattern, not from key_of or backend_key",
                p.ident
            )),
            none: false,
        });
        syn::visit::visit_pat_ident(self, p);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        // A closure's parameters end with it.
        let outer = self.bindings.len();
        syn::visit::visit_expr_closure(self, closure);
        self.bindings.truncate(outer);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        let pat = match &local.pat {
            syn::Pat::Type(t) => &*t.pat,
            other => other,
        };
        // Judged against the names visible before this `let`.
        let simple = match (pat, &local.init) {
            (syn::Pat::Ident(p), Some(init)) => Some((
                p.ident.to_string(),
                self.judge_key(&init.expr),
                self.is_none(&init.expr),
            )),
            _ => None,
        };
        syn::visit::visit_local(self, local);
        if let Some((name, verdict, none)) = simple {
            self.bindings.push(Binding {
                name,
                verdict,
                none,
            });
        }
    }

    /// `key = ..` re-judges every binding of that name, in an outer block too.
    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        syn::visit::visit_expr_assign(self, assign);
        if let syn::Expr::Path(p) = &*assign.left
            && let Some(name) = p.path.get_ident().map(ToString::to_string)
        {
            let (verdict, none) = (self.judge_key(&assign.right), self.is_none(&assign.right));
            for bound in self.bindings.iter_mut().filter(|b| b.name == name) {
                bound.verdict.clone_from(&verdict);
                bound.none = none;
            }
        }
    }

    /// A macro body is not parsed: one that names the kind fails.
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if macro_text(mac).contains("BackendNotification") {
            self.bad.push(format!(
                "{}: a macro body names BackendNotification; the scan cannot read it",
                self.file
            ));
        }
    }

    fn visit_expr_struct(&mut self, s: &'ast syn::ExprStruct) {
        // The kind as a `SourceKind::Variant` path; anything else (a variable,
        // a shorthand field, a `..base` update) is not a kind the scan can read.
        let variant = match field(s, "kind") {
            Some(syn::Expr::Path(p))
                if p.path.segments.len() >= 2
                    && p.path.segments[p.path.segments.len() - 2].ident == "SourceKind" =>
            {
                Some(last_ident(&p.path))
            }
            _ => None,
        };
        match (last_ident(&s.path).as_str(), variant.as_deref()) {
            (_, Some(other)) if other != "BackendNotification" => {}
            ("SourceEvent", Some(_)) => {
                self.count += 1;
                let place = format!("{}: emit {}", self.file, self.count);
                match field(s, "lifecycle_key") {
                    None => self.bad.push(format!("{place}: no lifecycle_key")),
                    Some(key) => {
                        if let Some(why) = self.judge_key(key) {
                            self.bad.push(format!("{place}: lifecycle_key {why}"));
                        }
                    }
                }
            }
            ("SourceEvent", None) => self.bad.push(format!(
                "{}: a SourceEvent whose kind is not a SourceKind path cannot be judged",
                self.file
            )),
            ("EventDescriptor", _) | (_, None) => {}
            (other, Some(_)) => self.bad.push(format!(
                "{}: a {other} of kind BackendNotification is neither an emit nor a descriptor",
                self.file
            )),
        }
        syn::visit::visit_expr_struct(self, s);
    }
}

/// Every breach of the key rule in `text`, and how many emits there were.
fn bad_emits(file: &str, text: &str) -> (Vec<String>, usize) {
    let mut emits = Emits {
        file,
        count: 0,
        bad: Vec::new(),
        bindings: Vec::new(),
    };
    emits.visit_file(&parse(file, text));
    (emits.bad, emits.count)
}

/// The credential rule over one file: `send` helpers counted, breaches named.
struct Sends<'f> {
    file: &'f str,
    helpers: usize,
    bad: Vec<String>,
    /// Per enclosing fn: whether it is a `send` helper, and whether it has
    /// reached `with_credential`.
    frames: Vec<(bool, bool)>,
}

impl Sends<'_> {
    fn in_fn(&mut self, name: &syn::Ident, visit: impl FnOnce(&mut Self)) {
        let helper = name == "send";
        self.helpers += usize::from(helper);
        self.frames.push((helper, false));
        visit(self);
        if let Some((true, false)) = self.frames.pop() {
            self.bad.push(format!(
                "{}: send helper never reaches with_credential",
                self.file
            ));
        }
    }
}

impl<'ast> Visit<'ast> for Sends<'_> {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !is_cfg_test(&m.attrs) {
            syn::visit::visit_item_mod(self, m);
        }
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if !is_cfg_test(&f.attrs) {
            self.in_fn(&f.sig.ident, |me| syn::visit::visit_item_fn(me, f));
        }
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if !is_cfg_test(&f.attrs) {
            self.in_fn(&f.sig.ident, |me| syn::visit::visit_impl_item_fn(me, f));
        }
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        if !is_cfg_test(&i.attrs) {
            syn::visit::visit_item_impl(self, i);
        }
    }

    /// A macro body is not parsed: a request sent in one, outside the
    /// helper, fails.
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let in_helper = self.frames.last().is_some_and(|(helper, _)| *helper);
        if macro_text(mac).contains(".send()") && !in_helper {
            self.bad.push(format!(
                "{}: request sent in a macro body outside a send helper",
                self.file
            ));
        }
    }

    /// `RequestBuilder::send(request)`, the call written as a path.
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let in_helper = self.frames.last().is_some_and(|(helper, _)| *helper);
        if let syn::Expr::Path(p) = &*call.func
            && p.path.segments.len() >= 2
            && last_ident(&p.path) == "send"
            && call.args.len() == 1
            && !in_helper
        {
            self.bad
                .push(format!("{}: request sent outside a send helper", self.file));
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "with_credential"
            && let Some(frame) = self.frames.last_mut()
        {
            frame.1 = true;
        }
        let in_helper = self.frames.last().is_some_and(|(helper, _)| *helper);
        if call.method == "send" && call.args.is_empty() && !in_helper {
            self.bad
                .push(format!("{}: request sent outside a send helper", self.file));
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// Every breach of the credential rule in `text`, and how many helpers there
/// were.
fn bad_sends(file: &str, text: &str) -> (Vec<String>, usize) {
    let mut sends = Sends {
        file,
        helpers: 0,
        bad: Vec::new(),
        frames: Vec::new(),
    };
    sends.visit_file(&parse(file, text));
    (sends.bad, sends.helpers)
}

fn read(dir: &str, file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir).join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The product `.rs` files under `dir`, at any depth, relative to it (test
/// files and `tests` directories excluded).
fn product_files(dir: &str) -> Vec<String> {
    fn walk(root: &Path, rel: &Path, out: &mut Vec<String>) {
        let here = root.join(rel);
        let entries =
            std::fs::read_dir(&here).unwrap_or_else(|e| panic!("list {}: {e}", here.display()));
        for entry in entries {
            let entry = entry.expect("dir entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = rel.join(&name);
            if entry.file_type().expect("file type").is_dir() {
                if name != "tests" {
                    walk(root, &path, out);
                }
            } else if std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                && !name.ends_with("_tests.rs")
            {
                // `/` on every platform: callers match `events/` prefixes.
                out.push(path.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join(dir),
        Path::new(""),
        &mut files,
    );
    files.sort();
    files
}

/// Whether product code (not a comment) in `text` names `word`.
fn names_in_code(text: &str, word: &str) -> bool {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .any(|line| line.contains(word))
}

/// Fail closed on files: no backend-notification emit outside the emit files,
/// and no transport taking the credential seam outside the scanned or
/// classified files.
#[test]
fn iso_t5_no_listener_emit_or_transport_escapes_the_scan() {
    // Anywhere in the crate: only a file building a `SourceEvent` can emit
    // one, and only those are parsed.
    let unscanned: Vec<String> = product_files("src")
        .into_iter()
        .filter(|file| {
            file.strip_prefix("events/")
                .is_none_or(|rest| !EMIT_FILES.contains(&rest))
        })
        .filter(|file| {
            let text = read("src", file);
            names_in_code(&text, "SourceEvent") && {
                let (bad, emits) = bad_emits(file, &text);
                emits > 0 || !bad.is_empty()
            }
        })
        .collect();
    assert!(
        unscanned.is_empty(),
        "emits outside EMIT_FILES: {unscanned:?}"
    );
    let listeners: Vec<String> = product_files("src/transport")
        .into_iter()
        .filter(|file| {
            let text = read("src/transport", file);
            file.contains("listen") || SEAM.iter().any(|name| names_in_code(&text, name))
        })
        .collect();
    let mut known: Vec<String> = SEND_FILES
        .iter()
        .chain(NOT_PER_USER.iter().map(|(file, _)| file))
        .map(|f| (*f).to_owned())
        .collect();
    known.sort();
    assert_eq!(
        listeners, known,
        "a listener transport is neither in SEND_FILES nor classified in NOT_PER_USER"
    );
    // The classification is re-checked, not trusted: the unscanned files send
    // nothing outside a helper either, and the rule that keeps a per-user
    // listener off stdio and WebSocket still stands.
    for (file, _) in NOT_PER_USER {
        let (bad, _) = bad_sends(file, &read("src/transport", file));
        assert!(bad.is_empty(), "{file}: {bad:?}");
    }
    assert!(
        read("src/config", "validation.rs")
            .contains("identity_propagation requires an http transport"),
        "the rule NOT_PER_USER rests on is gone: re-classify stdio_listen.rs and websocket_listen.rs"
    );
}

#[test]
fn iso_t5_every_listener_emit_carries_its_listeners_key() {
    let mut bad = Vec::new();
    let mut emits = 0;
    for file in EMIT_FILES {
        let (found, count) = bad_emits(file, &read("src/events", file));
        bad.extend(found);
        emits += count;
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(
        emits, EMITS,
        "a listener emit was added or removed: update EMITS"
    );
}

#[test]
fn iso_t5_every_listener_request_goes_through_the_credential_seam() {
    let mut bad = Vec::new();
    let mut helpers = 0;
    for file in SEND_FILES {
        let (found, count) = bad_sends(file, &read("src/transport", file));
        bad.extend(found);
        helpers += count;
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(
        helpers, SEND_HELPERS,
        "a send helper was added or removed: update SEND_HELPERS"
    );
}

/// An emit inside a fn, as the scan reads it.
fn emit_fn(body: &str) -> String {
    format!("fn f() {{\n{body}\n}}\n")
}

/// The key rule passes the shapes the product uses and fails every way a key
/// can stop being the listener's: none, the gateway's, from elsewhere,
/// shadowed, split across lines, or behind another literal.
#[test]
fn iso_t5_the_key_rule_fails_on_a_broken_emit() {
    let event = |key: &str| {
        format!("hub.emit(SourceEvent {{ name, kind: SourceKind::BackendNotification, {key} }});")
    };
    let keyed = emit_fn(&format!(
        "let lifecycle_key = self.key_of(&name, &data);\n{}",
        event("lifecycle_key")
    ));
    assert_eq!(bad_emits("upstream_session_notes.rs", &keyed), (vec![], 1));
    let gateway = emit_fn(&format!(
        "let key = backend_key(\n    None,\n    &n,\n    &json!({{}}),\n);\n{}",
        event("lifecycle_key: key")
    ));
    assert_eq!(bad_emits(SHARED_VIEW_FILE, &gateway), (vec![], 1));
    // The gateway's key, line breaks and all, on a listener path.
    assert_eq!(bad_emits("upstream_session_notes.rs", &gateway).0.len(), 1);
    let shadowed = emit_fn(&format!(
        "let key = self.key_of(&name, &data);\nlet key = backend_key(None, &n, &d);\n{}",
        event("lifecycle_key: key")
    ));
    assert_eq!(bad_emits("upstream_session_notes.rs", &shadowed).0.len(), 1);
    let none = emit_fn(&event("lifecycle_key: None"));
    assert_eq!(bad_emits("none.rs", &none).0.len(), 1);
    let elsewhere = emit_fn(&format!(
        "let lifecycle_key = Some(name.clone());\n{}",
        event("lifecycle_key")
    ));
    assert_eq!(bad_emits("elsewhere.rs", &elsewhere).0.len(), 1);
    let missing = emit_fn("hub.emit(SourceEvent { kind: SourceKind::BackendNotification });");
    assert_eq!(bad_emits("missing.rs", &missing).0.len(), 1);
    // Field order and a nested literal do not hide an emit from the count.
    let nested = emit_fn(
        "let lifecycle_key = Some(n);\nhub.emit(SourceEvent {\n    lifecycle_key,\n    data: Payload { a: 1 },\n    kind: SourceKind::BackendNotification,\n});\n",
    );
    assert_eq!(bad_emits("nested.rs", &nested).1, 1);
    assert_eq!(bad_emits("nested.rs", &nested).0.len(), 1);
    let descriptor =
        emit_fn("out.push(EventDescriptor { name, kind: SourceKind::BackendNotification });");
    assert_eq!(bad_emits("descriptor.rs", &descriptor), (vec![], 0));
    let stranger = emit_fn("out.push(Other { kind: SourceKind::BackendNotification });");
    assert_eq!(bad_emits("other.rs", &stranger).0.len(), 1);
    let listener = "upstream_session_notes.rs";
    // Every way a key reaches the emit is judged where it was bound.
    for (case, body) in [
        (
            "kind from a variable",
            "let kind = SourceKind::BackendNotification;\nhub.emit(SourceEvent { kind, lifecycle_key: self.key_of(&n, &d) });",
        ),
        (
            "kind from an update",
            "hub.emit(SourceEvent { lifecycle_key: self.key_of(&n, &d), ..base });",
        ),
        (
            "parenthesised None",
            "let key = backend_key((None), &n, &d);\nhub.emit(SourceEvent { kind: SourceKind::BackendNotification, lifecycle_key: key });",
        ),
        (
            "None through a name",
            "let obs = None;\nlet key = backend_key(obs, &n, &d);\nhub.emit(SourceEvent { kind: SourceKind::BackendNotification, lifecycle_key: key });",
        ),
        (
            "alias, then shadowed",
            "let key = None;\nlet lifecycle_key = key;\nlet key = self.key_of(&n, &d);\nhub.emit(SourceEvent { kind: SourceKind::BackendNotification, lifecycle_key });",
        ),
        (
            "reassigned",
            "let mut key = self.key_of(&n, &d);\nkey = None;\nhub.emit(SourceEvent { kind: SourceKind::BackendNotification, lifecycle_key: key });",
        ),
        (
            "closure parameter",
            "let key = self.key_of(&n, &d);\nhub.emit_with(|key| SourceEvent { kind: SourceKind::BackendNotification, lifecycle_key: key });",
        ),
        (
            "macro body",
            "emit!(SourceEvent { kind: SourceKind::BackendNotification, lifecycle_key: None });",
        ),
    ] {
        assert!(
            !bad_emits(listener, &emit_fn(body)).0.is_empty(),
            "{case} passed"
        );
    }
    // A fn that also builds outside tests is scanned; a test-only one is not.
    let both = "#[cfg(any(test, unix))]\nfn f() { hub.emit(SourceEvent { kind: SourceKind::BackendNotification, lifecycle_key: None }); }\n";
    assert_eq!(bad_emits(listener, both).0.len(), 1);
    let test_only = both.replace("any(test, unix)", "test");
    assert_eq!(bad_emits(listener, &test_only), (vec![], 0));
}

/// The credential rule passes the product's shape and fails a request sent
/// outside the helper, from a stored builder or across lines, and a helper
/// that skips `with_credential`.
#[test]
fn iso_t5_the_credential_rule_fails_on_a_broken_send() {
    let good = "impl T {\n    async fn send(&self) {\n        source.with_credential(|h| build(h).send())\n    }\n    async fn notify(&self) {\n        self.send(headers, |h| t.client.post(url).headers(h))\n    }\n}\n";
    assert_eq!(bad_sends("good.rs", good), (vec![], 1));
    let raw = "async fn notify(&self) {\n    t.client\n        .post(url)\n        .headers(h)\n        .send()\n        .await\n}\n";
    assert_eq!(bad_sends("raw.rs", raw).0.len(), 1);
    let stored = "async fn notify(&self) {\n    let request = t.client.post(url);\n    request.send().await\n}\n";
    assert_eq!(bad_sends("stored.rs", stored).0.len(), 1);
    let bypass = "async fn send(&self) {\n    build(headers).send().await\n}\n";
    assert_eq!(bad_sends("bypass.rs", bypass).0.len(), 1);
    let path_call = "async fn notify(&self) {\n    reqwest::RequestBuilder::send(t.client.post(url)).await\n}\n";
    assert_eq!(bad_sends("path_call.rs", path_call).0.len(), 1);
    let in_macro =
        "async fn notify(&self) {\n    tokio::select! { r = t.client.post(url).send() => r }\n}\n";
    assert_eq!(bad_sends("in_macro.rs", in_macro).0.len(), 1);
}

/// LEASE-T0, the static half: a lease is installed only for an
/// `events/lease` request. The hub's `lease` is called from the direct
/// route's `events/lease` answer alone, and the lease store's `install` from
/// that call alone, so no forwarded call carrying a passthrough header can
/// leave a token held. The behavioural half is
/// `lease_t0_a_call_that_is_not_a_lease_leaves_the_store_empty`.
#[test]
fn lease_t0_only_an_events_lease_request_installs_a_lease() {
    let naming = |words: &[&str]| -> Vec<String> {
        product_files("src")
            .into_iter()
            .filter(|f| {
                let text = read("src", f);
                words.iter().all(|w| names_in_code(&text, w))
            })
            .collect()
    };
    assert_eq!(
        naming(&[".lease("]),
        ["gateway/router/backend_handlers/direct_caller.rs"],
        "the hub's lease is called only for an events/lease request"
    );
    assert_eq!(
        naming(&["leases", ".install("]),
        ["events/lease_rpc.rs"],
        "the lease store installs only inside the hub's lease"
    );
}
