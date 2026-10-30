// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every transport a backend builds gets the backend's injected-value set
//! before its first send (MIK-9035 T1.32, DELTA-10): a function in
//! src/backend that constructs a transport must also attach the set
//! (`attach_needles`, `attach_needles_to`) or pass it (`self.needles`).
//! A new construction site without either fails here at review; the send
//! path refuses one at runtime.

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 1] = ["src/lib.rs"];

/// The calls that build a transport.
const CONSTRUCTORS: [[&str; 2]; 6] = [
    ["HttpTransport", "with_destination"],
    ["HttpTransport", "new"],
    ["StdioTransport", "new"],
    ["StdioTransport", "new_with_assigned_cache"],
    ["WebSocketTransport", "start_with_destination"],
    ["A2aTransport", "start"],
];

#[derive(Default)]
struct Body {
    constructs: bool,
    hands_needles: bool,
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = call.func.as_ref() {
            let segs: Vec<String> = p
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if segs.len() >= 2 {
                let tail = [segs[segs.len() - 2].as_str(), segs[segs.len() - 1].as_str()];
                if CONSTRUCTORS.contains(&tail) {
                    self.constructs = true;
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if method == "attach_needles" || method == "attach_needles_to" {
            self.hands_needles = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member
            && name == "needles"
        {
            self.hands_needles = true;
        }
        syn::visit::visit_expr_field(self, field);
    }
}

#[derive(Default)]
struct Sites {
    /// `file: function` of each constructing function, and whether it hands
    /// the set on.
    found: Vec<(String, bool)>,
}

impl Sites {
    fn function(&mut self, file: &str, func: &str, block: &syn::Block) {
        if !file.starts_with("src/backend/") {
            return;
        }
        let mut body = Body::default();
        body.visit_block(block);
        if body.constructs {
            self.found
                .push((format!("{file}: {func}"), body.hands_needles));
        }
    }
}

impl Sink for Sites {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        match item {
            syn::Item::Fn(function) => {
                self.function(&at.file, &function.sig.ident.to_string(), &function.block);
            }
            syn::Item::Impl(block) => {
                for member in &block.items {
                    if let syn::ImplItem::Fn(method) = member
                        && !test_only(&method.attrs)
                    {
                        self.function(&at.file, &method.sig.ident.to_string(), &method.block);
                    }
                }
            }
            _ => {}
        }
    }
}

#[test]
fn every_backend_transport_gets_the_needle_set() {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    assert!(
        sites.found.len() >= 5,
        "premise: the http, listener, stdio, WebSocket and A2A sites were seen: {:?}",
        sites.found
    );
    let bare: Vec<&String> = sites
        .found
        .iter()
        .filter(|(_, hands)| !hands)
        .map(|(site, _)| site)
        .collect();
    assert!(
        bare.is_empty(),
        "these build a transport without its needle set: {bare:?}"
    );
}

/// The pin's own proof: a constructing function that hands nothing on is
/// caught, and one that attaches is not.
#[test]
fn a_construction_without_an_attach_is_caught() {
    let bare: syn::Block = syn::parse_quote!({
        let t = HttpTransport::with_destination(url, headers, timeout, None, None, None, policy)?;
    });
    let attached: syn::Block = syn::parse_quote!({
        let t = HttpTransport::with_destination(url, headers, timeout, None, None, None, policy)?;
        self.attach_needles_to(&t);
    });
    let mut sites = Sites::default();
    sites.function("src/backend/fake.rs", "bare", &bare);
    sites.function("src/backend/fake.rs", "attached", &attached);
    assert_eq!(
        sites.found,
        vec![
            ("src/backend/fake.rs: bare".to_owned(), false),
            ("src/backend/fake.rs: attached".to_owned(), true),
        ]
    );
}
