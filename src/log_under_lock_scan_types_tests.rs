// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the log-under-lock scan knows about types: which struct fields are
//! `DashMap`s, and what each local name is bound to in the block being walked.
//! A map is judged by its type, never by a name it shares with another field.

use std::collections::{HashMap, HashSet};

/// A type's head: its last path segment, read through `&`, `&mut`, `Arc`,
/// `Box` and `Rc`, and whether the value is held by value (no reference on the
/// way). `Vec<DashMap<..>>` and `Option<DashMap<..>>` have the heads `Vec` and
/// `Option`: a type that only mentions a map is not one.
pub(super) fn head_of(ty: &syn::Type) -> Option<(String, bool)> {
    match ty {
        syn::Type::Reference(r) => head_of(&r.elem).map(|(name, _)| (name, false)),
        syn::Type::Paren(p) => head_of(&p.elem),
        syn::Type::Group(g) => head_of(&g.elem),
        syn::Type::Path(p) => {
            let seg = p.path.segments.last()?;
            let name = seg.ident.to_string();
            if matches!(name.as_str(), "Arc" | "Box" | "Rc")
                && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
                && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
            {
                // A shared pointer to a map hands out borrows of it.
                return head_of(inner).map(|(n, owned)| (n, owned && name == "Box"));
            }
            Some((name, true))
        }
        _ => None,
    }
}

/// Struct fields across every scanned file.
#[derive(Default)]
pub(super) struct Fields {
    /// struct name -> field name -> whether the field is a `DashMap`. Two
    /// structs of one name merge: a field is a map if either declares it so.
    by_struct: HashMap<String, HashMap<String, bool>>,
    /// Every field name some struct declares a `DashMap`: the rule for a
    /// receiver whose type is not written down (fails closed).
    any_map: HashSet<String>,
}

impl Fields {
    pub(super) fn learn(files: &[syn::File]) -> Self {
        let mut out = Self::default();
        for file in files {
            for item in super::all_items(&file.items) {
                let syn::Item::Struct(s) = item else { continue };
                let fields = out.by_struct.entry(s.ident.to_string()).or_default();
                for f in &s.fields {
                    let Some(id) = &f.ident else { continue };
                    let is_map = head_of(&f.ty).is_some_and(|(n, _)| n == "DashMap");
                    *fields.entry(id.to_string()).or_default() |= is_map;
                    if is_map {
                        out.any_map.insert(id.to_string());
                    }
                }
            }
        }
        out
    }

    /// Whether `field` of a receiver typed `owner` is a map. An unknown owner,
    /// or a known one without that field, falls back to the crate-wide name rule.
    pub(super) fn is_map(&self, owner: Option<&str>, field: &str) -> bool {
        match owner.and_then(|o| self.by_struct.get(o)) {
            Some(fields) if fields.contains_key(field) => fields[field],
            _ => self.any_map.contains(field),
        }
    }
}

/// What a local name is bound to.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Binding {
    /// A `DashMap`, owned or borrowed.
    Map { owned: bool },
    /// A value of a known struct.
    Typed(String),
    /// Anything else: shadows whatever the name meant before.
    Other,
}

impl Binding {
    /// A name bound with type `ty`; `by_ref` for a `ref` binding.
    pub(super) fn of_type(ty: &syn::Type, by_ref: bool) -> Self {
        match head_of(ty) {
            Some((name, owned)) if name == "DashMap" => Self::Map {
                owned: owned && !by_ref,
            },
            Some((name, _)) if name.starts_with(char::is_uppercase) => Self::Typed(name),
            _ => Self::Other,
        }
    }
}

/// Bindings in scope, innermost last. A block, an arm or a closure pushes a
/// scope, and its bindings end with it. Interior mutability lets the scan's
/// read-only checks (a block expression that binds before it yields) scope too.
#[derive(Default)]
pub(super) struct Env(std::cell::RefCell<Vec<HashMap<String, Binding>>>);

impl Env {
    pub(super) fn push(&self) {
        self.0.borrow_mut().push(HashMap::new());
    }

    pub(super) fn pop(&self) {
        self.0.borrow_mut().pop();
    }

    pub(super) fn bind(&self, name: String, binding: Binding) {
        let mut scopes = self.0.borrow_mut();
        if scopes.is_empty() {
            scopes.push(HashMap::new());
        }
        if let Some(scope) = scopes.last_mut() {
            scope.insert(name, binding);
        }
    }

    pub(super) fn get(&self, name: &str) -> Option<Binding> {
        self.0
            .borrow()
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).cloned())
    }
}
