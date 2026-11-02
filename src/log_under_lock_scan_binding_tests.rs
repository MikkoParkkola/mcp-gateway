// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The scan judges a map by its type: a `DashMap` reached through a local,
//! a reborrow, a typed parameter or an annotated `let` is still a map, and a
//! plain map that shares a `DashMap` field's name is not.

use super::scan;

/// Hits in one planted source file.
fn planted(src: &str) -> usize {
    let file = syn::parse_file(src).unwrap_or_else(|e| panic!("{e}: {src}"));
    scan(&[("planted.rs".to_owned(), file)]).len()
}

/// A registry whose `backends` is a `DashMap`, a config whose `backends` is
/// a plain map, a struct holding a `Vec` of maps and one holding an `Arc` of
/// one: the same field name, four types. Every row plants all four.
const MAPS: &str = "struct R { backends: DashMap<K, V> } \
                    struct C { backends: HashMap<K, V> } \
                    struct W2 { backends: Vec<DashMap<K, V>> } \
                    struct A { backends: Arc<DashMap<K, V>> }";

/// Hits in `body`, planted after [`MAPS`].
fn with_maps(body: &str) -> usize {
    planted(&format!("{MAPS} {body}"))
}

/// Hits across two planted files: [`MAPS`] plus `extra`, and `body`.
fn with_maps_and(extra: &str, body: &str) -> usize {
    let parse = |src: &str| syn::parse_file(src).unwrap_or_else(|e| panic!("{e}: {src}"));
    scan(&[
        ("maps.rs".to_owned(), parse(&format!("{MAPS} {extra}"))),
        ("body.rs".to_owned(), parse(body)),
    ])
    .len()
}

/// Each `(form, source, hits)` row, asserted alone.
fn rows(cases: &[(&str, &str, usize)]) {
    for (form, src, want) in cases {
        assert_eq!(with_maps(src), *want, "{form}");
    }
}

#[test]
fn scan1_a_dashmap_reached_through_a_binding_is_still_a_map() {
    rows(&[
        (
            "T3 for over a local",
            "impl R { fn f(&self) { let b = &self.backends; for e in b { warn!(\"x\"); } } }",
            1,
        ),
        (
            "T3 iter on a local",
            "impl R { fn f(&self) { let b = &self.backends; for e in b.iter() { warn!(\"x\"); } } }",
            1,
        ),
        (
            "T3 via an unresolved receiver",
            "fn f(x: &Unknown) { let b = &x.backends; for e in b.iter() { warn!(\"x\"); } }",
            1,
        ),
        (
            "T3 bare binding",
            "impl R { fn f(&self) { let b = self.backends; for e in b.iter() { warn!(\"x\"); } } }",
            1,
        ),
        (
            "T4 reborrow",
            "impl R { fn f(&self) { let b = &self.backends; let c = &*b; for e in c.iter() { warn!(\"x\"); } } }",
            1,
        ),
        (
            "T4 move",
            "impl R { fn f(&self) { let b = &self.backends; let c = b; for e in c.iter() { warn!(\"x\"); } } }",
            1,
        ),
        (
            "T5 parameter",
            "fn f(m: &DashMap<K, V>) { for e in m.iter() { warn!(\"x\"); } }",
            1,
        ),
        (
            "T5 annotated let, opaque initializer",
            "fn f(src: S) { let m: &DashMap<K, V> = src; for e in m.iter() { warn!(\"x\"); } }",
            1,
        ),
        (
            "wildcard over iter",
            "impl R { fn f(&self) { for _ in self.backends.iter() { warn!(\"x\"); } } }",
            1,
        ),
        (
            "wildcard over a field",
            "impl R { fn f(&self) { for _ in &self.backends { warn!(\"x\"); } } }",
            1,
        ),
        (
            "wildcard over a local",
            "impl R { fn f(&self) { let b = &self.backends; for _ in b { warn!(\"x\"); } } }",
            1,
        ),
        (
            "shadow C to R by let",
            "fn f(c: &C, r: &R) { let c = r; for e in &c.backends { warn!(\"x\"); } }",
            1,
        ),
        (
            "shadow by a loop variable",
            "fn f(c: &C, rs: &[R]) { for c in rs { for e in &c.backends { warn!(\"x\"); } } }",
            1,
        ),
        (
            "self-referencing shadow, R",
            "impl R { fn f(&self, c: &R) { let c = &c.backends; for e in c { warn!(\"x\"); } } }",
            1,
        ),
        (
            "a map local in a nested block",
            "impl R { fn f(&self, ok: bool) { let b = &self.backends; if ok { for e in b.iter() { warn!(\"x\"); } } } }",
            1,
        ),
        (
            "an Arc field",
            "impl A { fn f(&self) { for e in self.backends.iter() { warn!(\"x\"); } } }",
            1,
        ),
        (
            "a closure capture",
            "impl R { fn f(&self) { let b = &self.backends; let g = || { for e in b.iter() { warn!(\"x\"); } }; } }",
            1,
        ),
        (
            "a guard out of a block expression",
            "impl R { fn f(&self, k: K) { let g = { let b = &self.backends; b.get(&k) }; warn!(\"x\"); } }",
            1,
        ),
    ]);
}

#[test]
fn scan2_a_plain_map_of_a_dashmaps_name_is_not_a_map() {
    rows(&[
        (
            "T1 a resolved parameter's plain field",
            "fn f(c: &C) { for e in &c.backends { warn!(\"x\"); } }",
            0,
        ),
        (
            "T1 a local bound to a plain field",
            "fn f(c: &C) { let b = &c.backends; for e in b { warn!(\"x\"); } }",
            0,
        ),
        (
            "T1 self in impl C",
            "impl C { fn f(&self) { for e in &self.backends { warn!(\"x\"); } } }",
            0,
        ),
        (
            "T1 an annotated let receiver",
            "fn f(src: S) { let c: &C = src; for e in &c.backends { warn!(\"x\"); } }",
            0,
        ),
        (
            "T1 through Arc",
            "fn f(c: Arc<C>) { for e in &c.backends { warn!(\"x\"); } }",
            0,
        ),
        (
            "an annotation outranks the initializer",
            "fn f(w: &W) { let c: &C = &w.inner; for e in &c.backends { warn!(\"x\"); } }",
            0,
        ),
        (
            "self-referencing shadow, C",
            "fn f(c: &C) { let c = &c.backends; for e in c { warn!(\"x\"); } }",
            0,
        ),
        (
            "a shadowed map local",
            "impl R { fn f(&self) { let b = &self.backends; let b = &[1]; for e in b.iter() { warn!(\"x\"); } } }",
            0,
        ),
        (
            "block exit restores",
            "fn f(c: &C, r: &R) { { let c = r; } for e in &c.backends { warn!(\"x\"); } }",
            0,
        ),
        (
            "an owned map consumed",
            "fn f(m: DashMap<K, V>) { for e in m { warn!(\"x\"); } }",
            0,
        ),
        (
            "a Vec of maps is not a map",
            "fn f(w: &W2) { for e in &w.backends { warn!(\"x\"); } }",
            0,
        ),
        (
            "an Option of a map is not a map",
            "fn f(m: Option<DashMap<K, V>>) { for e in m.iter() { warn!(\"x\"); } }",
            0,
        ),
        (
            "a dropped block guard",
            "impl R { fn f(&self, k: K) { let g = { let b = &self.backends; b.get(&k) }; drop(g); warn!(\"x\"); } }",
            0,
        ),
        (
            "T2 an unresolved receiver fails closed",
            "fn f(x: &X) { for e in &x.backends { warn!(\"x\"); } }",
            1,
        ),
    ]);
    // Two structs named C, one declaring a map: the scan fails closed.
    assert_eq!(
        with_maps_and(
            "",
            "struct C { backends: DashMap<K, V> } fn f(c: &C) { for e in &c.backends { warn!(\"x\"); } }",
        ),
        1,
        "a duplicate struct name"
    );
}
