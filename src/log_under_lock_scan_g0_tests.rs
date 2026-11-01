// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! G0: the log-under-lock classifier's self-test, every guard form planted
//! held and released.

use super::scan;

/// Hits in one planted source file.
fn planted(src: &str) -> usize {
    let file = syn::parse_file(src).unwrap_or_else(|e| panic!("{e}: {src}"));
    scan(&[("planted.rs".to_owned(), file)]).len()
}

/// Every guard form the scan must see: (form, held, released).
const CASES: &[(&str, &str, &str)] = &[
    (
        "let",
        "fn f(m: &M) { let g = m.lock().unwrap(); warn!(\"x\"); }",
        "fn f(m: &M) { let v = { let g = m.lock().unwrap(); *g }; warn!(\"x\"); }",
    ),
    (
        "if let",
        "fn f(m: &M) { if let Ok(g) = m.lock() { warn!(\"x\"); } }",
        "fn f(m: &M) { if let Ok(g) = m.lock() { drop(g); warn!(\"x\"); } }",
    ),
    (
        "let chain",
        "fn f(m: &M) { if let Ok(g) = m.lock() && *g > 0 { warn!(\"x\"); } }",
        "fn f(m: &M) { if let Ok(g) = m.lock() && *g > 0 { drop(g); warn!(\"x\"); } }",
    ),
    (
        "while let",
        "fn f(m: &M) { while let Ok(g) = m.try_lock() { warn!(\"x\"); } }",
        "fn f(m: &M) { while let Ok(g) = m.try_lock() { drop(g); warn!(\"x\"); } }",
    ),
    (
        "let else",
        "fn f(m: &M) { let Ok(g) = m.lock() else { return }; warn!(\"x\"); }",
        "fn f(m: &M) { let Ok(g) = m.lock() else { return }; drop(g); warn!(\"x\"); }",
    ),
    (
        "timeout",
        "async fn f(m: &M) { let Ok(g) = timeout(d, m.lock()).await else { return }; warn!(\"x\"); }",
        "async fn f(m: &M) { let Ok(g) = timeout(d, m.lock()).await else { return }; drop(g); warn!(\"x\"); }",
    ),
    (
        "timeout_at",
        "async fn f(m: &M) { let Ok(g) = tokio::time::timeout_at(t, m.lock_owned()).await else { return }; warn!(\"x\"); }",
        "async fn f(m: &M) { let Ok(g) = tokio::time::timeout_at(t, m.lock_owned()).await else { return }; std::mem::drop(g); warn!(\"x\"); }",
    ),
    (
        "await and ?",
        "async fn f(m: &M) -> R { let g = m.write().await; let h = n.try_read().map_err(e)?; warn!(\"x\"); }",
        "async fn f(m: &M) -> R { { let g = m.write().await; } warn!(\"x\"); }",
    ),
    (
        "poison recovery",
        "fn f(m: &M) { let g = m.lock().unwrap_or_else(PoisonError::into_inner); warn!(\"x\"); }",
        "fn f(m: &M) { let v = *m.lock().unwrap_or_else(PoisonError::into_inner); warn!(\"x\"); }",
    ),
    (
        "block result",
        "fn f(m: &M) { let g = { m.lock().unwrap() }; warn!(\"x\"); }",
        "fn f(m: &M) { let g = { m.lock().unwrap() }; drop(g); warn!(\"x\"); }",
    ),
    (
        "match and Some hand-off",
        "async fn f(l: Option<A>) { let held = match l { Some(l) => { let Ok(held) = timeout(w, l.lock_owned()).await else { return }; Some(held) } None => None }; warn!(\"x\"); }",
        "async fn f(l: Option<A>) { let held = match l { Some(l) => { let Ok(held) = timeout(w, l.lock_owned()).await else { return }; Some(held) } None => None }; drop(held); warn!(\"x\"); }",
    ),
    (
        "move",
        "fn f(m: &M) { let a = m.lock().unwrap(); let b = a; warn!(\"x\"); }",
        "fn f(m: &M) { let a = m.lock().unwrap(); let b = a; drop(b); drop(a); warn!(\"x\"); }",
    ),
    (
        "guard parameter",
        "fn f(g: MutexGuard<'_, u8>) { warn!(\"x\"); }",
        "fn f(g: MutexGuard<'_, u8>) -> u8 { *g }",
    ),
    (
        "crate guard type",
        "type CacheGuard = OwnedMutexGuard<()>; fn f(held: CacheGuard) { warn!(\"x\"); }",
        "type CacheGuard = OwnedMutexGuard<()>; fn f(held: CacheGuard) { drop(held); warn!(\"x\"); }",
    ),
    (
        "guard helper",
        "impl S { fn order(&self) -> MutexGuard<'_, u8> { self.m.lock().unwrap() } fn f(&self) { let _o = self.order(); warn!(\"x\"); } }",
        "impl S { fn order(&self) -> MutexGuard<'_, u8> { self.m.lock().unwrap() } fn f(&self) { let _o = self.order(); drop(_o); warn!(\"x\"); } }",
    ),
    (
        "dashmap ref",
        "struct S { map: DashMap<u8, u8> } impl S { fn f(&self) { let r = self.map.get(&1); warn!(\"x\"); } }",
        "struct S { map: DashMap<u8, u8> } impl S { fn f(&self) { let k = self.map.get(&1).map(|r| *r); warn!(\"x\"); } }",
    ),
    (
        "match scrutinee",
        "fn f(m: &M) { match m.lock() { Ok(g) => { warn!(\"x\"); } Err(_) => {} } }",
        "fn f(m: &M) { match m.try_lock() { Ok(_) => {} Err(e) => { warn!(\"busy\"); } } }",
    ),
    (
        "PendingLogs::emit",
        "fn f(m: &M, logs: P) { let g = m.lock().unwrap(); logs.emit(); }",
        "fn f(m: &M, logs: P) { let g = m.lock().unwrap(); drop(g); logs.emit(); }",
    ),
    (
        "callee-locked callback",
        "fn f(e: &E) { e.tools_cache.replace(x, || { warn!(\"x\"); }); }",
        "fn f(e: &E) { e.tools_cache.replace(x, || {}); warn!(\"x\"); }",
    ),
    (
        "select! arm",
        "async fn f(m: &M) { tokio::select! { g = m.lock() => { warn!(\"x\"); } } }",
        "async fn f(m: &M) { tokio::select! { _ = tick() => { warn!(\"x\"); } } }",
    ),
    (
        "zero-argument read",
        "fn f(l: &L) { let g = l.read(); tracing::event!(Level::WARN, \"x\"); }",
        "fn f(r: &mut R, buf: &mut [u8]) { let n = r.read(buf); warn!(\"x\"); }",
    ),
];

/// G0: each guard form, held over a log line, is one hit; released first, none.
#[test]
fn g0_every_guard_form_is_found_and_every_released_form_is_not() {
    for (form, held, released) in CASES {
        assert_eq!(planted(held), 1, "{form}, held: not found exactly once");
        assert_eq!(planted(released), 0, "{form}, released: still found");
    }
}

/// G0: a hit names its line by the message, never by a field's value or the
/// target, so an allowlist entry cannot cover a new line in the same function.
#[test]
fn g0_a_hit_is_keyed_by_its_message() {
    let src = "fn f(m: &M) { let g = m.lock().unwrap(); \
               warn!(target: \"t\", path = \"p\", n = %x, \"the line {}\", y); }";
    let file = syn::parse_file(src).expect("planted source");
    assert_eq!(
        scan(&[("planted.rs".to_owned(), file)]),
        [(
            "planted.rs".to_owned(),
            "f".to_owned(),
            "warn!: the line {}".to_owned()
        )]
    );
}
