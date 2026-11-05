// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fixture with one of its options switched (auth, sanitizing, the
//! schema check, the modern route, a bearer or a key server). Moved out of
//! the shared fixture to keep it under the file-size ceiling.

use super::*;

/// [`fixture`] with `security.sanitize_input` set to `on`.
pub(crate) async fn fixture_sanitizing(answer: Answer, on: bool) -> Fx {
    SANITIZE.with(|s| s.set(on));
    let fx = fixture_inner(answer, false, |meta| meta).await;
    SANITIZE.with(|s| s.set(false));
    fx
}

/// Any fixture builder, run with authentication off.
pub(crate) async fn auth_off<T, F: std::future::Future<Output = T>>(build: F) -> T {
    AUTH_OFF.with(|s| s.set(true));
    let fx = build.await;
    AUTH_OFF.with(|s| s.set(false));
    fx
}

/// Any fixture builder, run with `security.sanitize_input` = `on` (the
/// firewalled and code-mode fixtures under sanitization).
pub(crate) async fn sanitizing<T, F: std::future::Future<Output = T>>(on: bool, build: F) -> T {
    SANITIZE.with(|s| s.set(on));
    let fx = build.await;
    SANITIZE.with(|s| s.set(false));
    fx
}

/// Run `build` with the input-schema check off on both backends and nothing
/// else armed (unsigned), so a directive-named argument reaches dispatch.
/// [`fixture_hardened_signed_schema_off`] also arms signing.
pub(crate) async fn schema_off<T, F: std::future::Future<Output = T>>(build: F) -> T {
    SCHEMA_OFF.with(|s| s.set(true));
    let fx = build.await;
    SCHEMA_OFF.with(|s| s.set(false));
    fx
}

/// [`fixture`] under the default posture with `server.modern_protocol: false`,
/// the rollback gate that turns the 2026-07-28 revision off.
pub(crate) async fn fixture_modern_off(answer: Answer) -> Fx {
    MODERN_OFF.with(|m| m.set(true));
    let fx = fixture_inner(answer, false, |meta| meta).await;
    MODERN_OFF.with(|m| m.set(false));
    fx
}

/// [`fixture_built`] with a static bearer configured, and an API key named
/// `bearer` (its secret is `bearer`): two credentials sharing one display
/// name.
pub(crate) async fn fixture_with_bearer(
    answer: Answer,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    WITH_BEARER.with(|b| b.set(true));
    let fx = fixture_inner(answer, false, build).await;
    WITH_BEARER.with(|b| b.set(false));
    fx
}

/// [`fixture`] with a key server attached, so its temporary tokens are
/// credentials the auth middleware resolves.
pub(crate) async fn fixture_with_key_server(
    answer: Answer,
    key_server: Arc<crate::key_server::KeyServer>,
) -> Fx {
    KEY_SERVER.with(|k| *k.borrow_mut() = Some(key_server));
    let fx = fixture_inner(answer, false, |meta| meta).await;
    KEY_SERVER.with(|k| *k.borrow_mut() = None);
    fx
}
