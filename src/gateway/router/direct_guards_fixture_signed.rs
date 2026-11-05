// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fixtures under `security.posture: hardened` with message signing
//! armed, and the relayed ones. Moved out of the shared fixture to keep it
//! under the file-size ceiling.

use super::*;

/// The fixture under `security.posture: hardened` (personal keys) with message
/// signing armed, so the direct route signs every `tools/call` it serves.
pub(crate) async fn fixture_hardened_signed(answer: Answer, require_nonce: bool) -> Fx {
    fixture_hardened_signed_built(answer, require_nonce, |meta| meta).await
}

/// [`fixture_hardened_signed`], arming the signed `MetaMcp` with `build`.
pub(crate) async fn fixture_hardened_signed_built(
    answer: Answer,
    require_nonce: bool,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    HARDENED.with(|h| h.set(true));
    let fx = fixture_inner(answer, false, |meta| build(signing(meta, require_nonce))).await;
    HARDENED.with(|h| h.set(false));
    fx
}

/// [`fixture_hardened_signed_built`] with `log` as the state's transparency
/// log; `build` arms the same log on the `MetaMcp`, so both routes record
/// their deliveries in one file.
pub(crate) async fn fixture_hardened_signed_logged(
    answer: Answer,
    log: Arc<crate::security::TransparencyLogger>,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    STATE_LOG.with(|l| *l.borrow_mut() = Some(log));
    let fx = fixture_hardened_signed_built(answer, false, build).await;
    STATE_LOG.with(|l| *l.borrow_mut() = None);
    fx
}

/// [`fixture_hardened_signed`] with relay detection on as in
/// [`fixture_relayed`]: every direct `tools/call` is signed and staged.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_signed_relayed(answer: Answer) -> Fx {
    HARDENED.with(|h| h.set(true));
    RELAY.with(|r| r.set(true));
    let fx = fixture_inner(answer, true, |meta| signing(meta, false)).await;
    HARDENED.with(|h| h.set(false));
    RELAY.with(|r| r.set(false));
    fx
}

/// [`fixture_signed_relayed`] with `log` as the state's transparency log,
/// `build` arming the signed `MetaMcp` (where a delivery-record failure
/// meets the relay commit).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_signed_relayed_logged(
    answer: Answer,
    log: Arc<crate::security::TransparencyLogger>,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    HARDENED.with(|h| h.set(true));
    RELAY.with(|r| r.set(true));
    STATE_LOG.with(|l| *l.borrow_mut() = Some(log));
    let fx = fixture_inner(answer, true, |meta| build(signing(meta, false))).await;
    HARDENED.with(|h| h.set(false));
    RELAY.with(|r| r.set(false));
    STATE_LOG.with(|l| *l.borrow_mut() = None);
    fx
}

/// [`fixture_firewalled`] with relay detection on for `alpha:read` and
/// `alpha:resources/read`, so the direct route stages receipts.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_relayed(answer: Answer) -> Fx {
    RELAY.with(|r| r.set(true));
    let fx = fixture_inner(answer, true, |meta| meta).await;
    RELAY.with(|r| r.set(false));
    fx
}

/// [`fixture_hardened_signed_built`] with the input-schema check off on both
/// backends, so a call never fills a tool list before dispatch.
pub(crate) async fn fixture_hardened_signed_schema_off(
    answer: Answer,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    SCHEMA_OFF.with(|s| s.set(true));
    let fx = fixture_hardened_signed_built(answer, true, build).await;
    SCHEMA_OFF.with(|s| s.set(false));
    fx
}
