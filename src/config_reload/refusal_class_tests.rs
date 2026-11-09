// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Public reload text and pre-write refusal classification oracles.

use super::reload_context::replace::{
    Expected, RefusalClass, ReplaceError, Replaced, replace_detached,
};
use super::replace_test_support::{START, WAIT, read, setup, setup_refusing_reload, to};
use crate::gateway::test_helpers::write_owner_only;

const POSTURE: &str = "server:\n  public_url: \"https://gw.example.com\"\n";

/// K2: red oracle is Posture before writing the network-posture candidate.
#[tokio::test]
async fn k2_pre_write_posture() {
    let (_dir, path, ctx) = setup_refusing_reload();
    let error = replace_detached(ctx, to(Expected::Any, POSTURE, Replaced::Discard), WAIT)
        .await
        .expect_err("posture must refuse");
    assert_eq!(read(&path), START, "validation must precede the write");
    let ReplaceError::ReloadRefused { class, reason } = error else {
        panic!("expected reload refusal: {error:?}");
    };
    assert!(
        reason.starts_with("config reload refused: refusing to serve HTTP"),
        "{reason}"
    );
    assert_eq!(class, RefusalClass::Posture);
}

/// K2: red oracle is Invalid before writing bytes that are YAML but not a config
/// (they pass the secret-slot check and fail the config parse).
#[tokio::test]
async fn k2_pre_write_parse() {
    let (_dir, path, ctx) = setup_refusing_reload();
    let error = replace_detached(
        ctx,
        to(
            Expected::Any,
            "server:\n  port: not-a-number\n",
            Replaced::Discard,
        ),
        WAIT,
    )
    .await
    .expect_err("parse must refuse");
    assert_eq!(read(&path), START, "validation must precede the write");
    let ReplaceError::ReloadRefused { class, reason } = error else {
        panic!("expected reload refusal: {error:?}");
    };
    assert!(reason.starts_with("Failed to parse config:"), "{reason}");
    assert_eq!(class, RefusalClass::Invalid);
}

/// K4: oracle is the exact existing public error; this control passes the stub.
#[tokio::test]
async fn k4_public_posture_text_is_unchanged() {
    let (_dir, path, ctx) = setup();
    write_owner_only(&path, POSTURE).expect("write candidate");
    let error = ctx.reload_outcome().await.expect_err("posture refusal");
    assert_eq!(
        error,
        "config reload refused: refusing to serve HTTP, reachable at the declared public_url host gw.example.com: authentication is disabled, so any caller \
        that reaches it can invoke every configured backend with this \
        gateway's credentials. Set auth.enabled = true with a bearer token and keep auth.public_paths \
        to /health: with authentication off, every path is open regardless of \
        that list. If authentication terminates in front \
        of this gateway (a sidecar, a service mesh, or a reverse proxy), set \
        server.allow_unauthenticated_network_bind = true. No backend was started or stopped, \
        and no configuration was published. This configuration is on disk, so the next start, including an \
        unplanned one, will refuse to serve. Revert it, or close the \
        tool paths."
    );
}
