// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The revision a conditional write needs is printed where the user meets it:
//! on the answer that carries it, and in the refusals that ask for it. The end
//! to end path against the real router lives in the router's own rows.

use super::*;

/// One GET of `path` against `stand`, sent through the shared send.
async fn get(stand: &Stand, path: &str) -> CliOutcome {
    run_api_with(
        &args(path),
        &stand.base,
        &LinkTls::default(),
        credential,
        no_stdin,
        send,
    )
    .await
}

/// An answer that carries an `ETag` prints it as given, with what it is for.
#[tokio::test]
async fn an_answer_with_an_etag_prints_its_revision() {
    let stand = stand_in_with_headers(
        StatusCode::OK,
        "text/yaml; charset=utf-8",
        "name: a\n",
        &[("etag", "\"5e0c\"")],
    )
    .await;
    let out = get(&stand, "/ui/api/capabilities/a").await;
    assert_eq!(out.exit().code(), 0, "{}", out.stderr());
    assert!(
        out.stderr().lines().any(|line| line
            == "api: revision \"5e0c\"; to change this resource, send it with --if-match."),
        "the revision line is missing: {}",
        out.stderr()
    );
}

/// Control: an answer without an `ETag` prints no revision line.
#[tokio::test]
async fn an_answer_without_an_etag_prints_no_revision() {
    let stand = stand_in(StatusCode::OK, "application/json", "{}").await;
    let out = get(&stand, "/ui/api/capabilities").await;
    assert_eq!(out.exit().code(), 0, "{}", out.stderr());
    assert!(!out.stderr().contains("api: revision"), "{}", out.stderr());
}

/// Which recovery a 428 names, by method and path: only a PUT or DELETE on
/// one capability gets a load-and-retry recipe; look-alike paths, other
/// methods and other routes keep the generic remedy.
#[tokio::test]
async fn only_a_capability_save_or_delete_gets_a_recovery_recipe() {
    const SAVE: &str = "apply your change";
    const DELETE: &str = "mean to remove";
    const GENERIC: &str = "the current revision";
    let stand = stand_in(
        StatusCode::PRECONDITION_REQUIRED,
        "application/json",
        r#"{"error":"precondition_required","message":"Send If-Match"}"#,
    )
    .await;
    for (method, path, want) in [
        (ApiMethod::Put, "/ui/api/capabilities/a", SAVE),
        (ApiMethod::Put, "/ui/api/capabilities/a?validate=1", SAVE),
        (ApiMethod::Delete, "/ui/api/capabilities/a", DELETE),
        (ApiMethod::Post, "/ui/api/capabilities/a", GENERIC),
        (ApiMethod::Patch, "/ui/api/capabilities/a", GENERIC),
        (ApiMethod::Put, "/ui/api/capabilities/a/b", GENERIC),
        (ApiMethod::Delete, "/ui/api/capabilities/a/", GENERIC),
        (ApiMethod::Put, "/ui/api/capabilities-x/a", GENERIC),
    ] {
        let mut call = args(path);
        call.method = method.clone();
        if method != ApiMethod::Delete {
            call.data = Some("{}".to_owned());
        }
        let out = run_api_with(
            &call,
            &stand.base,
            &LinkTls::default(),
            credential,
            no_stdin,
            send,
        )
        .await;
        let printed = out.stderr();
        for other in [SAVE, DELETE, GENERIC] {
            assert_eq!(
                printed.contains(other),
                other == want,
                "{method:?} {path}: {printed}"
            );
        }
    }
}

/// Which recovery a stale write (409) names: a DELETE on one capability is
/// told to check and delete again, any other write to redo its change; a
/// delete on a path that is not one capability keeps the generic remedy.
#[tokio::test]
async fn a_stale_write_names_the_recovery_its_method_needs() {
    const SAVE: &str = "apply your change";
    const DELETE: &str = "mean to remove";
    const GENERIC: &str = "the current revision";
    let stand = stand_in(
        StatusCode::CONFLICT,
        "application/json",
        r#"{"error":"stale","message":"changed since it was loaded"}"#,
    )
    .await;
    for (method, path, want) in [
        (ApiMethod::Delete, "/ui/api/capabilities/a", DELETE),
        (ApiMethod::Put, "/ui/api/capabilities/a", SAVE),
        (ApiMethod::Post, "/ui/api/capabilities/a", SAVE),
        (ApiMethod::Patch, "/ui/api/capabilities/a", SAVE),
        (ApiMethod::Delete, "/ui/api/capabilities/a/", GENERIC),
        (ApiMethod::Delete, "/ui/api/capabilities-x/a", GENERIC),
    ] {
        let mut call = args(path);
        call.method = method.clone();
        if method != ApiMethod::Delete {
            call.data = Some("{}".to_owned());
        }
        let out = run_api_with(
            &call,
            &stand.base,
            &LinkTls::default(),
            credential,
            no_stdin,
            send,
        )
        .await;
        let printed = out.stderr();
        for other in [SAVE, DELETE, GENERIC] {
            assert_eq!(
                printed.contains(other),
                other == want,
                "{method:?} {path}: {printed}"
            );
        }
    }
}

/// Control: a 428 that is neither a capability save nor a delete keeps the
/// generic remedy, since no load-and-reapply recipe fits it.
#[tokio::test]
async fn another_precondition_refusal_keeps_the_generic_remedy() {
    let stand = stand_in(
        StatusCode::PRECONDITION_REQUIRED,
        "application/json",
        r#"{"error":"precondition_required","message":"Send If-Match"}"#,
    )
    .await;
    let mut put = args("/ui/api/config");
    put.method = ApiMethod::Put;
    put.data = Some("{}".to_owned());
    let out = run_api_with(
        &put,
        &stand.base,
        &LinkTls::default(),
        credential,
        no_stdin,
        send,
    )
    .await;
    assert_eq!(
        out.stderr(),
        "error: Send If-Match\nSend the request with If-Match set to the current revision. Gateway reason: precondition_required.\n"
    );
}
