// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The capability editor's routes: validate-only, the base check, the pin.

use super::*;

use mcp_gateway::capability::{compute_capability_hash, rewrite_with_pin};
use sha2::{Digest, Sha256};

/// Send `body` with `headers` as the admin; `(status, ETag, JSON body)`.
async fn call(
    router: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (StatusCode, Option<String>, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .header("content-type", "application/x-yaml");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let resp = Router::clone(router)
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        etag,
        serde_json::from_slice(&bytes).unwrap_or(json!(null)),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// [`VALID_YAML`] with a verified pin line.
fn pinned_yaml() -> String {
    rewrite_with_pin(VALID_YAML, &compute_capability_hash(VALID_YAML))
}

/// A capability directory holding `kept.yaml` with `text`, and its router.
async fn editor_with(text: &str) -> (TempDir, std::path::PathBuf, Router, TempDir) {
    let tmp = TempDir::new().unwrap();
    let cap_file = tmp.path().join("kept.yaml");
    write_owner_only(&cap_file, text).unwrap();
    let (state, store) = make_app_state(Some(tmp.path().to_str().unwrap()), None).await;
    (tmp, cap_file, create_router(state), store)
}

const EDITED_FROM: &str = "Test capability for integration tests";

// ── T1: the validate route writes nothing ────────────────────────────────────

#[tokio::test]
async fn test_validate_route_answers_and_never_writes() {
    let (tmp, cap_file, router, _store) = editor_with(VALID_YAML).await;
    let edited = VALID_YAML.replace(EDITED_FROM, "Unsaved edit");

    let (status, _, body) = call(
        &router,
        Method::POST,
        "/ui/api/capabilities/kept/validate",
        &[],
        &edited,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["valid"], true, "{body}");
    assert!(
        body["errors"].as_array().is_some_and(Vec::is_empty),
        "{body}"
    );
    assert!(
        body["diff"]
            .as_str()
            .is_some_and(|d| d.contains("+description: Unsaved edit")),
        "the diff shows the change a save would make: {body}"
    );
    assert!(body.get("pin").is_some(), "{body}");
    assert_eq!(std::fs::read_to_string(&cap_file).unwrap(), VALID_YAML);

    let (status, _, body) = call(
        &router,
        Method::POST,
        "/ui/api/capabilities/never-created/validate",
        &[],
        VALID_YAML,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!tmp.path().join("never-created.yaml").exists());
}

// ── T3: errors carry the broken line ─────────────────────────────────────────

#[tokio::test]
async fn test_validate_reports_the_syntax_error_line() {
    let (_tmp, _file, router, _store) = editor_with(VALID_YAML).await;

    // A tab cannot indent YAML: the scanner stops on line 3.
    let (status, _, body) = call(
        &router,
        Method::POST,
        "/ui/api/capabilities/kept/validate",
        &[],
        "name: kept\ndescription: ok\n\tbad: 1\n",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["valid"], false, "{body}");
    assert_eq!(body["errors"][0]["line"], 3, "{body}");
    assert!(body["errors"][0]["column"].is_u64(), "{body}");

    // A structural error names a field, not a position.
    let (_, _, body) = call(
        &router,
        Method::POST,
        "/ui/api/capabilities/kept/validate",
        &[],
        "name: kept\nproviders: 5\n",
    )
    .await;
    assert_eq!(body["valid"], false, "{body}");
    assert!(body["errors"][0].get("line").is_none(), "{body}");
    assert!(body["errors"][0]["message"].is_string(), "{body}");
}

// ── T7: an edit-save never blesses a tampered file ───────────────────────────

#[tokio::test]
async fn test_save_over_a_mismatched_pin_is_refused() {
    let tampered = pinned_yaml().replace(EDITED_FROM, "Tampered on disk");
    let (_tmp, cap_file, router, _store) = editor_with(&tampered).await;
    let base = format!("\"{}\"", sha256_hex(tampered.as_bytes()));
    let edited = tampered.replace("Tampered on disk", "Edited in the UI");

    let (status, _, body) = call(
        &router,
        Method::PUT,
        "/ui/api/capabilities/kept",
        &[("if-match", &base)],
        &edited,
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "pin_mismatch", "{body}");
    assert_eq!(std::fs::read_to_string(&cap_file).unwrap(), tampered);

    // Deleting the tampered file is still allowed.
    let (status, _, body) = call(
        &router,
        Method::DELETE,
        "/ui/api/capabilities/kept",
        &[("if-match", &base)],
        "",
    )
    .await;
    assert!(status.is_success(), "{status}: {body}");
    assert!(!cap_file.exists());
}

// ── T8: the base check and the base after a save ─────────────────────────────

#[tokio::test]
async fn test_save_on_a_stale_base_offers_a_patch() {
    let (_tmp, cap_file, router, _store) = editor_with(VALID_YAML).await;
    let (status, etag, _) = call(&router, Method::GET, "/ui/api/capabilities/kept", &[], "").await;
    assert_eq!(status, StatusCode::OK);
    let etag = etag.expect("GET answers an ETag");
    assert_eq!(etag, format!("\"{}\"", sha256_hex(VALID_YAML.as_bytes())));

    // Another writer changes the file after the editor loaded it.
    let theirs = VALID_YAML.replace(EDITED_FROM, "Their change");
    std::fs::write(&cap_file, &theirs).unwrap();
    let mine = VALID_YAML.replace(EDITED_FROM, "My change");

    let (status, _, body) = call(
        &router,
        Method::PUT,
        "/ui/api/capabilities/kept",
        &[("if-match", &etag)],
        &mine,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "stale", "{body}");
    let patch = body["patch"].as_str().expect("a stale save offers a patch");
    // The base is a hash, so the patch runs from the current file to the
    // sent text: the other writer's line shows as removed.
    assert!(patch.contains("-description: Their change"), "{patch}");
    assert!(patch.contains("+description: My change"), "{patch}");
    assert_eq!(
        body["current_sha256"],
        sha256_hex(theirs.as_bytes()).as_str(),
        "{body}"
    );
    assert_eq!(std::fs::read_to_string(&cap_file).unwrap(), theirs);
}

#[tokio::test]
async fn test_save_without_if_match_is_428() {
    let (_tmp, cap_file, router, _store) = editor_with(VALID_YAML).await;
    let mine = VALID_YAML.replace(EDITED_FROM, "My change");

    let (status, _, body) = call(
        &router,
        Method::PUT,
        "/ui/api/capabilities/kept",
        &[],
        &mine,
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "{body}");
    assert_eq!(body["error"], "precondition_required", "{body}");
    assert_eq!(std::fs::read_to_string(&cap_file).unwrap(), VALID_YAML);

    let (status, _, _) = call(
        &router,
        Method::DELETE,
        "/ui/api/capabilities/kept",
        &[],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert!(cap_file.exists());
}

/// Strong comparison: the quoted and the bare hash match; a weak tag and `*`
/// never do.
#[tokio::test]
async fn test_if_match_is_a_strong_comparison() {
    let hash = sha256_hex(VALID_YAML.as_bytes());
    for (tag, matches) in [
        (format!("W/\"{hash}\""), false),
        ("*".to_string(), false),
        (hash.clone(), true),
        (format!("\"{hash}\""), true),
    ] {
        let (_tmp, cap_file, router, _store) = editor_with(VALID_YAML).await;
        let mine = VALID_YAML.replace(EDITED_FROM, "My change");
        let (status, _, body) = call(
            &router,
            Method::PUT,
            "/ui/api/capabilities/kept",
            &[("if-match", &tag)],
            &mine,
        )
        .await;
        if matches {
            assert_eq!(status, StatusCode::OK, "{tag}: {body}");
            assert_eq!(std::fs::read_to_string(&cap_file).unwrap(), mine);
        } else {
            assert_eq!(status, StatusCode::CONFLICT, "{tag}: {body}");
            assert_eq!(body["error"], "stale", "{tag}: {body}");
            assert_eq!(std::fs::read_to_string(&cap_file).unwrap(), VALID_YAML);
        }
    }
}

/// A save answers the hash of the bytes it wrote, which is the next save's
/// base: for a pinned file those differ from the text sent (the pin value).
#[tokio::test]
async fn test_save_answers_the_next_base() {
    let pinned = pinned_yaml();
    let (_tmp, cap_file, router, _store) = editor_with(&pinned).await;
    let first = pinned.replace(EDITED_FROM, "First save");

    let (status, etag, body) = call(
        &router,
        Method::PUT,
        "/ui/api/capabilities/kept",
        &[("if-match", &sha256_hex(pinned.as_bytes()))],
        &first,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let on_disk = std::fs::read_to_string(&cap_file).unwrap();
    assert_ne!(on_disk, first, "the pin value was updated in place");
    let next = sha256_hex(on_disk.as_bytes());
    assert_eq!(body["sha256"], next.as_str(), "{body}");
    assert_eq!(etag.as_deref(), Some(format!("\"{next}\"").as_str()));

    let second = on_disk.replace("First save", "Second save");
    let (status, _, body) = call(
        &router,
        Method::PUT,
        "/ui/api/capabilities/kept",
        &[("if-match", &next)],
        &second,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the answered base is current: {body}"
    );
}

// ── T4/T5: the save changes only the edited lines and the pin value ──────────

#[tokio::test]
async fn test_save_keeps_crlf_and_bom_from_the_base() {
    let crlf = format!(
        "\u{feff}# kept comment\r\n{}",
        VALID_YAML.replace('\n', "\r\n")
    );
    let (_tmp, cap_file, router, _store) = editor_with(&crlf).await;
    // A browser sends LF and drops the BOM.
    let sent = crlf
        .trim_start_matches('\u{feff}')
        .replace("\r\n", "\n")
        .replace(EDITED_FROM, "One value changed");

    let (status, _, body) = call(
        &router,
        Method::PUT,
        "/ui/api/capabilities/kept",
        &[("if-match", &sha256_hex(crlf.as_bytes()))],
        &sent,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let expected = crlf.replace(EDITED_FROM, "One value changed");
    assert_eq!(std::fs::read_to_string(&cap_file).unwrap(), expected);
}

#[tokio::test]
async fn test_pinned_save_rewrites_the_pin_in_place() {
    let pinned = format!("# kept comment\n{}", pinned_yaml());
    let (_tmp, cap_file, router, _store) = editor_with(&pinned).await;
    let pin_index = pinned
        .lines()
        .position(|l| l.starts_with("sha256:"))
        .unwrap();
    let sent = pinned.replace(EDITED_FROM, "One value changed");

    let (status, _, body) = call(
        &router,
        Method::PUT,
        "/ui/api/capabilities/kept",
        &[("if-match", &sha256_hex(pinned.as_bytes()))],
        &sent,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let on_disk = std::fs::read_to_string(&cap_file).unwrap();
    let changed: Vec<usize> = on_disk
        .lines()
        .zip(pinned.lines())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    let edited_index = pinned
        .lines()
        .position(|l| l.contains(EDITED_FROM))
        .unwrap();
    assert_eq!(changed, {
        let mut v = vec![pin_index, edited_index];
        v.sort_unstable();
        v
    });
    let pin_line = on_disk.lines().nth(pin_index).unwrap();
    assert_eq!(
        pin_line,
        format!("sha256: {}", compute_capability_hash(&on_disk)),
        "the pin verifies the bytes written"
    );
}

#[tokio::test]
async fn test_save_to_a_name_with_no_file_is_404() {
    let (tmp, _file, router, _store) = editor_with(VALID_YAML).await;
    let (status, _, body) = call(
        &router,
        Method::PUT,
        "/ui/api/capabilities/absent",
        &[("if-match", &sha256_hex(VALID_YAML.as_bytes()))],
        VALID_YAML,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "not_found", "{body}");
    assert!(
        !tmp.path().join("absent.yaml").exists(),
        "PUT never creates"
    );
}
