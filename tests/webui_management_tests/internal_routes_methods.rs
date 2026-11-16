// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each INTERNAL route answers only the methods it has rows for: any other
//! method is refused, so a hidden route never grows an unpinned answer.

use super::*;

const PROBE_METHODS: [Method; 7] = [
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::OPTIONS,
];

/// INTERNAL paths whose other methods answer 404 by design, not 405, and why.
const OTHER_METHODS_NOT_FOUND: &[(&str, &str)] = &[(
    "/ui/{*path}",
    "the shell's method fallback answers 404, as before the shell existed \
     (src/gateway/ui/shell.rs:152-155, routed at src/gateway/ui/mod.rs:171-173)",
)];

/// A method outside a route's rows answers 405, or 404 on a path listed in
/// [`OTHER_METHODS_NOT_FOUND`]. HEAD on a GET route is served by the GET
/// handler (axum 0.8), so it answers like GET with an empty body.
#[tokio::test]
async fn internal_routes_refuse_every_other_method() {
    let gw = gateway(Fixture::AuthOn).await;
    let mut wrong = Vec::new();
    for path in doc_internal_paths(SURFACE_DOC)
        .iter()
        .filter(|p| mounted(p))
    {
        let rows: Vec<&Row> = all_rows().filter(|r| r.path == path).collect();
        let Some(first) = rows.first() else { continue };
        let has = |m: &Method| rows.iter().any(|r| r.method == *m);
        for method in PROBE_METHODS.iter().filter(|m| !has(m)) {
            if *method == Method::HEAD && has(&Method::GET) {
                // Back to back, so no row's write sits between the two.
                let (get, _, _) = send(
                    &gw,
                    request(&Method::GET, first.uri, Caller::Admin, Payload::None),
                )
                .await;
                let (head, _, body) = send(
                    &gw,
                    request(method, first.uri, Caller::Admin, Payload::None),
                )
                .await;
                if head != get || !body.is_empty() {
                    wrong.push(format!(
                        "HEAD {path}: {head} with {} body bytes, GET answered {get}",
                        body.len()
                    ));
                }
                continue;
            }
            let (status, _, _) = send(
                &gw,
                request(method, first.uri, Caller::Admin, Payload::None),
            )
            .await;
            let expected = if OTHER_METHODS_NOT_FOUND.iter().any(|(p, _)| p == path) {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::METHOD_NOT_ALLOWED
            };
            if status != expected {
                wrong.push(format!(
                    "{method} {path}: expected {expected}, got {status}"
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "INTERNAL routes answer methods they have no row for:\n{}",
        wrong.join("\n")
    );
}
