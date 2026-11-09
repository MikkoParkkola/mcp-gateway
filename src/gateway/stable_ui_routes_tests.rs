// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The documented stable method and path pairs remain owned and registered.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::{Next, from_fn};
use axum::response::Response;
use tower::ServiceExt as _;

use super::routes;

struct StableRoute<'a> {
    method: Method,
    template: &'a str,
}

/// Every non-markup line is an entry: a typo must fail, not shorten the list.
fn parse_route_list(text: &str) -> Result<Vec<StableRoute<'_>>, String> {
    let mut routes = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("# ")
            || line.starts_with("> ")
            || (line.starts_with("<!-- SPDX-") && line.ends_with(" -->"))
            || matches!(line, "```text" | "```")
        {
            continue;
        }
        let invalid = || {
            format!(
                "line {}: expected METHOD /ui/api/... description",
                index + 1
            )
        };
        let mut words = line.split_whitespace();
        let method = match words.next() {
            Some("GET") => Method::GET,
            Some("POST") => Method::POST,
            Some("PUT") => Method::PUT,
            Some("PATCH") => Method::PATCH,
            Some("DELETE") => Method::DELETE,
            _ => return Err(invalid()),
        };
        let template = words.next().ok_or_else(invalid)?;
        if !template.starts_with("/ui/api/")
            || template == "/ui/api/"
            || template.contains(['?', '#'])
            || words.next().is_none()
        {
            return Err(invalid());
        }
        routes.push(StableRoute { method, template });
    }
    Ok(routes)
}

fn route_document() -> String {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/api/stable-ui-routes.md");
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn stable_routes_are_owned() {
    let document = route_document();
    let listed = parse_route_list(&document).expect("the stable route list is well formed");
    assert!(!listed.is_empty(), "the stable route list is not empty");
    for route in listed {
        assert!(
            routes::OWNED.contains(&route.template),
            "{} {} is not an owned route",
            route.method,
            route.template
        );
    }
}

/// Capture axum's selection before the handler runs. A fallback has none.
async fn record_matched_path(request: Request<Body>, next: Next) -> Response {
    let matched = request.extensions().get::<MatchedPath>().cloned();
    let mut response = next.run(request).await;
    if let Some(matched) = matched {
        response.extensions_mut().insert(matched);
    }
    response
}

fn request_path(template: &str) -> String {
    template
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "stable-route-fixture"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[tokio::test]
async fn stable_routes_answer_their_method() {
    let document = route_document();
    let listed = parse_route_list(&document).expect("the stable route list is well formed");
    assert!(!listed.is_empty(), "the stable route list is not empty");
    let (state, _dir) = super::router::tests::audience_state(
        &crate::config::AuthConfig::default(),
        (None, None),
        |meta| meta,
    )
    .await;
    let router = super::ui::api_router()
        .layer(from_fn(record_matched_path))
        .with_state(Arc::clone(&state));

    for route in listed {
        let request = Request::builder()
            .method(route.method.clone())
            .uri(request_path(route.template))
            .extension(state.live_config.generation())
            .extension(super::auth::AuthenticatedClient {
                admin: true,
                authenticated: true,
                credential_kind: crate::security::audit::CredentialKind::StaticBearer,
                principal: super::auth::principal_of("stable-ui-routes-test-secret"),
                ..super::auth::anonymous_client()
            })
            .body(Body::empty())
            .expect("the documented route builds a request");
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("the router is infallible");
        assert_eq!(
            response
                .extensions()
                .get::<MatchedPath>()
                .map(MatchedPath::as_str),
            Some(route.template),
            "{} {} must reach its registered template, not a fallback",
            route.method,
            route.template
        );
        assert_ne!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{} {} must keep its documented method",
            route.method,
            route.template
        );
        assert!(
            !matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ),
            "{} {} must admit the fixture's admin caller",
            route.method,
            route.template
        );
    }
}

#[test]
fn the_route_list_parser_rejects_a_malformed_line() {
    let valid = "GET /ui/api/status Gateway health";
    assert_eq!(parse_route_list(valid).expect("valid entry").len(), 1);
    for malformed in [
        "/ui/api/keys Missing method",
        "GET /mcp Outside the UI API",
        "GET /ui/api/keys",
        "GTE /ui/api/keys Misspelled method",
        "GET /ui/api/keys?x= Query instead of a path template",
    ] {
        let document = format!("{valid}\n{malformed}\nPOST /ui/api/reload Reload");
        assert!(
            parse_route_list(&document).is_err(),
            "a malformed line must not silently disappear: {malformed}"
        );
    }
}
