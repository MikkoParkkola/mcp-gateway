// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `DiscoveryChain` — parallel well-known path probing.
//!
//! Probes up to 10 well-known paths concurrently via `futures::future::join_all`
//! for single-RTT discovery latency (~200-500ms). Every URL is SSRF-validated
//! before fetching.

use futures::future::join_all;
use reqwest::Client;
use tracing::debug;

use crate::security::ssrf::{SSRF_BLOCKED, validate_url_not_ssrf};

/// Ordered chain of spec probe strategies.
pub struct DiscoveryChain<'a> {
    client: &'a Client,
    auth: Option<&'a str>,
    /// The first pinning-resolver refusal seen by any probe (#2027).
    ssrf_refusal: std::sync::Mutex<Option<String>>,
}

/// A single probe strategy.
struct Probe {
    /// Suffix to append to the base URL.
    path: &'static str,
    /// Expected format if this probe succeeds.
    format: super::SpecFormat,
    /// HTTP method.
    method: ProbeMethod,
}

/// HTTP method for a probe.
enum ProbeMethod {
    Get,
    /// POST with the given body (reserved for GraphQL introspection).
    #[allow(dead_code)]
    Post(&'static str),
}

/// GraphQL introspection query (minimal — Phase 2).
#[allow(dead_code)]
const GRAPHQL_INTROSPECTION: &str = r#"{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name description args { name description type { name kind ofType { name kind } } } } } } }"}"#;

impl<'a> DiscoveryChain<'a> {
    /// Create a new chain with the given HTTP client and optional auth header.
    #[must_use]
    pub fn new(client: &'a Client, auth: Option<&'a str>) -> Self {
        Self {
            client,
            auth,
            ssrf_refusal: std::sync::Mutex::new(None),
        }
    }

    /// Probe all well-known paths in parallel, return first successful result
    /// in priority order.
    ///
    /// All probes are launched concurrently via `join_all`, reducing latency
    /// from up to N * RTT (sequential) to a single network RTT (~200-500ms).
    /// Priority order is preserved: the first successful probe in the probe
    /// list wins when multiple succeed simultaneously.
    pub async fn probe(&self, base_url: &str) -> Option<super::DiscoveryResult> {
        let probes = Self::probes();

        // Launch all probes concurrently
        let futures: Vec<_> = probes
            .iter()
            .map(|p| self.probe_single(base_url, p))
            .collect();

        let results = join_all(futures).await;

        // Preserve priority order: first Some wins
        results.into_iter().find_map(|r| r)
    }

    /// Probe a single well-known path. Returns `None` on any failure.
    async fn probe_single(&self, base_url: &str, probe: &Probe) -> Option<super::DiscoveryResult> {
        let url = format!("{}{}", base_url.trim_end_matches('/'), probe.path);

        // SSRF gate: reject private/reserved IPs before touching the network
        if validate_url_not_ssrf(&url).is_err() {
            debug!(url = %url, "SSRF blocked probe");
            return None;
        }

        let req = match probe.method {
            ProbeMethod::Get => {
                let mut r = self.client.get(&url);
                if let Some(auth) = self.auth {
                    r = r.header("Authorization", auth);
                }
                r
            }
            ProbeMethod::Post(body) => {
                let mut r = self
                    .client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(body);
                if let Some(auth) = self.auth {
                    r = r.header("Authorization", auth);
                }
                r
            }
        };

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                // Guard against excessively large specs (10 MB limit)
                if let Some(len) = resp.content_length()
                    && len > 10 * 1024 * 1024
                {
                    debug!(url = %url, len = len, "Spec too large, skipping");
                    return None;
                }

                match resp.text().await {
                    Ok(body) if Self::looks_like_spec(&body, probe.format) => {
                        debug!(url = %url, format = ?probe.format, "Probe succeeded");
                        Some(super::DiscoveryResult {
                            spec_url: url,
                            format: probe.format,
                            spec_content: body,
                            discovery_method: super::DiscoveryMethod::WellKnownPath(
                                probe.path.to_string(),
                            ),
                        })
                    }
                    _ => None,
                }
            }
            Ok(_) => None,
            Err(error) => {
                self.record_ssrf_refusal(&error);
                None
            }
        }
    }

    /// Why the probes found nothing, when the cause was an address the
    /// pinning resolver refused rather than a missing spec.
    pub(crate) fn ssrf_refusal(&self) -> Option<String> {
        self.ssrf_refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Keep the first "SSRF blocked" message found in a request error's
    /// source chain (the resolver reports it as an I/O error message).
    fn record_ssrf_refusal(&self, error: &reqwest::Error) {
        let mut source: Option<&dyn std::error::Error> = Some(error);
        while let Some(inner) = source {
            let text = inner.to_string();
            if text.starts_with(SSRF_BLOCKED) {
                self.ssrf_refusal
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get_or_insert(text);
                return;
            }
            source = inner.source();
        }
    }

    /// All probes in priority order.
    ///
    /// GraphQL probe is included for completeness but `DiscoveryEngine`
    /// will reject GraphQL results with a "Phase 2 deferred" message.
    fn probes() -> Vec<Probe> {
        vec![
            Probe {
                path: "/.well-known/openapi.json",
                format: super::SpecFormat::OpenApi3,
                method: ProbeMethod::Get,
            },
            Probe {
                path: "/openapi.json",
                format: super::SpecFormat::OpenApi3,
                method: ProbeMethod::Get,
            },
            Probe {
                path: "/openapi.yaml",
                format: super::SpecFormat::OpenApi3,
                method: ProbeMethod::Get,
            },
            Probe {
                path: "/swagger.json",
                format: super::SpecFormat::Swagger2,
                method: ProbeMethod::Get,
            },
            Probe {
                path: "/swagger.yaml",
                format: super::SpecFormat::Swagger2,
                method: ProbeMethod::Get,
            },
            Probe {
                path: "/api-docs",
                format: super::SpecFormat::OpenApi3,
                method: ProbeMethod::Get,
            },
            // GraphQL probe — deferred to Phase 2, but probe so we can report it
            Probe {
                path: "/graphql",
                format: super::SpecFormat::GraphQL,
                method: ProbeMethod::Post(GRAPHQL_INTROSPECTION),
            },
            Probe {
                path: "/docs",
                format: super::SpecFormat::OpenApi3,
                method: ProbeMethod::Get,
            },
            Probe {
                path: "/api/docs",
                format: super::SpecFormat::OpenApi3,
                method: ProbeMethod::Get,
            },
            Probe {
                path: "/v1",
                format: super::SpecFormat::OpenApi3,
                method: ProbeMethod::Get,
            },
            Probe {
                path: "/api/v1",
                format: super::SpecFormat::OpenApi3,
                method: ProbeMethod::Get,
            },
        ]
    }

    /// Quick content sniff: does this body plausibly contain the expected format?
    ///
    /// Intentionally lenient — the `SpecDetector` does a stricter parse
    /// afterwards. Here we just avoid treating HTML error pages as specs.
    pub(crate) fn looks_like_spec(body: &str, format: super::SpecFormat) -> bool {
        match format {
            super::SpecFormat::OpenApi3 => {
                (body.contains("\"openapi\"") || body.contains("openapi:"))
                    && (body.contains("paths") || body.contains("info"))
            }
            super::SpecFormat::Swagger2 => {
                (body.contains("\"swagger\"") || body.contains("swagger:"))
                    && (body.contains("paths") || body.contains("basePath"))
            }
            super::SpecFormat::GraphQL => body.contains("__schema") && body.contains("queryType"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::discovery::SpecFormat;

    #[test]
    fn looks_like_spec_openapi3_json() {
        let body = r#"{"openapi":"3.0.0","info":{"title":"Test"},"paths":{}}"#;
        assert!(DiscoveryChain::looks_like_spec(body, SpecFormat::OpenApi3));
    }

    #[test]
    fn looks_like_spec_openapi3_yaml() {
        let body = "openapi: '3.0.0'\ninfo:\n  title: Test\npaths: {}";
        assert!(DiscoveryChain::looks_like_spec(body, SpecFormat::OpenApi3));
    }

    #[test]
    fn looks_like_spec_swagger2_json() {
        let body = r#"{"swagger":"2.0","basePath":"/","paths":{}}"#;
        assert!(DiscoveryChain::looks_like_spec(body, SpecFormat::Swagger2));
    }

    #[test]
    fn looks_like_spec_swagger2_yaml() {
        let body = "swagger: '2.0'\nbasePath: /\npaths: {}";
        assert!(DiscoveryChain::looks_like_spec(body, SpecFormat::Swagger2));
    }

    #[test]
    fn looks_like_spec_graphql() {
        let body = r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#;
        assert!(DiscoveryChain::looks_like_spec(body, SpecFormat::GraphQL));
    }

    #[test]
    fn looks_like_spec_rejects_html() {
        let body = "<html><body><h1>API Docs</h1></body></html>";
        assert!(!DiscoveryChain::looks_like_spec(body, SpecFormat::OpenApi3));
        assert!(!DiscoveryChain::looks_like_spec(body, SpecFormat::Swagger2));
        assert!(!DiscoveryChain::looks_like_spec(body, SpecFormat::GraphQL));
    }

    #[test]
    fn looks_like_spec_rejects_wrong_format() {
        let openapi_body = r#"{"openapi":"3.0.0","paths":{}}"#;
        // OpenAPI body should not match Swagger2 detector
        assert!(!DiscoveryChain::looks_like_spec(
            openapi_body,
            SpecFormat::Swagger2
        ));
    }

    /// A port nothing listens on: from the reserved test range, which no port-0
    /// bind can be handed (src/test_ports.rs), so the redirect target stays closed.
    fn closed_port() -> u16 {
        crate::test_ports::reserved_port()
    }

    #[tokio::test]
    async fn probe_records_ssrf_refusal_on_blocked_redirect() {
        let closed = closed_port();
        let target = format!("http://127.0.0.1:{closed}/");
        let app = axum::Router::new().fallback(move || {
            let target = target.clone();
            async move {
                (
                    axum::http::StatusCode::FOUND,
                    [(axum::http::header::LOCATION, target)],
                )
            }
        });
        let listener = tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            tokio::net::TcpListener::bind("127.0.0.1:0"),
        )
        .await
        .expect("bounded")
        .expect("bind");
        let addr_a = listener.local_addr().expect("addr");
        let port_a = addr_a.port();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let client = crate::capability::discovery::discovery_client(
            crate::security::ssrf::pinned_client_builder()
                .resolve("spec-a.discovery-fixture.test", addr_a)
                .resolve("spec-b.discovery-fixture.test", addr_a),
            std::time::Duration::from_secs(5),
        );
        let chain = DiscoveryChain::new(&client, None);
        let base_a = format!("http://spec-a.discovery-fixture.test:{port_a}");
        let probed = tokio::time::timeout(crate::test_wait::HANG_BOUND, chain.probe(&base_a))
            .await
            .expect("bounded");
        assert!(probed.is_none(), "a blocked hop finds no spec");
        let refusal = chain.ssrf_refusal();
        assert!(
            refusal
                .as_deref()
                .is_some_and(|m| m.starts_with("SSRF blocked")),
            "ssrf_refusal must name the block, got: {refusal:?}"
        );
    }

    #[tokio::test]
    async fn probe_follows_safe_cross_host_redirect_to_spec() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let b_hits = Arc::new(AtomicUsize::new(0));
        let b_counter = Arc::clone(&b_hits);
        let spec_body = r#"{"openapi":"3.0.0","paths":{}}"#;
        let app_b = axum::Router::new().route(
            "/spec.json",
            axum::routing::get(move || {
                let b_counter = Arc::clone(&b_counter);
                let body = spec_body.to_string();
                async move {
                    b_counter.fetch_add(1, Ordering::SeqCst);
                    body
                }
            }),
        );
        let listener_b = tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            tokio::net::TcpListener::bind("127.0.0.1:0"),
        )
        .await
        .expect("bounded")
        .expect("bind b");
        let addr_b = listener_b.local_addr().expect("addr b");
        let port_b = addr_b.port();
        tokio::spawn(async move { axum::serve(listener_b, app_b).await });

        let target_b = format!("http://spec-b.discovery-fixture.test:{port_b}/spec.json");
        let app_a = axum::Router::new().route(
            "/openapi.json",
            axum::routing::get(move || {
                let target = target_b.clone();
                async move {
                    (
                        axum::http::StatusCode::FOUND,
                        [(axum::http::header::LOCATION, target)],
                    )
                }
            }),
        );
        let listener_a = tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            tokio::net::TcpListener::bind("127.0.0.1:0"),
        )
        .await
        .expect("bounded")
        .expect("bind a");
        let addr_a = listener_a.local_addr().expect("addr a");
        let port_a = addr_a.port();
        tokio::spawn(async move { axum::serve(listener_a, app_a).await });

        let client = crate::capability::discovery::discovery_client(
            crate::security::ssrf::pinned_client_builder()
                .resolve("spec-a.discovery-fixture.test", addr_a)
                .resolve("spec-b.discovery-fixture.test", addr_b),
            std::time::Duration::from_secs(5),
        );
        let base_a = format!("http://spec-a.discovery-fixture.test:{port_a}");
        let chain = DiscoveryChain::new(&client, None);
        let probed = tokio::time::timeout(crate::test_wait::HANG_BOUND, chain.probe(&base_a))
            .await
            .expect("bounded");
        assert!(probed.is_some(), "a safe redirect finds the spec");
        assert_eq!(
            b_hits.load(Ordering::SeqCst),
            1,
            "B serves the followed redirect once"
        );
    }

    #[tokio::test]
    async fn probe_strips_authorization_on_cross_host_redirect() {
        use std::sync::Arc;

        let auth = format!("{} {}", "Bearer", "synthetic-marker-not-a-credential");

        let b_auths: Arc<std::sync::Mutex<Vec<Option<String>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let b_auths_route = Arc::clone(&b_auths);
        let spec_body = r#"{"openapi":"3.0.0","paths":{}}"#;
        let app_b = axum::Router::new().route(
            "/spec.json",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let b_auths = Arc::clone(&b_auths_route);
                let body = spec_body.to_string();
                async move {
                    let seen = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok().map(str::to_string));
                    b_auths.lock().unwrap_or_else(|e| e.into_inner()).push(seen);
                    body
                }
            }),
        );
        let listener_b = tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            tokio::net::TcpListener::bind("127.0.0.1:0"),
        )
        .await
        .expect("bounded")
        .expect("bind b");
        let addr_b = listener_b.local_addr().expect("addr b");
        let port_b = addr_b.port();
        tokio::spawn(async move { axum::serve(listener_b, app_b).await });

        let a_auths: Arc<std::sync::Mutex<Vec<Option<String>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let a_auths_route = Arc::clone(&a_auths);
        let target_b = format!("http://spec-b.discovery-fixture.test:{port_b}/spec.json");
        let app_a = axum::Router::new().route(
            "/openapi.json",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let a_auths = Arc::clone(&a_auths_route);
                let target = target_b.clone();
                async move {
                    let seen = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok().map(str::to_string));
                    a_auths.lock().unwrap_or_else(|e| e.into_inner()).push(seen);
                    (
                        axum::http::StatusCode::FOUND,
                        [(axum::http::header::LOCATION, target)],
                    )
                }
            }),
        );
        let listener_a = tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            tokio::net::TcpListener::bind("127.0.0.1:0"),
        )
        .await
        .expect("bounded")
        .expect("bind a");
        let addr_a = listener_a.local_addr().expect("addr a");
        let port_a = addr_a.port();
        tokio::spawn(async move { axum::serve(listener_a, app_a).await });

        let client = crate::capability::discovery::discovery_client(
            crate::security::ssrf::pinned_client_builder()
                .resolve("spec-a.discovery-fixture.test", addr_a)
                .resolve("spec-b.discovery-fixture.test", addr_b),
            std::time::Duration::from_secs(5),
        );
        let base_a = format!("http://spec-a.discovery-fixture.test:{port_a}");
        let chain = DiscoveryChain::new(&client, Some(&auth));
        let probed = tokio::time::timeout(crate::test_wait::HANG_BOUND, chain.probe(&base_a))
            .await
            .expect("bounded");
        assert!(probed.is_some(), "a safe redirect finds the spec");
        let seen_a = a_auths.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen_a.len(), 1, "A sees its probe once");
        assert!(
            seen_a[0].is_some(),
            "A's probe request must carry authorization"
        );
        drop(seen_a);
        let seen_b = b_auths.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen_b.len(), 1, "B serves the followed redirect once");
        assert!(
            seen_b[0].is_none(),
            "B must not receive the authorization header"
        );
    }
}
