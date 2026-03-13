//! `DiscoveryChain` — parallel well-known path probing.
//!
//! Probes up to 10 well-known paths concurrently via `futures::future::join_all`
//! for single-RTT discovery latency (~200-500ms). Every URL is SSRF-validated
//! before fetching.

use futures::future::join_all;
use reqwest::Client;
use tracing::debug;

use crate::security::ssrf::validate_url_not_ssrf;

/// Ordered chain of spec probe strategies.
pub struct DiscoveryChain<'a> {
    client: &'a Client,
    auth: Option<&'a str>,
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
        Self { client, auth }
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
            _ => None,
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
}
