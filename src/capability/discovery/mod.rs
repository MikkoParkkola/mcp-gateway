// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Auto-Capability Discovery from URL (RFC-0074)
//!
//! Implements the `cap import-url` pipeline:
//!
//! ```text
//! URL -> DiscoveryChain (parallel probing) -> SpecDetector (format sniff)
//!     -> OpenApiConverter -> QualityScorer -> DeduplicateFilter
//!     -> Vec<GeneratedCapability>
//! ```
//!
//! All URL fetches are SSRF-validated before execution. The probe fan-out is
//! parallel via `futures::future::join_all` for single-RTT discovery latency.

pub mod chain;
pub mod dedup;
pub mod detector;
pub mod html_scanner;
pub mod quality;

pub use chain::DiscoveryChain;
pub use dedup::deduplicate;
pub use detector::SpecDetector;
pub use quality::{EndpointQuality, rank_capabilities, score_capability};

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::security::ssrf::validate_url_not_ssrf;

// ============================================================================
// Public types
// ============================================================================

/// Result of discovering an API specification from a URL.
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// The URL where the spec was found.
    pub spec_url: String,
    /// Detected specification format.
    pub format: SpecFormat,
    /// Raw spec content (JSON or YAML string).
    pub spec_content: String,
    /// How the spec was discovered (for logging/UX).
    pub discovery_method: DiscoveryMethod,
}

/// Detected API specification format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpecFormat {
    /// `OpenAPI` 3.x
    OpenApi3,
    /// Swagger 2.0
    Swagger2,
    /// GraphQL introspection schema (Phase 2 — deferred)
    GraphQL,
}

impl std::fmt::Display for SpecFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenApi3 => write!(f, "OpenAPI 3.x"),
            Self::Swagger2 => write!(f, "Swagger 2.0"),
            Self::GraphQL => write!(f, "GraphQL"),
        }
    }
}

/// How the spec was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Found at a well-known path (e.g., /openapi.json).
    WellKnownPath(String),
    /// Found via an HTML page link or meta tag.
    HtmlLink(String),
    /// GraphQL introspection query succeeded.
    GraphQLIntrospection,
    /// Found in robots.txt API path hints.
    RobotsTxt,
}

/// Options controlling the discovery process.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    /// Name prefix for generated capabilities (e.g., "stripe").
    pub prefix: Option<String>,
    /// Output directory for generated YAML files.
    pub output_dir: PathBuf,
    /// Authorization header value (e.g., "Bearer `sk_test_xxx`").
    pub auth: Option<String>,
    /// Maximum number of endpoints to generate (default: 50).
    pub max_endpoints: usize,
    /// If true, print what would be generated without writing files.
    pub dry_run: bool,
    /// If true, prompt user to confirm each endpoint (not for v1).
    pub interactive: bool,
    /// Existing capability names to skip (dedup).
    pub existing_names: Vec<String>,
    /// Request timeout for spec fetching.
    pub timeout: std::time::Duration,
    /// Default cost per call for generated capabilities (RFC-0075).
    pub cost_per_call: Option<f64>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            prefix: None,
            output_dir: PathBuf::from("capabilities"),
            auth: None,
            max_endpoints: 50,
            dry_run: false,
            interactive: false,
            existing_names: Vec::new(),
            timeout: std::time::Duration::from_secs(30),
            cost_per_call: None,
        }
    }
}

/// The main discovery engine.
///
/// Orchestrates: SSRF check -> parallel probe -> format detection ->
/// `OpenAPI` conversion -> quality scoring -> deduplication -> truncation.
pub struct DiscoveryEngine {
    client: reqwest::Client,
    options: DiscoveryOptions,
}

impl DiscoveryEngine {
    /// Create a new `DiscoveryEngine` with a configured reqwest client.
    ///
    /// The client enforces:
    /// - every name resolved once and pinned: a name resolving to a private,
    ///   loopback or reserved address is refused at connect (#2027)
    /// - no proxy from `HTTP(S)_PROXY` in the environment (#1881)
    /// - SSRF validation on every redirect hop
    /// - Max 5 redirects
    /// - Configurable timeout from `options.timeout`
    ///
    /// # Panics
    ///
    /// Panics if reqwest fails to build the client (invalid TLS config). A
    /// default client is no fallback: it would follow environment proxies.
    #[must_use]
    pub fn new(options: DiscoveryOptions) -> Self {
        // The pinned builder never uses an environment proxy (#1881) and pins
        // every name this client fetches: probes, HTML-found spec links and
        // redirect targets, none of which the base-URL check sees (#2027).
        let client = crate::security::ssrf::pinned_client_builder()
            .timeout(options.timeout)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                let ssrf_blocked = validate_url_not_ssrf(attempt.url().as_str()).is_err();
                let too_many_hops = attempt.previous().len() >= 5;
                if ssrf_blocked || too_many_hops {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .user_agent("mcp-gateway/2.5 capability-discovery")
            .build()
            .expect("Failed to create HTTP client");
        Self { client, options }
    }

    /// Discover API specifications from a base URL.
    ///
    /// Pipeline:
    /// 1. SSRF check on `base_url`
    /// 2. `DiscoveryChain` parallel probe — find spec URL
    /// 3. `SpecDetector` — confirm format
    /// 4. `OpenApiConverter` — generate `GeneratedCapability` objects
    /// 5. Quality score, dedup, truncate to `max_endpoints`
    ///
    /// # Errors
    ///
    /// Returns an error if SSRF check fails or no spec could be found.
    pub async fn discover(
        &self,
        base_url: &str,
    ) -> crate::Result<Vec<crate::capability::GeneratedCapability>> {
        // 1. SSRF gate on base URL
        validate_url_not_ssrf(base_url)
            .map_err(|e| crate::Error::Protocol(format!("SSRF check failed for base URL: {e}")))?;

        info!(url = %base_url, "Starting capability discovery");

        // 2. Parallel probe chain
        let chain = DiscoveryChain::new(&self.client, self.options.auth.as_deref());
        let Some(result) = chain.probe(base_url).await else {
            // The pin refused the name at connect: say so, not "no spec" (#2027).
            if let Some(refusal) = chain.ssrf_refusal() {
                return Err(crate::Error::Protocol(format!(
                    "SSRF check failed for base URL: {refusal}"
                )));
            }
            return Err(crate::Error::Config(format!(
                "No API spec found at {base_url} — tried well-known paths, HTML scanning"
            )));
        };

        info!(
            spec_url = %result.spec_url,
            format = %result.format,
            "Discovered API spec"
        );

        // 3. Verify format with SpecDetector (double-check chain's quick sniff)
        let confirmed_format = SpecDetector::detect(&result.spec_content).unwrap_or(result.format);

        if confirmed_format == SpecFormat::GraphQL {
            warn!("GraphQL spec detected — support is Phase 2, skipping");
            return Err(crate::Error::Config(
                "GraphQL discovery is deferred to Phase 2. Use `cap import` with a local OpenAPI spec.".into(),
            ));
        }

        debug!(format = ?confirmed_format, "Format confirmed");

        // 4. Convert via OpenApiConverter
        let mut converter = crate::capability::OpenApiConverter::new();
        if let Some(ref prefix) = self.options.prefix {
            converter = converter.with_prefix(prefix);
        }

        let candidates = converter
            .convert_string(&result.spec_content)
            .map_err(|e| crate::Error::Config(format!("Failed to convert spec: {e}")))?;

        info!(count = candidates.len(), "Converted spec to capabilities");

        // 5. Dedup against existing names
        let deduped = deduplicate(candidates, &self.options.existing_names);

        // 6. Score and sort by quality
        let ranked = rank_capabilities(deduped);

        // 7. Truncate to max_endpoints
        let final_caps: Vec<_> = ranked
            .into_iter()
            .take(self.options.max_endpoints)
            .map(|(cap, quality)| {
                debug!(name = %cap.name, score = quality.score, "Ranked capability");
                cap
            })
            .collect();

        info!(count = final_caps.len(), "Discovery complete");
        Ok(final_caps)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_format_display() {
        assert_eq!(SpecFormat::OpenApi3.to_string(), "OpenAPI 3.x");
        assert_eq!(SpecFormat::Swagger2.to_string(), "Swagger 2.0");
        assert_eq!(SpecFormat::GraphQL.to_string(), "GraphQL");
    }

    #[test]
    fn discovery_options_defaults() {
        let opts = DiscoveryOptions::default();
        assert_eq!(opts.max_endpoints, 50);
        assert!(!opts.dry_run);
        assert!(opts.prefix.is_none());
        assert_eq!(opts.timeout, std::time::Duration::from_secs(30));
    }

    // -- #2027: names are pinned, not just IP literals --

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A loopback listener that only counts the connections it accepts, on
    /// `127.0.0.1` and (where the host has IPv6) on `::1` at the same port, since
    /// `localhost` may resolve to either.
    async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
        let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = v4.local_addr().unwrap().port();
        let v6 = tokio::net::TcpListener::bind(("::1", port)).await.ok();
        let accepted = Arc::new(AtomicUsize::new(0));
        for listener in std::iter::once(v4).chain(v6) {
            let count = Arc::clone(&accepted);
            tokio::spawn(async move {
                while listener.accept().await.is_ok() {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        (port, accepted)
    }

    fn engine() -> DiscoveryEngine {
        DiscoveryEngine::new(DiscoveryOptions {
            timeout: std::time::Duration::from_secs(2),
            ..DiscoveryOptions::default()
        })
    }

    /// The error and every source in its chain, joined.
    fn error_chain(error: &dyn std::error::Error) -> String {
        let mut text = error.to_string();
        let mut source = error.source();
        while let Some(inner) = source {
            text.push_str(" | ");
            text.push_str(&inner.to_string());
            source = inner.source();
        }
        text
    }

    #[tokio::test]
    async fn discover_refuses_a_base_name_resolving_to_loopback() {
        let (port, accepted) = counting_listener().await;
        let error = engine()
            .discover(&format!("http://localhost:{port}"))
            .await
            .expect_err("a name resolving to loopback must be refused");
        let text = error.to_string();
        assert!(
            text.contains("SSRF") && text.contains("'localhost'"),
            "{text}"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "the listener was reached"
        );
    }

    /// The client also follows redirects, whose targets the base-URL check
    /// never sees: it must pin every name itself.
    #[tokio::test]
    async fn discovery_client_pins_names_on_every_request() {
        let (port, accepted) = counting_listener().await;
        let error = engine()
            .client
            .get(format!("http://localhost:{port}/openapi.json"))
            .send()
            .await
            .expect_err("a name resolving to loopback must not connect");
        assert!(error_chain(&error).contains("SSRF blocked"), "{error:?}");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "the listener was reached"
        );
    }
}
