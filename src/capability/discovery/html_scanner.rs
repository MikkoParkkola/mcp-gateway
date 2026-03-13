//! HTML spec link extraction for the discovery chain.
//!
//! Scans an HTML page for links to API specification files using four patterns:
//!
//! 1. `<link rel="api-description" href="...">` — IANA registered relation
//! 2. `SwaggerUI` `url: "..."` or `spec-url="..."` JS initialiser
//! 3. `<redoc spec-url="...">` element
//! 4. Generic `<a href="...">` pointing to `*.json` / `*.yaml` files
//!    containing "openapi", "swagger", or "api-docs" in the URL
//!
//! Regex patterns are compile-time constants (no user input involved) so
//! regex injection is not a concern. All extracted URLs are SSRF-validated
//! before use by the caller.

use regex::Regex;
use std::sync::OnceLock;

// ============================================================================
// Compiled regex cache (lazy static via OnceLock)
// ============================================================================

fn re_link_api_description() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"<link[^>]+rel=["']api-description["'][^>]+href=["']([^"']+)["']"#)
            .expect("static regex")
    })
}

fn re_swagger_ui_url() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:url:\s*["']|spec-url=["'])([^"']+\.(?:json|yaml|yml))["']"#)
            .expect("static regex")
    })
}

fn re_redoc() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"<redoc[^>]+spec-url=["']([^"']+)["']"#).expect("static regex"))
}

fn re_link_href_spec() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"href=["']([^"']*(?:openapi|swagger|api-docs)[^"']*\.(?:json|yaml|yml))["']"#)
            .expect("static regex")
    })
}

// ============================================================================
// Public API
// ============================================================================

/// Scan an HTML page for links to API specifications.
///
/// Returns deduplicated, sorted absolute URLs. Relative URLs are resolved
/// against `base_url`. SSRF validation is the caller's responsibility.
#[must_use]
pub fn extract_spec_links(html: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();

    // Pattern 1: <link rel="api-description" href="...">
    for cap in re_link_api_description().captures_iter(html) {
        if let Some(href) = cap.get(1) {
            links.push(resolve_url(base_url, href.as_str()));
        }
    }

    // Pattern 2: Swagger UI spec URL
    for cap in re_swagger_ui_url().captures_iter(html) {
        if let Some(href) = cap.get(1) {
            links.push(resolve_url(base_url, href.as_str()));
        }
    }

    // Pattern 3: Redoc spec-url attribute
    for cap in re_redoc().captures_iter(html) {
        if let Some(href) = cap.get(1) {
            links.push(resolve_url(base_url, href.as_str()));
        }
    }

    // Pattern 4: Generic <a href="..."> pointing to spec files
    for cap in re_link_href_spec().captures_iter(html) {
        if let Some(href) = cap.get(1) {
            links.push(resolve_url(base_url, href.as_str()));
        }
    }

    links.sort();
    links.dedup();
    links
}

/// Resolve a potentially relative URL against a base URL.
///
/// - Absolute URLs (`http://` / `https://`) are returned unchanged.
/// - Absolute paths (`/path`) are combined with scheme + host from `base_url`.
/// - Relative paths are appended to `base_url` with a `/` separator.
#[must_use]
pub fn resolve_url(base: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        return href.to_string();
    }

    if href.starts_with('/') {
        // Absolute path — combine with scheme + host
        if let Ok(parsed) = url::Url::parse(base) {
            let host = parsed.host_str().unwrap_or("");
            return format!("{}://{}{}", parsed.scheme(), host, href);
        }
    }

    // Relative path — append to base (strip trailing slash from base first)
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        href.trim_start_matches('/')
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://api.example.com";

    // ── resolve_url ───────────────────────────────────────────────────────────

    #[test]
    fn resolve_absolute_url_unchanged() {
        assert_eq!(
            resolve_url(BASE, "https://other.com/openapi.json"),
            "https://other.com/openapi.json"
        );
    }

    #[test]
    fn resolve_absolute_path() {
        assert_eq!(
            resolve_url(BASE, "/openapi.json"),
            "https://api.example.com/openapi.json"
        );
    }

    #[test]
    fn resolve_relative_path() {
        assert_eq!(
            resolve_url(BASE, "v2/openapi.json"),
            "https://api.example.com/v2/openapi.json"
        );
    }

    #[test]
    fn resolve_relative_path_with_trailing_slash_on_base() {
        assert_eq!(
            resolve_url("https://api.example.com/", "swagger.json"),
            "https://api.example.com/swagger.json"
        );
    }

    // ── extract_spec_links ────────────────────────────────────────────────────

    #[test]
    fn extract_link_rel_api_description() {
        let html = r#"<link rel="api-description" href="/openapi.json">"#;
        let links = extract_spec_links(html, BASE);
        assert!(
            links.contains(&"https://api.example.com/openapi.json".to_string()),
            "links = {links:?}"
        );
    }

    #[test]
    fn extract_swagger_ui_url_pattern() {
        let html = r#"SwaggerUIBundle({ url: "/api/openapi.yaml", dom_id: '#swagger-ui' })"#;
        let links = extract_spec_links(html, BASE);
        assert!(
            links.contains(&"https://api.example.com/api/openapi.yaml".to_string()),
            "links = {links:?}"
        );
    }

    #[test]
    fn extract_redoc_spec_url() {
        let html = r#"<redoc spec-url="/openapi.yaml"></redoc>"#;
        let links = extract_spec_links(html, BASE);
        assert!(
            links.contains(&"https://api.example.com/openapi.yaml".to_string()),
            "links = {links:?}"
        );
    }

    #[test]
    fn extract_generic_a_href_openapi() {
        let html = r#"<a href="/docs/openapi.json">Download spec</a>"#;
        let links = extract_spec_links(html, BASE);
        assert!(
            links.contains(&"https://api.example.com/docs/openapi.json".to_string()),
            "links = {links:?}"
        );
    }

    #[test]
    fn extract_deduplicates_results() {
        let html = r#"
            <link rel="api-description" href="/openapi.json">
            <a href="/openapi.json">Download</a>
        "#;
        let links = extract_spec_links(html, BASE);
        let openapi_links: Vec<_> = links
            .iter()
            .filter(|l| l.contains("openapi.json"))
            .collect();
        assert_eq!(openapi_links.len(), 1, "should deduplicate: {links:?}");
    }

    #[test]
    fn extract_returns_empty_for_no_matches() {
        let html = "<html><body><p>Hello world</p></body></html>";
        assert!(extract_spec_links(html, BASE).is_empty());
    }

    #[test]
    fn extract_ignores_non_spec_hrefs() {
        // A link to a .json file that isn't a spec shouldn't match
        let html = r#"<a href="/data/export.json">Export data</a>"#;
        let links = extract_spec_links(html, BASE);
        assert!(
            links.is_empty(),
            "non-spec href should not match: {links:?}"
        );
    }
}
