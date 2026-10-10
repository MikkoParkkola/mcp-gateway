// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which protected-resource metadata document describes this backend
//! (MIK-8320, MIK-8324).
//!
//! Candidates, in order (MCP 2025-11-25, Authorization, "Protected Resource
//! Metadata Discovery"): the `resource_metadata` URL a 401 names, then the
//! RFC 9728 path-inserted well-known URL, then the origin's. Every document is
//! held to the configured resource (RFC 9728 §3.3), the origin's included: the
//! gateway's stricter reading, because the MCP resource indicator is the
//! server's canonical URI and an origin-named document would bind tokens to
//! another audience. Only a mismatch or a destination refusal ends the walk;
//! a candidate that is absent, not a document, or unreachable moves to the
//! next, which is safe only because of that check.

use super::OAuthClient;
use crate::oauth::metadata::{self, ProtectedResourceMetadata};
use crate::security::sanitize::{redact_url_for_diagnostics, redact_url_keep_path};
use crate::security::ssrf::is_ssrf_refusal;
use crate::{Error, Result};
use tracing::debug;

/// The RFC 9728 §3.1 well-known URL for `resource`: inserted between the host
/// and the path and query, both kept (a path's trailing slash included). Only
/// the lone slash of an empty path goes. RFC 8414's authorization-server rule,
/// which drops a trailing slash, stays in [`metadata::well_known_url`].
pub(crate) fn resource_metadata_url(resource: &str) -> Result<String> {
    let parsed =
        url::Url::parse(resource).map_err(|e| Error::OAuth(format!("Invalid URL: {e}")))?;
    let authority = metadata::base_url(resource)?;
    let path = match parsed.path() {
        "/" => "",
        path => path,
    };
    let query = parsed.query().map(|q| format!("?{q}")).unwrap_or_default();
    Ok(format!(
        "{authority}/.well-known/oauth-protected-resource{path}{query}"
    ))
}

/// Whether a document's `resource` names the configured resource: its exact
/// spelling, or that URL as serialized (`https://h` is `https://h/`, a default
/// port drops). `/mcp` and `/mcp/` stay different resources.
fn names(resource: &str, configured: &str) -> bool {
    resource == configured || url::Url::parse(configured).is_ok_and(|u| u.as_str() == resource)
}

/// The `resource_metadata` parameter of the first `Bearer` challenge carrying
/// one, across every `WWW-Authenticate` header (RFC 9110 §11.6.1: scheme and
/// parameter names are case-insensitive; a value may be a quoted-string).
pub(crate) fn resource_metadata_hint(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| challenges(v).into_iter().find_map(bearer_hint))
}

/// One challenge: its scheme and its `name=value` parameters.
type Challenge = (String, Vec<(String, String)>);

fn bearer_hint((scheme, params): Challenge) -> Option<String> {
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    params
        .into_iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("resource_metadata"))
        .map(|(_, value)| value)
}

/// Split a header value into challenges. A token not followed by `=` starts a
/// new challenge; commas inside a quoted-string do not split. A malformed
/// tail ends the parse with what was read so far.
fn challenges(value: &str) -> Vec<Challenge> {
    let mut out: Vec<Challenge> = Vec::new();
    let mut rest = value.trim_start();
    while !rest.is_empty() {
        rest = rest.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
        let end = rest
            .find(|c: char| c == '=' || c == ',' || c.is_whitespace())
            .unwrap_or(rest.len());
        let token = &rest[..end];
        if token.is_empty() {
            break;
        }
        let after = rest[end..].trim_start();
        if let Some(raw) = after.strip_prefix('=') {
            let raw = raw.trim_start();
            let (param, tail) = if let Some(quoted) = raw.strip_prefix('"') {
                match quoted_string(quoted) {
                    Some(parsed) => parsed,
                    None => break,
                }
            } else {
                let stop = raw.find(',').unwrap_or(raw.len());
                (raw[..stop].trim().to_string(), &raw[stop..])
            };
            match out.last_mut() {
                Some((_, params)) => params.push((token.to_string(), param)),
                None => break,
            }
            rest = tail;
        } else {
            out.push((token.to_string(), Vec::new()));
            rest = after;
        }
    }
    out
}

/// The unescaped content of a quoted-string whose opening quote is gone, and
/// the text after its closing quote; `None` when it never closes.
fn quoted_string(s: &str) -> Option<(String, &str)> {
    let mut value = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => value.push(chars.next()?.1),
            '"' => return Some((value, &s[i + 1..])),
            c => value.push(c),
        }
    }
    None
}

/// What one candidate URL answered. Only a found document is held to §3.3;
/// a destination refusal is not an outcome here but an error that ends the
/// walk.
enum Fetched {
    Found(ProtectedResourceMetadata),
    /// Not a document here: a non-success status, a body that is not one, or
    /// a transport failure. The next candidate is tried.
    Absent,
}

impl OAuthClient {
    /// The metadata document describing this backend, or `None` when no
    /// candidate has one (the caller then uses the origin, as before).
    ///
    /// # Errors
    ///
    /// A document naming another resource, or a destination-policy refusal.
    pub(super) async fn discover_resource_metadata(
        &self,
    ) -> Result<Option<ProtectedResourceMetadata>> {
        let mut candidates = Vec::new();
        if let Some(hint) = self.probe_resource_metadata_hint().await {
            candidates.push(hint);
        }
        candidates.push(resource_metadata_url(&self.resource_url)?);
        let origin = metadata::well_known_url(
            &metadata::base_url(&self.resource_url)?,
            "oauth-protected-resource",
        )?;
        if !candidates.contains(&origin) {
            candidates.push(origin);
        }
        for url in candidates {
            if let Fetched::Found(meta) = self.fetch_resource_metadata(&url).await? {
                if !names(&meta.resource, &self.resource_url) {
                    return Err(Error::OAuth(format!(
                        "protected resource metadata at {} names {:?}, not this backend's {:?}; \
                         the gateway requires the metadata to name the configured resource \
                         (RFC 9728 §3.3, held for every discovery URL). Configure the backend \
                         URL as the resource the server's metadata names, or ask the server \
                         to publish metadata for it.",
                        redact_url_keep_path(&url),
                        redact_url_keep_path(&meta.resource),
                        redact_url_keep_path(&self.resource_url),
                    )));
                }
                return Ok(Some(meta));
            }
        }
        Ok(None)
    }

    /// Ask the resource itself, unauthenticated, as an MCP client's first
    /// request does: a 401 may name its metadata (MCP 2025-11-25 MUST). The
    /// client follows no redirect (gateway-owned clients, MIK-8018), so a 3xx
    /// names nothing and its `Location` is never fetched.
    ///
    /// Any failure here, a destination refusal included, is no hint: the probe
    /// goes to the configured resource, which the transport holds to the
    /// destination policy anyway, and it only reads a header. The hinted URL
    /// itself is checked like every candidate before anything is fetched.
    async fn probe_resource_metadata_hint(&self) -> Option<String> {
        let url = &self.resource_url;
        let client = match self
            .check_destination(url, "MCP endpoint")
            .and_then(|()| self.refresh_client_for(url))
        {
            Ok(client) => client,
            Err(e) => {
                debug!(error = %e, "No resource-metadata hint: the probe is not sent");
                return None;
            }
        };
        let response = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .header("MCP-Protocol-Version", "2025-11-25")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)
            .send()
            .await
            .map_err(|e| {
                // Never the raw reqwest error: its Display carries the URL,
                // query credentials included.
                let safe = crate::security::http_diagnostics::safe_reqwest_message(
                    "the resource-metadata probe failed",
                    &e,
                );
                debug!(error = %safe, "No resource-metadata hint");
            })
            .ok()?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return None;
        }
        // A hint that is not an absolute URL (empty, relative) names nothing:
        // it must not end discovery before the well-known candidates.
        resource_metadata_hint(response.headers()).filter(|hint| url::Url::parse(hint).is_ok())
    }

    async fn fetch_resource_metadata(&self, url: &str) -> Result<Fetched> {
        self.check_destination(url, "protected resource metadata")?;
        let client = self.client_for(url)?;
        let response = match client.get(url).send().await {
            Ok(response) if response.status().is_success() => response,
            Ok(_) => return Ok(Fetched::Absent),
            Err(e) => {
                let error = crate::security::http_diagnostics::oauth_request_error(
                    "Failed to fetch protected resource metadata",
                    &e,
                );
                if is_ssrf_refusal(&error) {
                    return Err(error);
                }
                debug!(url = %redact_url_for_diagnostics(url), error = %error, "No metadata here");
                return Ok(Fetched::Absent);
            }
        };
        match response.json::<ProtectedResourceMetadata>().await {
            Ok(meta) => Ok(Fetched::Found(meta)),
            Err(_) => Ok(Fetched::Absent),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, WWW_AUTHENTICATE};

    #[test]
    fn the_rfc_9728_url_keeps_the_path_its_trailing_slash_and_the_query() {
        let url = |r| resource_metadata_url(r).unwrap();
        assert_eq!(
            url("https://h/mcp"),
            "https://h/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            url("https://h/mcp/"),
            "https://h/.well-known/oauth-protected-resource/mcp/"
        );
        assert_eq!(
            url("https://h:8443/mcp?x=1"),
            "https://h:8443/.well-known/oauth-protected-resource/mcp?x=1"
        );
        assert_eq!(
            url("https://h/"),
            "https://h/.well-known/oauth-protected-resource"
        );
        assert_eq!(
            url("https://h"),
            "https://h/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn a_resource_is_named_by_its_spelling_or_its_serialized_url_only() {
        assert!(
            names("https://h/", "https://h"),
            "empty-path slash (kapa.ai)"
        );
        assert!(names("https://h/x", "https://h:443/x"), "default port");
        assert!(names("https://h/mcp", "https://h/mcp"));
        assert!(
            !names("https://h/mcp/", "https://h/mcp"),
            "a trailing slash is another resource"
        );
        assert!(
            !names("https://h", "https://h/mcp"),
            "the origin is not the path resource"
        );
        assert!(
            !names("https://H/mcp", "https://h/mcp"),
            "host case in the document"
        );
        assert!(
            names("https://h/mcp", "https://H/mcp"),
            "the configured URL as serialized"
        );
    }

    fn hint(values: &[&str]) -> Option<String> {
        let mut headers = HeaderMap::new();
        for v in values {
            headers.append(WWW_AUTHENTICATE, HeaderValue::from_str(v).unwrap());
        }
        resource_metadata_hint(&headers)
    }

    #[test]
    fn the_hint_is_read_from_a_bearer_challenge_case_insensitively() {
        assert_eq!(
            hint(&[r#"Bearer realm="OAuth", resource_metadata="https://h/m", scope="a b""#]),
            Some("https://h/m".into())
        );
        assert_eq!(
            hint(&[r#"bearer RESOURCE_METADATA="https://h/m""#]),
            Some("https://h/m".into())
        );
        assert_eq!(
            hint(&["Bearer resource_metadata=https://h/m"]),
            Some("https://h/m".into())
        );
    }

    #[test]
    fn several_challenges_and_commas_inside_quotes_are_parsed() {
        assert_eq!(
            hint(&[r#"Basic realm="a, b", Bearer error="x, y", resource_metadata="https://h/m""#]),
            Some("https://h/m".into())
        );
        assert_eq!(
            hint(&[
                r#"Basic resource_metadata="https://evil/""#,
                r#"Bearer resource_metadata="https://h/m""#
            ]),
            Some("https://h/m".into()),
            "only a Bearer challenge's parameter counts"
        );
        assert_eq!(
            hint(&[r#"Bearer resource_metadata="https://h/a\"b""#]),
            Some(r#"https://h/a"b"#.into())
        );
    }

    #[test]
    fn a_missing_or_malformed_hint_is_no_hint() {
        assert_eq!(hint(&[]), None);
        assert_eq!(hint(&[r#"Bearer realm="OAuth""#]), None);
        assert_eq!(
            hint(&[r#"Bearer resource_metadata="https://h/never-closed"#]),
            None
        );
        assert_eq!(hint(&["=garbage"]), None);
    }
}
