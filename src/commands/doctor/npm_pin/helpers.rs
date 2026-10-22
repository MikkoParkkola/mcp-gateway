// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The private halves of the npm pin check: the one fetch, the pin and
//! proxy parsers, and the terminal sanitizer pieces. The decision, the
//! client and the rows stay in the parent module.

use mcp_gateway::config::BackendConfig;
use url::Url;

use super::{ACCEPT, ClientCfg, MAX_DOC_BYTES, package_url};

/// One package document, or `None` on any failure: a non-200 status, a
/// transport error, or a decoded body past [`MAX_DOC_BYTES`], at which
/// point reading stops. Only the package name is sent.
pub(super) async fn fetch_doc(
    http: &reqwest::Client,
    cfg: &ClientCfg,
    name: &str,
) -> Option<Vec<u8>> {
    let mut response = http
        .get(package_url(&cfg.base, name))
        .header(reqwest::header::ACCEPT, ACCEPT)
        .send()
        .await
        .ok()?;
    if response.status() != reqwest::StatusCode::OK {
        return None;
    }
    // `chunk` yields decoded bytes (reqwest undoes gzip), so the cap
    // bounds the decoded size, not the wire size.
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len() + chunk.len() > MAX_DOC_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

/// Whether `version` is an exact pin: `^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`
/// and at most 64 characters. Tags, ranges and build metadata are not.
pub(super) fn is_exact_version(version: &str) -> bool {
    if version.is_empty() || version.chars().count() > 64 {
        return false;
    }
    let (core, prerelease) = match version.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (version, None),
    };
    let mut parts = core.split('.');
    for _ in 0..3 {
        match parts.next() {
            Some(part) if !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()) => {}
            _ => return false,
        }
    }
    if parts.next().is_some() {
        return false;
    }
    match prerelease {
        None => true,
        Some(text) => {
            !text.is_empty()
                && text
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        }
    }
}

/// A proxy value this check will use, parsed: an `http`/`https` URL with a
/// host and no credentials (credentials would be sent to the proxy, which
/// this check never does), whose serialized form `http::Uri` also accepts
/// with an authority. The last condition matters: `url` accepts hosts
/// like `proxy{typo}` that the HTTP stack drops, going direct instead.
pub(super) fn usable_proxy(value: &str) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    if url.host().is_none() || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let uri: axum::http::Uri = url.as_str().parse().ok()?;
    uri.authority()?;
    Some(url)
}

/// `raw` with ANSI escape sequences removed: CSI (`ESC [`, through a final
/// byte in 0x40..=0x7E), OSC (`ESC ]`, through BEL or `ESC \`), and any
/// other `ESC` together with the character after it.
pub(super) fn strip_escapes(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '\u{1b}' {
            out.push(chars[index]);
            index += 1;
            continue;
        }
        match chars.get(index + 1) {
            Some('[') => {
                let mut end = index + 2;
                while end < chars.len() {
                    let c = chars[end];
                    end += 1;
                    if matches!(c, '\u{40}'..='\u{7e}') {
                        break;
                    }
                }
                index = end;
            }
            Some(']') => {
                let mut end = index + 2;
                while end < chars.len() {
                    if chars[end] == '\u{7}' {
                        end += 1;
                        break;
                    }
                    if chars[end] == '\u{1b}' && chars.get(end + 1) == Some(&'\\') {
                        end += 2;
                        break;
                    }
                    end += 1;
                }
                index = end;
            }
            // Any other escape drops itself and its one operand character;
            // a trailing ESC drops just itself.
            Some(_) => index += 2,
            None => index += 1,
        }
    }
    out
}

/// Whether `c` is a Unicode format character (general category Cf): bidi
/// overrides, zero-width marks and their kin, which reorder or hide the
/// text around them on a terminal.
pub(super) fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{08e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// Whether the backend's env sets `MEMORY_FILE_PATH` to an absolute path,
/// the one spelling that keeps the graph across package versions.
pub(super) fn has_absolute_memory_path(config: &BackendConfig) -> bool {
    match config.env.get("MEMORY_FILE_PATH") {
        Some(value) => std::path::Path::new(value).is_absolute(),
        None => false,
    }
}
