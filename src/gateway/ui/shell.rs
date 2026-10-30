// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The new web UI's shell (MIK-8870): every `/ui/*` deep link answers one
//! static document, and `/ui/assets/*` serves its content-hashed files with
//! an immutable cache. Both are compile-time constants, unauthenticated like
//! `/ui` and holding no gateway data: the shell's script reads `/ui/api`
//! after load. A page not yet built shows a "Not built yet" state linking
//! `/ui/classic`; `/ui` stays the classic page until the cutover.
//! `scripts/dev/rehash_ui_assets.py` renames edited assets and rewrites this
//! table and the references to them.

use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

/// The shell document.
const DOCUMENT: &str = include_str!("shell/index.html");

/// Every asset by its content-hashed name: the name's hash is the first 12
/// hex digits of the SHA-256 of its bytes (a test holds this), so an edited
/// asset gets a new name and a cached copy can never go stale.
pub(super) const ASSETS: &[(&str, &[u8])] = &[
    (
        "BigShoulders-700.5faff1f81ec2.woff2",
        include_bytes!("shell/fonts/BigShoulders-700.5faff1f81ec2.woff2"),
    ),
    (
        "BigShoulders-800.dee5cd68621c.woff2",
        include_bytes!("shell/fonts/BigShoulders-800.dee5cd68621c.woff2"),
    ),
    (
        "Overpass-400.3d4945e84023.woff2",
        include_bytes!("shell/fonts/Overpass-400.3d4945e84023.woff2"),
    ),
    (
        "OverpassMono-400.9b51e031ff0d.woff2",
        include_bytes!("shell/fonts/OverpassMono-400.9b51e031ff0d.woff2"),
    ),
    (
        "shell.9a1145e288ad.css",
        include_bytes!("shell/shell.9a1145e288ad.css"),
    ),
    (
        "shell.ae2d6f9af7ac.js",
        include_bytes!("shell/shell.ae2d6f9af7ac.js"),
    ),
    (
        "tips.7c43dc6560cf.json",
        include_bytes!("shell/tips.7c43dc6560cf.json"),
    ),
    (
        "tools.24f226efcd24.css",
        include_bytes!("shell/tools.24f226efcd24.css"),
    ),
    (
        "tools.ff2bb0ce777a.js",
        include_bytes!("shell/tools.ff2bb0ce777a.js"),
    ),
    (
        "tooltip.5251c22696fd.css",
        include_bytes!("shell/tooltip.5251c22696fd.css"),
    ),
    (
        "tooltip.deb27f374db3.js",
        include_bytes!("shell/tooltip.deb27f374db3.js"),
    ),
];

/// The frame stylesheet the document inlines (`<style id="frame">`).
#[cfg(test)]
const FRAME_CSS: &str = include_str!("shell-src/frame.css");

/// The shell's policy with `{frame}` for the inlined frame's hash source:
/// everything from this origin, nothing else inline, no framing. Fonts come
/// from `font-src 'self'`, so they are self-hosted. The fixture server
/// (ui-tests/server.mjs) builds its policy from the same file.
const CSP_BASE: &str = include_str!("csp-base.txt");

/// The policy the document is served with: the base, allowing exactly the
/// document's inlined frame by its SHA-256, and no `'unsafe-inline'`.
pub(super) fn csp() -> &'static str {
    static CSP: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let source = format!(
            "'sha256-{}'",
            crate::hashing::sha256_base64(inlined_frame().as_bytes())
        );
        CSP_BASE.trim_end().replace("{frame}", &source)
    });
    &CSP
}

/// The text between the document's `<style id="frame">` and its `</style>`,
/// exactly as served; empty when there is none (a shell test refuses that).
fn inlined_frame() -> &'static str {
    let open = r#"<style id="frame">"#;
    DOCUMENT
        .find(open)
        .map(|i| &DOCUMENT[i + open.len()..])
        .and_then(|rest| rest.find("</style>").map(|end| &rest[..end]))
        .unwrap_or_default()
}

/// `GET /ui/{*path}`: the shell document, except under `api` and `assets`,
/// which answer 404 so an unrouted API or asset path never gets HTML.
pub(super) async fn document(Path(path): Path<String>) -> Response {
    let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
    if matches!(first, "api" | "assets") {
        return StatusCode::NOT_FOUND.into_response();
    }
    (
        [
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
            (header::CONTENT_SECURITY_POLICY, csp()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(DOCUMENT),
    )
        .into_response()
}

/// `GET /ui/assets/{file}`: one asset by exact name, or 404. The lookup is
/// a table match, never a filesystem path, so nothing outside it is reachable.
pub(super) async fn asset(Path(file): Path<String>) -> Response {
    let Some((_, bytes)) = ASSETS.iter().find(|(name, _)| *name == file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, content_type(&file)),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        *bytes,
    )
        .into_response()
}

/// The asset's type from its extension.
fn content_type(file: &str) -> &'static str {
    match file.rsplit_once('.').map(|(_, ext)| ext) {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("woff2") => "font/woff2",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

/// Any other method on a shell path: 404, as before the shell existed.
pub(super) async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

#[cfg(test)]
#[path = "shell_tests.rs"]
mod tests;
