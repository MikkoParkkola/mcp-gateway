// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The UI API's version: one number the server serves in `GET /ui/api/status` and the CLI prints in `--version`.
//!
//! It goes up when a route in docs/api/stable-ui-routes.md changes incompatibly: a route removed, or a field a stable
//! route returns removed or retyped. An added route or field does not change it. clap builds its version string at
//! compile time and cannot read a `const`, so the number lives in one macro that both uses expand.

/// The UI API version as a literal, for `concat!` in clap's version string.
macro_rules! ui_api_version {
    () => {
        1
    };
}
pub(crate) use ui_api_version;

/// The UI API version the server serves (the status route, which only the web UI build has).
#[cfg(feature = "webui")]
pub(crate) const UI_API_VERSION: u32 = ui_api_version!();

#[cfg(tp1)]
#[cfg(test)]
#[path = "ui_api_version_tests.rs"]
mod tests;
