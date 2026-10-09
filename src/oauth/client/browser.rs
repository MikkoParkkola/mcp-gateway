// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Opening the authorization URL in the user's browser (MIK-8197).
//!
//! The URL is checked once, on every platform, and handed to the launcher as
//! one argument that no shell parses. It came from the authorization
//! server's metadata, so it is untrusted input to whatever runs it.

use std::process::{Command, Stdio};

use crate::{Error, Result};

/// The URL a launcher may be handed: `https`, or `http` on a loopback host,
/// and nothing a platform handler would act on (a file, a script, a
/// registered protocol). Returned parsed, so the launcher gets its
/// serialization, never the raw input.
///
/// Parsing percent-encodes whitespace and `"` (and drops tabs and newlines),
/// so the serialization never holds what makes Rust's Windows quoting wrap an
/// argument. The Windows launcher relies on that; a test pins it, and the
/// debug assertion documents it.
pub(super) fn launchable(url: &str) -> Result<url::Url> {
    let parsed =
        url::Url::parse(url).map_err(|e| Error::OAuth(format!("Invalid OAuth URL: {e}")))?;
    if !crate::gateway::is_tls_or_loopback(&parsed) {
        return Err(Error::OAuth(
            "refusing to open an authorization URL that is not https (or http on a loopback host)"
                .to_string(),
        ));
    }
    debug_assert!(
        !parsed.as_str().contains([' ', '\t', '\n', '\r', '"']),
        "a parsed URL serializes with no whitespace or quote"
    );
    Ok(parsed)
}

/// The command that opens `url` in the system browser. No shell parses it:
/// on Windows `rundll32` hands the rest of its command line to the URL
/// protocol handler (the `ShellExecute` route `start` used, minus cmd.exe's
/// parser, which split the URL at `&` and ran what followed). stdin and
/// stdout are closed: inherited, they would be the stdio transport's
/// JSON-RPC stream.
pub(super) fn launch_command(url: &url::Url) -> Command {
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("rundll32.exe");
        command.args(["url.dll,FileProtocolHandler", url.as_str()]);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(url.as_str());
        command
    };
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(url.as_str());
        command
    };
    command.stdin(Stdio::null()).stdout(Stdio::null());
    command
}

/// Open a URL in the system default browser. Returns `true` if a launcher
/// was spawned; a refused URL spawns nothing. The caller shows the URL to
/// the user either way.
pub(super) fn open_browser(url: &str) -> bool {
    match launchable(url) {
        Ok(url) => launch_command(&url).spawn().is_ok(),
        Err(refused) => {
            // The reason only: the URL came from a document the server served.
            tracing::warn!(error = %refused, "not opening a browser");
            false
        }
    }
}

#[cfg(test)]
#[path = "browser_tests.rs"]
mod tests;
