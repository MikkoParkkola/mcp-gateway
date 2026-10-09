// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Opening the authorization URL in the user's browser.

use std::process::Command;

use crate::Result;

/// The URL a launcher may be handed (MIK-8197).
pub(super) fn launchable(url: &str) -> Result<url::Url> {
    url::Url::parse(url).map_err(|e| crate::Error::OAuth(format!("Invalid OAuth URL: {e}")))
}

/// The command that opens `url` in the system browser.
pub(super) fn launch_command(url: &url::Url) -> Command {
    #[cfg(target_os = "windows")]
    {
        let mut command = Command::new("cmd");
        command.args(["/c", "start", url.as_str()]);
        command
    }
    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("open");
        command.arg(url.as_str());
        command
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let mut command = Command::new("xdg-open");
        command.arg(url.as_str());
        command
    }
}

/// Open a URL in the system default browser. Returns `true` if the command
/// was spawned successfully.
pub(super) fn open_browser(url: &str) -> bool {
    match launchable(url) {
        Ok(url) => launch_command(&url).spawn().is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
#[path = "browser_tests.rs"]
mod tests;
