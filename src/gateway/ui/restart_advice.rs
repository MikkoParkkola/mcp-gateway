// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the reload and settings-save answers say while a restart is pending:
//! one guidance line, a start command on Unix, or the refusal a restart would
//! meet instead. A child of `restart_confirm`, so the restart GET and these
//! answers read the same guidance constants.

use std::path::Path;

use serde_json::{Map, Value};

use super::Platform;

/// The Unix guidance line; the restart GET answers it as its recovery too.
pub(super) const UNIX_GUIDANCE: &str = super::Reason::RestartNotAvailable.recovery();
/// The Windows guidance line; the restart GET answers it as its recovery too.
pub(super) const WINDOWS_GUIDANCE: &str = super::Reason::WindowsManualRestart.recovery();

/// The refusal sentence for `why`, the reason a restart would not start.
pub(super) fn refusal_sentence(why: &str) -> String {
    // `why` may end in its own full stop; the sentence adds one.
    let why = why.trim_end_matches('.');
    format!("A restart would not start: {why}. Fix the config file first.")
}

/// A command that starts this gateway again with its config file.
pub(super) struct StartCommand(String);

impl StartCommand {
    /// The command for `exe` and `config`, or none when either path cannot
    /// be shown as one safe, copyable line.
    pub(super) fn new(exe: &Path, config: &Path) -> Option<Self> {
        let exe = shell_word(exe)?;
        let config = shell_word(&std::path::absolute(config).ok()?)?;
        Some(Self(format!("{exe} serve --config {config}")))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The keys one answer carries, or none when no restart is pending.
pub(super) fn advice(
    pending: bool,
    refusal: Option<&str>,
    platform: Platform,
    start: Option<&StartCommand>,
) -> Option<Map<String, Value>> {
    if !pending {
        return None;
    }
    let mut keys = Map::new();
    if let Some(why) = refusal {
        // Exclusive: advice to restart into a refusal would cost the gateway.
        keys.insert("start_refusal".into(), refusal_sentence(why).into());
        return Some(keys);
    }
    let (line, start) = match platform {
        Platform::Unix => (UNIX_GUIDANCE, start),
        // No command on Windows: a service there is not started this way.
        Platform::Windows => (WINDOWS_GUIDANCE, None),
    };
    keys.insert("restart_advice".into(), line.into());
    if let Some(start) = start {
        keys.insert("start_command".into(), start.as_str().into());
    }
    Some(keys)
}

/// `path` as one POSIX shell word: single-quoted, each ' written as '\''.
/// None for a path that is not UTF-8 (a JSON string cannot hold it as is)
/// or that holds a control character (a copied line would break on it).
fn shell_word(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    Some(format!("'{}'", text.replace('\'', r"'\''")))
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "restart_advice_tests.rs"]
mod tests;
