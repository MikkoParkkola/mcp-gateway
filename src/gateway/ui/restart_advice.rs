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
pub(super) const UNIX_GUIDANCE: &str = "";
/// The Windows guidance line; the restart GET answers it as its recovery too.
pub(super) const WINDOWS_GUIDANCE: &str = "";

/// The refusal sentence for `why`, the reason a restart would not start.
pub(super) fn refusal_sentence(why: &str) -> String {
    why.to_owned()
}

/// A command that starts this gateway again with its config file.
pub(super) struct StartCommand(String);

impl StartCommand {
    /// The command for `exe` and `config`, or none when either path cannot
    /// be shown as one safe, copyable line.
    pub(super) fn new(exe: &Path, config: &Path) -> Option<Self> {
        let _ = (exe, config);
        None
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
    let _ = (pending, refusal, platform, start);
    None
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "restart_advice_tests.rs"]
mod tests;
