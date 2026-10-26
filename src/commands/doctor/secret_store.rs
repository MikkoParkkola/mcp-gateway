// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `doctor` row `secret-store`: the store saves write to and why, so a
//! fallback to files under `auto` is never silent, and how many unused
//! entries are waiting for an admin (ADR-028).

use std::path::Path;

use mcp_gateway::SecretStoreReport;
use mcp_gateway::config::SecretStoreChoice;

use super::CheckResult;

pub(super) fn check_secret_store(config_path: &Path, choice: SecretStoreChoice) -> CheckResult {
    row(&mcp_gateway::doctor_report(config_path, choice))
}

/// Pass when saves land where the setting asks; warn on a fallback to files,
/// on unused entries, or when they could not be counted; fail when the
/// setting refuses every save.
fn row(report: &SecretStoreReport) -> CheckResult {
    let unused = report.unused.map_or_else(
        || {
            format!(
                "unused=? ({})",
                report.unused_error.as_deref().unwrap_or("not counted")
            )
        },
        |count| format!("unused={count}"),
    );
    let detail = format!(
        "setting={} store={} reason={}; {unused}",
        report.setting,
        report.chosen.unwrap_or("none"),
        report.reason,
    );
    let row = match (report.chosen, report.fell_back, report.unused) {
        (None, _, _) => CheckResult::fail("secret-store", detail)
            .with_hint("set `secrets.store: files`, or unlock or install the keychain"),
        (Some(_), true, counted) => {
            CheckResult::warn("secret-store", detail).with_hint(if counted.is_some() {
                "secrets go to files; unlock or install the keychain to keep them there"
            } else {
                "secrets go to files; unlock or install the keychain to keep them there. \
                 The unused entries could not be counted; run doctor again"
            })
        }
        (Some(_), false, Some(count)) if count > 0 => CheckResult::warn("secret-store", detail)
            .with_hint("unused entries stay until an admin removes them"),
        (Some(_), false, None) => CheckResult::warn("secret-store", detail)
            .with_hint("the unused entries could not be counted; run doctor again"),
        _ => CheckResult::pass("secret-store", detail),
    };
    row.with_category("secrets")
}

#[cfg(test)]
#[path = "secret_store_tests.rs"]
mod tests;
