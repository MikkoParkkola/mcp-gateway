// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the Linux preview-sandbox test files share: a finished preview's
//! output, and the skip that fails where the sandbox is required.

use std::process::ExitStatus;

use mcp_gateway::preview_sandbox::Refusal;

pub struct Output {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// `None` where this host refuses the sandbox and the tests are not
/// required; where `PREVIEW_SANDBOX_REQUIRED` is set, a refusal fails.
pub fn skip_or_fail(refusal: &Refusal) -> Option<Output> {
    assert!(
        std::env::var_os("PREVIEW_SANDBOX_REQUIRED").is_none(),
        "the sandbox is required here but refused: {refusal}"
    );
    eprintln!("skipped: this host refuses the preview sandbox: {refusal}");
    None
}
