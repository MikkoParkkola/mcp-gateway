// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The helper's uv fetch step (the uv fetch design, decisions 3, 6, 7 and 9):
//! uv's install inside the shared fetch frame, every interpreter spawn of the
//! fetch given `-S` through a wrapper, the direct-URL check, then the run of
//! the package's own console script.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the helper's uv branch calls these (the uv fetch part)"
    )
)]

use std::path::Path;

use super::fetch_step::FetchFailure;
use crate::preview_sandbox::control_msg::FetchStep;

/// The wrapper uv is given as its interpreter, in the preview home.
pub(super) const WRAPPER: &str = ".preview-python";

/// Write `home/.preview-python`, the interpreter uv runs: `python` with
/// `-S`, so no site processing (`.pth`, `sitecustomize`, `usercustomize`)
/// runs while the credential is live. Mode 0555; a failure is setup's.
pub(super) fn write_wrapper(home: &Path, python: &str) -> Result<(), FetchFailure> {
    std::fs::write(
        home.join(WRAPPER),
        format!("#!/bin/sh\nexec {python} \"$@\"\n"),
    )
    .map_err(|e| FetchFailure::at(FetchStep::Setup)(format!("writing the wrapper ({e})")))
}

#[cfg(test)]
#[path = "fetch_uv_tests.rs"]
mod tests;
