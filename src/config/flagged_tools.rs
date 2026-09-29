// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `allow_flagged_tools` pins (#1441): each value is the descriptor digest the
//! gateway logs when it withholds a tool, 64 lower-case hex characters.

use std::collections::HashMap;

use super::BackendConfig;
use crate::{Error, Result};

/// Refuse a pin that could never match a logged digest, at load, rather than
/// leave the tool silently withheld.
pub(super) fn validate_flagged_tool_pins(backends: &HashMap<String, BackendConfig>) -> Result<()> {
    for (name, backend) in backends {
        for (tool, digest) in &backend.allow_flagged_tools {
            let well_formed = digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !well_formed {
                return Err(Error::ConfigValidation(format!(
                    "backend '{name}' allow_flagged_tools.{tool}: expected the 64-character \
                     lower-case hex digest from the gateway log"
                )));
            }
        }
    }
    Ok(())
}
