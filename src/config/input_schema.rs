// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How strictly a backend's tool-call argument keys are held to the tool's
//! `inputSchema` (MIK-7570.SCHEMA.1, R2).

use serde::{Deserialize, Serialize};

/// Per-backend enforcement of undeclared argument keys.
///
/// An enum rather than a flag: `standard` is a third behaviour, not a point
/// between on and off, and a boolean in the config is a parse error rather than
/// a guess at which of the two the operator meant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputSchemaEnforcement {
    /// Gateway rule: a level that declares keys and does not state
    /// `additionalProperties` is closed. Default.
    #[default]
    Closed,
    /// JSON Schema default: absent `additionalProperties` leaves a level open.
    /// A level holding an unresolvable `$ref` is a free map, and is counted.
    Standard,
    /// No key check.
    Off,
}

#[cfg(test)]
impl super::BackendConfig {
    /// A default config with R2 `off`, for a test fixture whose transport
    /// serves no `tools/list` and whose subject is not R2: under the default
    /// `closed`, a cold call would list first (F13) and be refused as
    /// unreadable, so `off` keeps the fixture's call forwarded as before.
    pub(crate) fn r2_off() -> Self {
        Self {
            input_schema_enforcement: InputSchemaEnforcement::Off,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InputSchemaEnforcement;
    use serde_json::json;

    /// R2-T11 (config half): three named modes, `closed` by default, and a
    /// boolean is a parse error rather than a guess.
    #[test]
    fn enforcement_enum_parses_and_selects() {
        for (text, mode) in [
            ("closed", InputSchemaEnforcement::Closed),
            ("standard", InputSchemaEnforcement::Standard),
            ("off", InputSchemaEnforcement::Off),
        ] {
            assert_eq!(
                serde_json::from_value::<InputSchemaEnforcement>(json!(text)).unwrap(),
                mode
            );
        }
        assert!(serde_json::from_value::<InputSchemaEnforcement>(json!(true)).is_err());
        assert_eq!(
            crate::config::BackendConfig::default().input_schema_enforcement,
            InputSchemaEnforcement::Closed
        );
    }
}
