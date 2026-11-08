// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Client-side output redaction for CLI commands.
//!
//! Removes injected credential literals the CLI itself sent from text the CLI
//! prints. Delegates to the gateway's redactor so the two cannot drift.

/// Remove injected credential literals of any length, keeping surrounding text
/// structure. For JSON keys and values, including numbers matched by value at
/// any length while keeping JSON structure, use [`json`].
pub fn text(text: &str, secrets: &[String]) -> String {
    crate::security::secret_redaction::redact_untruncated(text, secrets, &[])
}

/// Remove injected credential literals from keys and values, including numbers
/// matched by value at any length, keeping JSON structure. Returns whether
/// anything was replaced.
pub fn json(value: &mut serde_json::Value, secrets: &[String]) -> bool {
    crate::security::secret_redaction::redact_value(value, secrets)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_public_surface_is_exactly_text_and_json() {
        let source = include_str!("redact.rs");
        let public: Vec<_> = source
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("pub fn "))
            .map(|line| {
                line.strip_prefix("pub fn ")
                    .expect("public function")
                    .split('(')
                    .next()
                    .expect("function name")
            })
            .collect();
        assert_eq!(public, ["text", "json"]);
        for item in ["pub struct ", "pub enum ", "pub use ", "pub mod "] {
            assert!(!source.lines().any(|line| line.trim().starts_with(item)));
        }
    }

    #[test]
    fn marker_rotation_uses_a_shared_marker_without_the_token() {
        let token = "redacted".to_string();
        let output = super::text(&token, std::slice::from_ref(&token));
        assert!(crate::security::secret_redaction::contains_marker(&output));
        assert!(!output.contains(&token));
    }
}
