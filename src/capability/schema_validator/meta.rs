// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! JSON Schema 2020-12 **meta**-validation — is a schema *document* itself
//! legal, never whether some *instance* satisfies it.
//!
//! This is the opposite question from the rest of this module:
//! [`super::validate_arguments`] and [`super::validate_output`] check whether
//! an argument/result *value* satisfies a schema. This file checks whether the
//! *schema* is a document the 2020-12 dialect permits at all. See
//! `docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity.md` (MIK-6865.SCHEMA.1).
//!
//! # Dialect pinning
//!
//! The check is pinned to Draft 2020-12 via
//! [`jsonschema::draft202012::meta::validator`] regardless of any `\$schema`
//! keyword a document declares or omits. A validator that dispatched on a
//! declared `\$schema` would silently accept a draft-07 document as if it were
//! 2020-12 — the whole point of SCHEMA.1 is the 2020-12 claim, so the check
//! must not defer to what the document claims about itself.
//!
//! # Trust boundary
//!
//! `jsonschema` is compiled with `default-features = false` (see `Cargo.toml`):
//! `resolve-http` and `resolve-file` are both off, so a `\$ref` inside a schema
//! under validation can never be dereferenced over the network or the
//! filesystem during this check — closing an SSRF vector and a path-traversal
//! vector at the dependency level rather than an app-level check that could be
//! bypassed.

use std::sync::OnceLock;

use jsonschema::meta::MetaValidator;
use serde_json::Value;

/// The 2020-12 meta-validator, built once and reused — construction parses
/// the meta-schema itself, which is wasted work to repeat per call.
fn validator() -> &'static MetaValidator<'static> {
    static VALIDATOR: OnceLock<MetaValidator<'static>> = OnceLock::new();
    VALIDATOR.get_or_init(jsonschema::draft202012::meta::validator)
}

/// Validate that `schema` is a legal JSON Schema 2020-12 document.
///
/// This does **not** check whether any *instance* satisfies `schema` — see
/// [`super::validate_arguments`] / [`super::validate_output`] for that. It
/// checks whether `schema` itself is a document the 2020-12 dialect permits,
/// regardless of what `\$schema` (if any) the document itself declares.
///
/// # Errors
///
/// Returns the first meta-schema violation as a human-readable message
/// naming the offending construct: the path to the keyword within `schema`
/// that failed, followed by the validator's own description of why. The
/// path is what makes the message actionable — the validator's `Display`
/// alone describes the failing *value* (e.g. `"[...] is not of types
/// \"boolean\", \"object\""`) without saying which keyword it belongs to.
pub(crate) fn validate_2020_12(schema: &Value) -> Result<(), String> {
    validator()
        .validate(schema)
        .map_err(|error| format!("{}: {error}", error.instance_path()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::validate_2020_12;

    #[test]
    fn validate_2020_12_accepts_a_schema_legal_under_every_dialect() {
        // GIVEN a schema that is legal under every JSON Schema dialect
        let schema = json!({"type": "object", "properties": {"x": {"type": "string"}}});

        // WHEN validated against the 2020-12 meta-schema
        let result = validate_2020_12(&schema);

        // THEN it is accepted
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    /// P4 (test plan): the check is pinned to 2020-12, and can tell that it
    /// is — not merely "some dialect". A validator configured to draft-07
    /// would pass every other row in this file while proving nothing about
    /// the criterion's actual dialect, so this asserts **both directions on
    /// the same fixture**: draft-07 tuple-form `items` (2020-12 replaced it
    /// with `prefixItems`) is clean under draft-07 and rejected under
    /// 2020-12. One direction alone is not enough — a validator that
    /// rejects everything satisfies the 2020-12 half alone.
    #[test]
    fn validate_2020_12_is_pinned_to_2020_12_not_draft07() {
        // GIVEN a schema legal under draft-07 and illegal under 2020-12
        let schema = json!({"items": [{"type": "string"}]});

        // WHEN validated against draft-07's own meta-schema directly —
        // named as the unit under test so this control cannot quietly
        // auto-detect its own dialect
        let draft07_result = jsonschema::draft7::meta::validator().validate(&schema);

        // AND WHEN validated through this module's 2020-12 entry point
        let draft202012_result = validate_2020_12(&schema);

        // THEN draft-07 accepts it
        assert!(
            draft07_result.is_ok(),
            "fixture must be legal under draft-07 for this control to mean anything"
        );
        // AND 2020-12 rejects it, naming the offending keyword
        let err = draft202012_result.expect_err("tuple-form items is illegal under 2020-12");
        assert!(
            err.contains("items"),
            "error should name the offending keyword, got: {err}"
        );
    }

    #[test]
    fn validate_2020_12_never_dereferences_a_ref_over_the_network() {
        // GIVEN a schema whose $ref points at an address that must never be
        // dialed during a meta-validation check
        let schema = json!({"$ref": "http://127.0.0.1:1/does-not-exist#"});
        let start = std::time::Instant::now();

        // WHEN validated against the 2020-12 meta-schema
        let _ = validate_2020_12(&schema);

        // THEN it returns immediately — `default-features = false` compiles
        // out `resolve-http`, so there is no code path left that could stall
        // on a network dial. A slow result here would mean the trust
        // boundary in this file's module doc no longer holds.
        assert!(
            start.elapsed().as_millis() < 500,
            "meta-validation must never attempt to resolve a $ref over the network"
        );
    }
}
