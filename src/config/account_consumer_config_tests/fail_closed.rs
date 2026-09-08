// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

/// CONTRACT: `AccountDescriptor.external_strategy` is an
/// `IdentityPropagationConfig` restricted to `signed_assertion` or
/// `token_exchange`, and for an account-bound external descriptor it must be
/// `required: true`. A `required: false` external strategy would let a backend
/// bound to the account fall back to unpropagated identity, so the load must
/// refuse and name both `external_strategy` and `required`.
#[test]
fn external_descriptor_strategy_requires_required_true() {
    let root = tempfile::TempDir::new().unwrap();
    let backends = "backends:\n  external-backend:\n    \
         http_url: https://external.example.invalid/mcp\n    \
         account: partner-api\n";

    for (port, strategy) in [(18726, "signed_assertion"), (18727, "token_exchange")] {
        let descriptors = external_descriptor("partner-api", "partner", strategy);
        assert_eq!(
            descriptors.matches("required: true").count(),
            1,
            "helper must carry exactly one required: true to substitute: {descriptors}"
        );
        evaluate(root.path(), port, &descriptors, backends).unwrap_or_else(|error| {
            panic!("required external descriptor with {strategy} must load, got: {error}")
        });
    }

    for (port, strategy) in [(18728, "signed_assertion"), (18729, "token_exchange")] {
        let required = external_descriptor("partner-api", "partner", strategy);
        assert_eq!(
            required.matches("required: true").count(),
            1,
            "helper must carry exactly one required: true to substitute: {required}"
        );
        let descriptors = required.replace("required: true", "required: false");
        let text = refusal_text(
            evaluate(root.path(), port, &descriptors, backends),
            &format!("an account-bound external descriptor with {strategy} and required: false"),
        );
        assert!(
            text.contains("external_strategy"),
            "refusal must name external_strategy: {text}"
        );
        assert!(
            text.contains("required"),
            "refusal must name the required flag it rejects: {text}"
        );
    }
}
