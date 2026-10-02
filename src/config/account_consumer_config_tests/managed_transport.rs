// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

/// Mutant: a managed backend may carry a secret-injection rule that writes the
/// Authorization header, or a transport that drops per-request headers.
#[test]
fn managed_account_backend_refuses_injected_authorization_and_headerless_transports() {
    let root = tempfile::TempDir::new().unwrap();
    let descriptors = managed_descriptor("work-gmail", "google");

    let injected = "backends:\n  gmail-backend:\n    \
         http_url: https://backend.example.invalid/mcp\n    \
         account: work-gmail\n    \
         secrets:\n      - name: injected-authz\n        value: \"env:INJECTED_AUTHZ\"\n        \
         inject_as: header\n        inject_key: authorization\n";
    let text = refusal_text(
        evaluate(root.path(), 18741, &descriptors, injected),
        "a managed account beside a rule injecting Authorization",
    );
    assert!(text.contains("injected-authz"), "names the rule: {text}");
    assert!(text.contains("Authorization"), "names the header: {text}");

    let stdio = "backends:\n  gmail-backend:\n    command: \"cat\"\n    account: work-gmail\n";
    let text = refusal_text(
        evaluate(root.path(), 18742, &descriptors, stdio),
        "a managed account on a transport that drops headers",
    );
    assert!(text.contains("per-request credential"), "{text}");

    // Positive control: the same account on a plain http backend loads.
    let plain = "backends:\n  gmail-backend:\n    \
         http_url: https://backend.example.invalid/mcp\n    account: work-gmail\n";
    evaluate(root.path(), 18743, &descriptors, plain).expect("a plain managed backend loads");
}

/// Mutant: binding a backend to an external descriptor with no strategy
/// compiles to an unpropagated backend instead of refusing.
#[test]
fn an_external_descriptor_without_a_strategy_cannot_be_bound() {
    // Parsed without the structural pass, so `compile` is the refusal under test.
    let yaml = "backends:\n  partner:\n    http_url: https://backend.example.invalid/mcp\n    \
         account: partner-api\n\
         accounts:\n  schema_version: accounts.v1\n  deployment: single_process\n  \
         instance_id: unit\n  store_dir: /unused/store\n  authority_dir: /unused/authority\n  \
         current_key_id: primary\n  keys:\n    primary: env:UNUSED\n  descriptors:\n    \
         partner-api:\n      mode: external\n      provider: partner\n";
    let config: Config = serde_yaml::from_str(yaml).expect("parses");
    let Err(error) = crate::config::account_bindings::compile(&config) else {
        panic!("a strategy-less external descriptor must refuse to bind");
    };
    assert!(
        error.to_string().contains("declares no external_strategy"),
        "{error}"
    );
}
