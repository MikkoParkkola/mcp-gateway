// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! START.10: startup names each static header a required binding's per-user
//! sessions leave off, per backend, and only for such backends.

use super::super::Config;

fn config(backends: &str) -> Config {
    crate::yaml::from_str(&format!("backends:\n{backends}")).expect("test config parses")
}

/// A backend on `url` with `required` and two static headers.
fn backend(name: &str, required: bool) -> String {
    format!(
        "  {name}:\n    http_url: https://{name}.example.test/mcp\n    headers:\n      \
         X-Tenant: acme\n      X-Static-Credential: placeholder\n    identity_propagation:\n      \
         strategy: signed_assertion\n      audience: https://{name}.example.test\n      \
         required: {required}\n      session_mode: per_user\n"
    )
}

#[test]
fn a_required_binding_names_every_static_header_it_leaves_off() {
    let warnings = config(&backend("api", true)).per_user_dropped_header_warnings();
    assert_eq!(
        warnings,
        [
            "backend 'api' has a required identity binding, so its per-user sessions send only \
          each user's own credential and leave off its static headers: X-Static-Credential, \
          X-Tenant. A shared session to it, where one exists, still sends them."
        ]
    );
    assert!(
        !warnings[0].contains("placeholder"),
        "a header's value is never logged"
    );
}

#[test]
fn an_optional_binding_keeps_its_headers_and_is_not_named() {
    assert!(
        config(&backend("api", false))
            .per_user_dropped_header_warnings()
            .is_empty()
    );
}

#[test]
fn a_required_binding_with_no_static_headers_is_not_named() {
    let yaml = "  api:\n    http_url: https://api.example.test/mcp\n    identity_propagation:\n      \
                strategy: signed_assertion\n      audience: https://api.example.test\n      \
                required: true\n      session_mode: per_user\n";
    assert!(config(yaml).per_user_dropped_header_warnings().is_empty());
}

#[test]
fn each_backend_gets_its_own_warning_in_name_order() {
    let warnings = config(&format!(
        "{}{}",
        backend("zeta", true),
        backend("alpha", true)
    ))
    .per_user_dropped_header_warnings();
    assert_eq!(warnings.len(), 2);
    assert!(warnings[0].starts_with("backend 'alpha'"), "{warnings:?}");
    assert!(warnings[1].starts_with("backend 'zeta'"), "{warnings:?}");
}

/// A backend bound to a `personal_managed` account runs with the required
/// binding that account compiles to, so its static headers are named too,
/// though its own config sets no `identity_propagation`.
#[test]
fn a_managed_account_backend_names_its_static_headers() {
    let config: Config = crate::yaml::from_str(
        "accounts:\n  schema_version: accounts.v1\n  enabled: true\n  \
         deployment: single_process\n  instance_id: gateway-test\n  \
         store_dir: /nonexistent/store\n  authority_dir: /nonexistent/authority\n  \
         current_key_id: current\n  keys:\n    current: env:UNSET_TEST_KEY\n  \
         descriptors:\n    work:\n      mode: personal_managed\n      \
         provider: gmail\n      resource: https://api.example.invalid/\n      \
         issuer: https://issuer.example.invalid\n      \
         authorization_endpoint: https://issuer.example.invalid/authorize\n      \
         token_endpoint: https://issuer.example.invalid/token\n      \
         client_id: synthetic-client-id\n      \
         redirect_uri: https://gateway.example.invalid/callback\n      \
         scopes:\n        - https://api.example.invalid/scope.read\n      \
         send_resource_parameter: true\n\
         backends:\n  mail:\n    http_url: https://mail.example.test/mcp\n    \
         account: work\n    headers:\n      X-Api-Key: placeholder\n",
    )
    .expect("test config parses");
    let bound = crate::config::account_bindings::compile(&config).expect("the binding compiles");
    assert!(
        bound["mail"]
            .propagation
            .as_ref()
            .is_some_and(|binding| binding.required),
        "premise: a personal_managed account compiles to a required binding"
    );
    let warnings = config.per_user_dropped_header_warnings();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("'mail'") && warnings[0].contains("X-Api-Key"),
        "{warnings:?}"
    );
}
