// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which 3.x backend a migration reads: only an unambiguous one, or the one the
//! operator named.

use super::{OfflineMigrationError, resolve_legacy_backend_name};

fn config(backends: &[(&str, &str)]) -> crate::config::Config {
    let bound: String = backends
        .iter()
        .map(|(name, account)| {
            format!(
                "  {name}:\n    http_url: https://backend.fixture.test/mcp\n    account: {account}\n"
            )
        })
        .collect();
    let described: String = ["work", "home"]
        .iter()
        .map(|account| {
            format!(
                "    {account}:\n      mode: personal_managed\n      provider: fixture\n      \
                 resource: https://api.fixture.test/\n      issuer: https://issuer.fixture.test\n      \
                 authorization_endpoint: https://issuer.fixture.test/authorize\n      \
                 token_endpoint: https://issuer.fixture.test/token\n      client_id: c\n      \
                 redirect_uri: https://gateway.fixture.test/callback\n      scopes: [read]\n      \
                 send_resource_parameter: true\n"
            )
        })
        .collect();
    let yaml = format!(
        "backends:\n{bound}accounts:\n  schema_version: accounts.v1\n  enabled: true\n  \
         deployment: single_process\n  instance_id: unit\n  store_dir: /unused/store\n  \
         authority_dir: /unused/authority\n  current_key_id: primary\n  keys:\n    \
         primary: env:UNUSED\n  descriptors:\n{described}"
    );
    serde_yaml::from_str(&yaml).expect("config parses")
}

/// Mutant: with no bound backend, or two, the migration guesses a 3.x file and
/// moves one backend's credential onto another's account.
#[test]
fn a_legacy_backend_is_named_only_when_it_is_the_one_bound_or_the_operator_said() {
    let config = config(&[("mail", "work"), ("files", "work"), ("notes", "home")]);
    assert_eq!(
        resolve_legacy_backend_name(&config, "home", None).as_deref(),
        Ok("notes"),
        "control: exactly one backend is bound"
    );
    assert!(matches!(
        resolve_legacy_backend_name(&config, "absent", None),
        Err(OfflineMigrationError::NoBoundBackend(id)) if id == "absent"
    ));
    assert!(matches!(
        resolve_legacy_backend_name(&config, "work", None),
        Err(OfflineMigrationError::AmbiguousBackend { count: 2, .. })
    ));
    assert_eq!(
        resolve_legacy_backend_name(&config, "work", Some("mail")).as_deref(),
        Ok("mail"),
        "the operator's name settles the ambiguity"
    );
}
