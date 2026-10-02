// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adapter-runtime and descriptor refusals, split out of `config_tests.rs` to
//! keep both files under the size ceiling.

use super::*;

const ADAPTER_VAR: &str = "MCP_ACCOUNTS_ADAPTER_SECRET";
const ADAPTER_SECRET: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

fn adapter_overlay() -> CountingOverlay {
    CountingOverlay::new(&[
        (KEY_VAR, KEY_B64),
        (RETIRED_VAR, RETIRED_KEY_B64),
        (ADAPTER_VAR, ADAPTER_SECRET),
    ])
}

fn with_adapter(accounts: AccountsConfig, variable: &str) -> AccountsConfig {
    AccountsConfig {
        adapters: vec![AdapterConfig {
            kind: adapters::AdapterKind::OpenwebuiSignedHeader,
            installation_id: "desk".into(),
            header: "X-OpenWebUI-Assertion".into(),
            issuer: "open-webui".into(),
            hmac_secret_ref: format!("env:{variable}"),
            allowed_api_key_names: vec!["desktop".into()],
            max_lifetime_seconds: 300,
            clock_skew_seconds: 30,
            session: None,
        }],
        ..accounts
    }
}

#[test]
fn adapter_runtime_reads_nothing_when_no_adapter_is_configured() {
    let tmp = root();
    let env = adapter_overlay();
    let none = resolve_adapter_runtime(None, &env, &[]).expect("no accounts block");
    assert!(none.is_empty());
    let empty = resolve_adapter_runtime(Some(&valid(tmp.path())), &env, &[]).expect("no adapter");
    assert!(empty.is_empty());
    assert!(env.lookups().is_empty(), "nothing is configured to read");
}

#[test]
fn adapter_runtime_refuses_a_wrong_schema_or_deployment_before_reading_anything() {
    let tmp = root();
    let env = adapter_overlay();
    let good = with_adapter(valid(tmp.path()), ADAPTER_VAR);

    let control = resolve_adapter_runtime(Some(&good), &env, &[]).expect("valid adapter block");
    assert_eq!(control.len(), 1);
    assert_eq!(control[0].installation_id, "desk");
    assert_eq!(control[0].secret, ADAPTER_SECRET.as_bytes());
    let reads_for_control = env.lookups().len();
    assert!(reads_for_control > 0);

    let schema = AccountsConfig {
        schema_version: "accounts.v0".into(),
        ..good.clone()
    };
    assert_eq!(
        domain_err(resolve_adapter_runtime(Some(&schema), &env, &[]), "schema"),
        AccountsConfigError::SchemaVersion
    );
    let deployment = AccountsConfig {
        deployment: "multi_process".into(),
        ..good
    };
    assert_eq!(
        domain_err(
            resolve_adapter_runtime(Some(&deployment), &env, &[]),
            "deployment"
        ),
        AccountsConfigError::Deployment
    );
    assert_eq!(
        env.lookups().len(),
        reads_for_control,
        "a refused block must not read a single secret"
    );
}

#[test]
fn adapter_runtime_refuses_a_literal_store_key_without_an_overlay_read() {
    let tmp = root();
    let env = adapter_overlay();
    let mut config = with_adapter(valid(tmp.path()), ADAPTER_VAR);
    config.keys.insert("current".into(), KEY_B64.into());

    assert_eq!(
        domain_err(
            resolve_adapter_runtime(Some(&config), &env, &[]),
            "literal key"
        ),
        AccountsConfigError::KeyNotAReference {
            key_id: "current".into()
        }
    );
    assert!(
        !env.lookups().iter().any(|name| name == KEY_B64)
            && !env.references().iter().any(|r| r == KEY_B64),
        "the literal is never resolved"
    );
}

#[test]
fn resolve_refuses_an_unresolvable_adapter_secret_after_the_store_keys() {
    let tmp = root();
    let missing = with_adapter(valid(tmp.path()), "MCP_ACCOUNTS_ABSENT_ADAPTER");
    assert_eq!(
        domain_err(resolve(Some(&missing), &adapter_overlay()), "absent secret"),
        AccountsConfigError::AdapterSecretUnresolved {
            index: 0,
            variable: "MCP_ACCOUNTS_ABSENT_ADAPTER".into()
        }
    );

    let present = with_adapter(valid(tmp.path()), ADAPTER_VAR);
    let resolved = resolve(Some(&present), &adapter_overlay())
        .expect("resolves")
        .expect("enabled block");
    assert!(resolved.secret_refs_read.contains(&ADAPTER_VAR.to_string()));
}

fn with_descriptor(id: &str, yaml: &str) -> AccountsConfig {
    let tmp = root();
    let descriptor: AccountDescriptor = serde_yaml::from_str(yaml).expect("descriptor parses");
    AccountsConfig {
        descriptors: Some(BTreeMap::from([(id.to_owned(), descriptor)])),
        ..valid(tmp.path())
    }
}

const EXTERNAL: &str = "mode: external\nprovider: p\nexternal_strategy:\n  strategy: signed_assertion\n  audience: https://x.example.invalid/\n  session_mode: stateless\n  required: true\n";

/// Mutant: an empty account id or provider is accepted, or the external
/// strategy is forbidden-checks removed so a mode the operator did not declare
/// runs under a strategy block.
#[test]
fn descriptor_identity_and_strategy_placement_are_refused() {
    let problem = |accounts: &AccountsConfig| match validate_descriptors(Some(accounts)) {
        Err(AccountsConfigError::Descriptor { problem, .. }) => problem,
        other => panic!("expected a descriptor refusal, got {other:?}"),
    };
    assert_eq!(
        problem(&with_descriptor("", "mode: shared\nprovider: p\n")),
        "account id must be nonempty"
    );
    assert_eq!(
        problem(&with_descriptor("a", "mode: shared\nprovider: \"\"\n")),
        "provider must be nonempty"
    );
    let strategy = EXTERNAL.split_once("external_strategy").unwrap().1;
    let managed = "mode: personal_managed\nprovider: p\nresource: https://api.fixture.test/\n\
        issuer: https://issuer.fixture.test\n\
        authorization_endpoint: https://issuer.fixture.test/authorize\n\
        token_endpoint: https://issuer.fixture.test/token\nclient_id: c\n\
        redirect_uri: https://gateway.fixture.test/callback\nscopes: [read]\n\
        send_resource_parameter: true\n";
    validate_descriptors(Some(&with_descriptor("a", managed)))
        .expect("control: a complete managed descriptor is accepted");
    assert_eq!(
        problem(&with_descriptor(
            "a",
            &format!("{managed}external_strategy{strategy}")
        )),
        "external_strategy is valid only on mode external"
    );
    let shared = format!("mode: shared\nprovider: p\nexternal_strategy{strategy}");
    assert_eq!(
        problem(&with_descriptor("a", &shared)),
        "external_strategy is valid only on mode external"
    );
    // Positive control: the same block on mode external is accepted.
    validate_descriptors(Some(&with_descriptor("a", EXTERNAL))).expect("external accepts it");
}

/// Mutant: an external descriptor without a strategy, with a non-minting one,
/// without `required`, or with an invalid block is accepted.
#[test]
fn an_external_descriptor_needs_a_minting_required_valid_strategy() {
    let refused = |yaml: &str| validate_descriptors(Some(&with_descriptor("a", yaml)));
    assert!(matches!(
        refused("mode: external\nprovider: p\n"),
        Err(AccountsConfigError::Descriptor { .. })
    ));
    for kind in ["vault", "passthrough"] {
        let yaml = EXTERNAL.replace("signed_assertion", kind);
        assert!(
            matches!(refused(&yaml), Err(AccountsConfigError::Descriptor { .. })),
            "{kind}"
        );
    }
    let optional = EXTERNAL.replace("required: true", "required: false");
    assert!(matches!(
        refused(&optional),
        Err(AccountsConfigError::Descriptor { .. })
    ));
    let exchange = EXTERNAL.replace("signed_assertion", "token_exchange");
    assert!(
        matches!(
            refused(&exchange),
            Err(AccountsConfigError::DescriptorStrategy { .. })
        ),
        "token_exchange without an endpoint fails the strategy's own validation"
    );
    assert!(refused(EXTERNAL).is_ok());
    let with_endpoint =
        format!("{exchange}  token_exchange_endpoint: https://issuer.fixture.test/exchange\n");
    assert!(
        refused(&with_endpoint).is_ok(),
        "token_exchange with its endpoint"
    );
}
