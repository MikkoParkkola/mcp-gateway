// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::Config;
use base64::Engine as _;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

const CURRENT_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=";
const RETIRED_B64: &str = "UlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlI=";
const DECOY_B64: &str = "U1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1M=";
const CURRENT_VAR: &str = "ACCOUNT_CURRENT_KEY";
const RETIRED_VAR: &str = "ACCOUNT_RETIRED_KEY";
const DECOY_VAR: &str = "ACCOUNT_DECOY_KEY";

fn decode_fixture(encoded: &str, fill: u8) -> Vec<u8> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("fixture key must be valid standard base64");
    assert_eq!(bytes.len(), 32);
    assert!(bytes.iter().all(|b| *b == fill));
    bytes
}

fn write_env(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("keys.env");
    fs::write(
        &path,
        format!(
            "{CURRENT_VAR}={CURRENT_B64}\n{RETIRED_VAR}={RETIRED_B64}\n{DECOY_VAR}={DECOY_B64}\n"
        ),
    )
    .unwrap();
    path
}

fn write_yaml(dir: &Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("config.yaml");
    fs::write(&path, body).unwrap();
    path
}

fn json_of(config: &Config) -> Value {
    serde_json::to_value(config).expect("Config must serialize")
}

#[test]
fn enabled_accounts_block_survives_evaluation_without_materializing_keys_or_dirs() {
    let current = decode_fixture(CURRENT_B64, 0x51);
    let retired = decode_fixture(RETIRED_B64, 0x52);
    let _decoy = decode_fixture(DECOY_B64, 0x53);

    let root = tempfile::TempDir::new().unwrap();
    let store_dir = root.path().join("store");
    let authority_dir = root.path().join("authority");
    let env_path = write_env(root.path());
    let config_path = write_yaml(
        root.path(),
        &format!(
            "env_files:\n  - {}\nserver:\n  port: 18481\naccounts:\n  schema_version: accounts.v1\n  enabled: true\n  deployment: single_process\n  instance_id: gateway-a\n  store_dir: {}\n  authority_dir: {}\n  current_key_id: current\n  keys:\n    current: env:{CURRENT_VAR}\n    retired: env:{RETIRED_VAR}\n  limits:\n    store_entries: 10000\n    authority_bytes: 16777216\n",
            env_path.display(),
            store_dir.display(),
            authority_dir.display(),
        ),
    );

    let evaluated = Config::load_evaluated(Some(&config_path)).expect("valid config must evaluate");
    assert_eq!(evaluated.config.server.port, 18481);

    let dumped = json_of(&evaluated.config);
    let accounts = dumped
        .get("accounts")
        .filter(|v| !v.is_null())
        .expect("enabled accounts block must survive Config parse/serialization");
    assert_eq!(accounts["schema_version"], "accounts.v1");
    assert_eq!(accounts["enabled"], true);
    assert_eq!(accounts["deployment"], "single_process");
    assert_eq!(accounts["instance_id"], "gateway-a");
    assert_eq!(accounts["store_dir"], store_dir.to_string_lossy().as_ref());
    assert_eq!(
        accounts["authority_dir"],
        authority_dir.to_string_lossy().as_ref()
    );
    assert_eq!(accounts["current_key_id"], "current");
    assert_eq!(accounts["limits"]["store_entries"], 10000);
    assert_eq!(accounts["limits"]["authority_bytes"], 16_777_216);
    assert_eq!(accounts["keys"]["current"], format!("env:{CURRENT_VAR}"));
    assert_eq!(accounts["keys"]["retired"], format!("env:{RETIRED_VAR}"));
    let serialized = dumped.to_string();
    assert!(!serialized.contains(CURRENT_B64));
    assert!(!serialized.contains(RETIRED_B64));
    assert!(!format!("{evaluated:?}").contains(CURRENT_B64));
    assert!(!format!("{evaluated:?}").contains(RETIRED_B64));

    assert_eq!(
        evaluated.secret_refs,
        BTreeSet::from([CURRENT_VAR.to_string(), RETIRED_VAR.to_string()])
    );
    assert_eq!(
        evaluated.overlay.resolve(CURRENT_VAR).as_deref(),
        Some(CURRENT_B64)
    );
    assert_eq!(
        evaluated.overlay.resolve(RETIRED_VAR).as_deref(),
        Some(RETIRED_B64)
    );
    assert_eq!(
        evaluated.overlay.resolve(DECOY_VAR).as_deref(),
        Some(DECOY_B64)
    );
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(evaluated.overlay.resolve(CURRENT_VAR).unwrap())
            .unwrap(),
        current
    );
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(evaluated.overlay.resolve(RETIRED_VAR).unwrap())
            .unwrap(),
        retired
    );
    assert!(!store_dir.exists());
    assert!(!authority_dir.exists());
}

#[test]
fn omitted_accounts_preserves_ordinary_evaluation() {
    let _current = decode_fixture(CURRENT_B64, 0x51);
    let _retired = decode_fixture(RETIRED_B64, 0x52);
    let _decoy = decode_fixture(DECOY_B64, 0x53);

    let root = tempfile::TempDir::new().unwrap();
    let store_dir = root.path().join("store");
    let authority_dir = root.path().join("authority");
    let env_path = write_env(root.path());
    let config_path = write_yaml(
        root.path(),
        &format!(
            "env_files:\n  - {}\nserver:\n  port: 18482\n",
            env_path.display()
        ),
    );

    let evaluated =
        Config::load_evaluated(Some(&config_path)).expect("ordinary config must evaluate");
    assert_eq!(evaluated.config.server.port, 18482);
    match json_of(&evaluated.config).get("accounts") {
        None | Some(Value::Null) => {}
        Some(other) => panic!("omitted accounts must stay absent/null, got {other}"),
    }
    assert!(!evaluated.secret_refs.contains(CURRENT_VAR));
    assert!(!evaluated.secret_refs.contains(RETIRED_VAR));
    assert!(!evaluated.secret_refs.contains(DECOY_VAR));
    assert_eq!(
        evaluated.overlay.resolve(CURRENT_VAR).as_deref(),
        Some(CURRENT_B64)
    );
    assert!(!store_dir.exists());
    assert!(!authority_dir.exists());
}

fn quoted_yaml_path(path: &Path) -> String {
    serde_json::to_string(&path.to_string_lossy().as_ref()).expect("path must JSON-quote")
}

fn write_sample_accounts(
    dir: &Path,
    port: u16,
    accounts_body: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let env_path = write_env(dir);
    let store_dir = dir.join("store");
    let authority_dir = dir.join("authority");
    let config_path = write_yaml(
        dir,
        &format!(
            "env_files:\n  - {}\nserver:\n  port: {port}\naccounts:\n  store_dir: {}\n  authority_dir: {}\n{accounts_body}",
            quoted_yaml_path(&env_path),
            quoted_yaml_path(&store_dir),
            quoted_yaml_path(&authority_dir),
        ),
    );
    (config_path, store_dir, authority_dir)
}

#[test]
fn partial_accounts_limits_preserve_unspecified_field_defaults() {
    let root = tempfile::TempDir::new().unwrap();
    let dir = root.path();
    let fixture_keys = format!(
        "  schema_version: accounts.v1\n  enabled: true\n  deployment: single_process\n  instance_id: gateway-a\n  current_key_id: current\n  keys:\n    current: env:{CURRENT_VAR}\n    retired: env:{RETIRED_VAR}\n"
    );

    let load_limits = |body: &str| {
        let (config_path, store_dir, authority_dir) = write_sample_accounts(dir, 18483, body);
        let evaluated = Config::load_evaluated(Some(&config_path))
            .expect("partial/omitted limits must evaluate");
        assert_eq!(evaluated.config.server.port, 18483);
        assert_eq!(
            evaluated.secret_refs,
            BTreeSet::from([CURRENT_VAR.to_string(), RETIRED_VAR.to_string()])
        );
        assert!(!store_dir.exists());
        assert!(!authority_dir.exists());
        json_of(&evaluated.config)["accounts"]["limits"].clone()
    };

    let store_only = load_limits(&format!(
        "{fixture_keys}  limits:\n    store_entries: 5000\n"
    ));
    assert_eq!(store_only["store_entries"], 5000);
    assert_eq!(store_only["authority_bytes"], 16_777_216);

    let authority_only = load_limits(&format!(
        "{fixture_keys}  limits:\n    authority_bytes: 65536\n"
    ));
    assert_eq!(authority_only["store_entries"], 10000);
    assert_eq!(authority_only["authority_bytes"], 65536);

    let omitted = load_limits(&fixture_keys);
    assert_eq!(omitted["store_entries"], 10000);
    assert_eq!(omitted["authority_bytes"], 16_777_216);

    let (bad_path, bad_store, bad_authority) = write_sample_accounts(
        dir,
        18483,
        &format!(
            "{fixture_keys}  limits:\n    store_entries: 10000\n    authority_bytes: 16777216\n    store_entires: 1\n"
        ),
    );
    let err =
        Config::load_evaluated(Some(&bad_path)).expect_err("unknown limits key must stay rejected");
    let err_text = err.to_string();
    assert!(
        err_text.contains("store_entires"),
        "deny_unknown_fields must survive defaulting, got {err_text}"
    );
    assert!(!bad_store.exists());
    assert!(!bad_authority.exists());
}

#[test]
fn disabled_accounts_preserve_ordinary_config_evaluation() {
    let root = tempfile::TempDir::new().unwrap();
    let dir = root.path();
    let missing_keys = "    current: env:ACCOUNT_KEY_ABSENT_FROM_ENV_FILES\n";

    let load_disabled = |port: u16, enabled_line: &str| {
        let (config_path, store_dir, authority_dir) = write_sample_accounts(
            dir,
            port,
            &format!(
                "  schema_version: accounts.v1\n{enabled_line}  deployment: single_process\n  instance_id: gateway-a\n  current_key_id: current\n  keys:\n{missing_keys}"
            ),
        );
        let evaluated = Config::load_evaluated(Some(&config_path))
            .expect("disabled accounts must not require custody or key material");
        assert_eq!(evaluated.config.server.port, port);
        let dumped = json_of(&evaluated.config);
        let accounts = dumped
            .get("accounts")
            .filter(|v| !v.is_null())
            .expect("disabled accounts block must survive Config parse/serialization");
        assert_eq!(accounts["enabled"], false);
        assert_eq!(
            accounts["keys"]["current"],
            "env:ACCOUNT_KEY_ABSENT_FROM_ENV_FILES"
        );
        assert!(!store_dir.exists());
        assert!(!authority_dir.exists());
    };

    load_disabled(18484, "  enabled: false\n");
    load_disabled(18485, "");

    let (schema_path, schema_store, schema_authority) = write_sample_accounts(
        dir,
        18486,
        &format!(
            "  schema_version: accounts.v0\n  enabled: false\n  deployment: single_process\n  instance_id: gateway-a\n  current_key_id: current\n  keys:\n{missing_keys}"
        ),
    );
    let schema_err = Config::load_evaluated(Some(&schema_path))
        .expect_err("wrong schema_version must reject before NotEnabled");
    assert!(
        schema_err
            .to_string()
            .contains("accounts.schema_version must be the literal accounts.v1"),
        "got {schema_err}"
    );
    assert!(!schema_store.exists());
    assert!(!schema_authority.exists());

    let (deploy_path, deploy_store, deploy_authority) = write_sample_accounts(
        dir,
        18487,
        &format!(
            "  schema_version: accounts.v1\n  enabled: false\n  deployment: multi_process\n  instance_id: gateway-a\n  current_key_id: current\n  keys:\n{missing_keys}"
        ),
    );
    let deploy_err = Config::load_evaluated(Some(&deploy_path))
        .expect_err("wrong deployment must reject before NotEnabled");
    assert!(
        deploy_err
            .to_string()
            .contains("accounts.deployment must be the literal single_process for managed custody"),
        "got {deploy_err}"
    );
    assert!(!deploy_store.exists());
    assert!(!deploy_authority.exists());
}

#[test]
fn legacy_secret_refs_and_port_zero_survive_alongside_account_key_references() {
    const BEARER_VAR: &str = "LEGACY_BEARER_TOKEN";
    const API_KEY_VAR: &str = "LEGACY_API_KEY";
    const AGENT_SECRET_VAR: &str = "LEGACY_AGENT_HS256";
    const ADMIN_TOKEN_VAR: &str = "LEGACY_ADMIN_TOKEN";
    const BEARER_VALUE: &str = "legacy-bearer-value-1";
    const API_KEY_VALUE: &str = "legacy-api-key-value-2";
    const AGENT_SECRET_VALUE: &str = "legacy-agent-hs256-value-3";
    const ADMIN_TOKEN_VALUE: &str = "legacy-admin-token-value-4";
    const LITERAL_API_KEY: &str = "literal-api-key-not-a-reference";

    let root = tempfile::TempDir::new().unwrap();
    let dir = root.path();
    let store_dir = dir.join("store");
    let authority_dir = dir.join("authority");

    let env_path = write_env(dir);
    let mut env_body = fs::read_to_string(&env_path).unwrap();
    let _ = write!(
        env_body,
        "{BEARER_VAR}={BEARER_VALUE}\n{API_KEY_VAR}={API_KEY_VALUE}\n{AGENT_SECRET_VAR}={AGENT_SECRET_VALUE}\n{ADMIN_TOKEN_VAR}={ADMIN_TOKEN_VALUE}\n"
    );
    fs::write(&env_path, env_body).unwrap();

    let config_path = write_yaml(
        dir,
        &format!(
            "env_files:\n  - {}\nserver:\n  port: 0\nauth:\n  bearer_token: env:{BEARER_VAR}\n  api_keys:\n    - key: env:{API_KEY_VAR}\n      name: ref-client\n    - key: {LITERAL_API_KEY}\n      name: literal-client\nagent_auth:\n  enabled: false\n  agents:\n    - client_id: agent-with-secret\n      name: Agent With Secret\n      hs256_secret: env:{AGENT_SECRET_VAR}\n    - client_id: agent-without-secret\n      name: Agent Without Secret\nkey_server:\n  enabled: false\n  admin_token: env:{ADMIN_TOKEN_VAR}\naccounts:\n  schema_version: accounts.v1\n  enabled: true\n  deployment: single_process\n  instance_id: gateway-a\n  store_dir: {}\n  authority_dir: {}\n  current_key_id: current\n  keys:\n    current: env:{CURRENT_VAR}\n    retired: env:{RETIRED_VAR}\n",
            quoted_yaml_path(&env_path),
            quoted_yaml_path(&store_dir),
            quoted_yaml_path(&authority_dir),
        ),
    );

    let evaluated = Config::load_evaluated(Some(&config_path))
        .expect("legacy secret refs plus account key refs must evaluate");

    // Port 0 stays a valid, preserved value (warning path, not a rejection).
    assert_eq!(evaluated.config.server.port, 0);
    let dumped = json_of(&evaluated.config);
    assert_eq!(dumped["server"]["port"], 0);

    // Each legacy `env:` slot is materialized to its own distinct value.
    assert_eq!(
        evaluated.config.auth.bearer_token.as_deref(),
        Some(BEARER_VALUE)
    );
    assert_eq!(evaluated.config.auth.api_keys[0].key, API_KEY_VALUE);
    assert_eq!(evaluated.config.auth.api_keys[1].key, LITERAL_API_KEY);
    assert_eq!(
        evaluated.config.agent_auth.agents[0]
            .hs256_secret
            .as_deref(),
        Some(AGENT_SECRET_VALUE)
    );
    assert!(evaluated.config.agent_auth.agents[1].hs256_secret.is_none());
    assert_eq!(
        evaluated.config.key_server.admin_token.as_deref(),
        Some(ADMIN_TOKEN_VALUE)
    );

    // Account keys are recorded by name only and stay `env:` references.
    let accounts = dumped
        .get("accounts")
        .filter(|v| !v.is_null())
        .expect("enabled accounts block must survive Config parse/serialization");
    assert_eq!(accounts["keys"]["current"], format!("env:{CURRENT_VAR}"));
    assert_eq!(accounts["keys"]["retired"], format!("env:{RETIRED_VAR}"));
    assert_eq!(
        evaluated.overlay.resolve(CURRENT_VAR).as_deref(),
        Some(CURRENT_B64)
    );
    assert_eq!(
        evaluated.overlay.resolve(RETIRED_VAR).as_deref(),
        Some(RETIRED_B64)
    );

    assert_eq!(
        evaluated.secret_refs,
        BTreeSet::from([
            ADMIN_TOKEN_VAR.to_string(),
            AGENT_SECRET_VAR.to_string(),
            API_KEY_VAR.to_string(),
            BEARER_VAR.to_string(),
            CURRENT_VAR.to_string(),
            RETIRED_VAR.to_string(),
        ])
    );
    assert!(!evaluated.secret_refs.contains(DECOY_VAR));
    assert_eq!(
        evaluated.overlay.resolve(DECOY_VAR).as_deref(),
        Some(DECOY_B64)
    );

    assert!(!store_dir.exists());
    assert!(!authority_dir.exists());
}

#[test]
fn overlay_debug_keeps_metadata_and_redacts_secret_values() {
    let dir = tempfile::tempdir().expect("tempdir must be created");
    let env_path = write_env(dir.path());
    let config_path = write_yaml(
        dir.path(),
        &format!(
            "server:\n  port: 8081\nenv_files:\n  - {}\n",
            env_path.to_str().expect("env path must be UTF-8")
        ),
    );

    let evaluated =
        Config::load_evaluated(Some(&config_path)).expect("config with env_files must evaluate");

    // Control: the overlay really does carry the secret, so the redaction below is meaningful.
    assert_eq!(
        evaluated.overlay.resolve(CURRENT_VAR).as_deref(),
        Some(CURRENT_B64),
        "fixture must actually contain the current key"
    );

    let rendered = format!("{:?}", evaluated.overlay);

    assert!(
        rendered.contains("EnvOverlay"),
        "diagnostics must identify the overlay type: {rendered}"
    );
    for name in [CURRENT_VAR, RETIRED_VAR, DECOY_VAR] {
        assert!(
            rendered.contains(name),
            "diagnostics must retain owned variable name {name}: {rendered}"
        );
    }
    assert!(
        rendered.contains("var_count: 3"),
        "diagnostics must report the three variables: {rendered}"
    );
    assert!(
        rendered.contains("source_count: 1"),
        "diagnostics must report the single source file: {rendered}"
    );

    for secret in [CURRENT_B64, RETIRED_B64, DECOY_B64] {
        assert!(
            !rendered.contains(secret),
            "diagnostics must never emit an overlay secret value: {rendered}"
        );
    }
    assert!(
        !rendered.contains(&format!("{CURRENT_VAR}=")),
        "diagnostics must never emit raw dotenv assignment text: {rendered}"
    );
}
