// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adapter and gateway authentication material kept apart, in validation and in `Config::load_evaluated`.

use super::*;

// ── Gateway authentication separation, through the public API ─────────────────
//
// The fixtures above are all `enabled: false`, so the MATERIAL half of the
// approved "reject secret reuse with gateway authentication" rule is unreachable
// from them (see the module docs). The cases below close exactly that gap and
// nothing more:
//
//   * the store is `enabled: true`, so secrets are actually resolved;
//   * material reaches the load through an `env_files` overlay written into a
//     temporary directory — NO test here reads, sets or mutates a process
//     environment variable, and every value is obvious fixture filler, never a
//     real credential;
//   * the adapter and the gateway API key name TWO DIFFERENT variables holding
//     the SAME value, which is precisely the case a reference-name comparison
//     cannot see.
//
// Still configuration only: no server starts, no custody opens, and the
// directories below are deliberately never created.

/// Fixture filler, 32 ASCII bytes. Not a credential and not random: these tests
/// assert comparison behaviour, and randomness is a property of the operator's
/// secret, not of this file.
fn filler_32(tag: char) -> String {
    std::iter::repeat_n(tag, 32).collect()
}

/// Base64 of 32 bytes, the shape `accounts.keys` requires.
fn store_key_b64(byte: u8) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([byte; 32])
}

/// Adapter secret and API key digest via `env_files`; `gateway_key` decides a collision.
fn enabled_store_yaml(dir: &std::path::Path, adapter_secret: &str, gateway_key: &str) -> String {
    let env_path = dir.join("adapter-separation.env");
    write_owner_only(
        &env_path,
        format!(
            "OWUI_SEP_STORE_KEY={}\nOWUI_SEP_ADAPTER_HMAC={adapter_secret}\n\
             OWUI_SEP_GATEWAY_KEY={}\n",
            store_key_b64(0x41),
            mcp_gateway::config::api_key_digest_spec(gateway_key.as_bytes())
        ),
    )
    .expect("fixture env file must be writable");
    format!(
        "\
env_files:
  - {}
server:
  port: 18777
security:
  transparency_log:
    enabled: true
auth:
  enabled: true
  api_keys:
    - name: owui-gateway-key
      key_sha256: env:OWUI_SEP_GATEWAY_KEY
accounts:
  schema_version: accounts.v1
  enabled: true
  deployment: single_process
  instance_id: openwebui-adapter-separation
  store_dir: {1}/store
  authority_dir: {1}/authority
  current_key_id: primary
  keys:
    primary: env:OWUI_SEP_STORE_KEY
  adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_SEP_ADAPTER_HMAC
      allowed_api_key_names:
        - owui-gateway-key
",
        env_path.display(),
        dir.display(),
    )
}

/// Two DIFFERENT variables holding the SAME value are one secret, and the public
/// validation entry point must refuse it.
///
/// This is the case the structural reference check provably cannot catch: the
/// two references are textually distinct. A gateway whose adapter signing key is
/// also its API key has one trust domain where the approved contract requires
/// two — an assertion could then be minted by anyone holding the API key.
#[test]
fn different_references_holding_the_same_material_are_refused_by_validate_with_env() {
    let shared = filler_32('g');
    let dir = tempfile::TempDir::new().expect("temp dir");
    let yaml = enabled_store_yaml(dir.path(), &shared, &shared);

    let config: Config =
        serde_yaml::from_str(&yaml).unwrap_or_else(|error| panic!("fixture must parse: {error}"));
    let error = config
        .validate_with_env(&config.env_overlay())
        .expect_err("an adapter secret equal to a gateway api key must be refused");

    let rendered = error.to_string();
    let lower = rendered.to_lowercase();
    assert!(
        lower.contains("adapters[0]") && lower.contains("hmac_secret_ref"),
        "refusal must name the offending adapter and field: {rendered}"
    );
    assert!(
        lower.contains("gateway") && lower.contains("auth.api_keys[0]"),
        "refusal must name the gateway credential it collides with: {rendered}"
    );
    assert!(
        !rendered.contains(&shared) && !rendered.contains(&store_key_b64(0x41)),
        "refusal must name configuration coordinates, never secret material: {rendered}"
    );
}

/// The positive control for the case above: the SAME enabled-store fixture with
/// distinct material is accepted.
///
/// Without this, the refusal above could be caused by anything else in an
/// enabled block — a store key, a directory, the overlay — rather than by the
/// reuse it claims to be about.
#[test]
fn distinct_adapter_and_gateway_material_is_accepted_by_validate_with_env() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let yaml = enabled_store_yaml(dir.path(), &filler_32('a'), &filler_32('b'));

    let config: Config =
        serde_yaml::from_str(&yaml).unwrap_or_else(|error| panic!("fixture must parse: {error}"));
    config
        .validate_with_env(&config.env_overlay())
        .unwrap_or_else(|error| {
            panic!("separated adapter and gateway material must be accepted: {error}")
        });
}

/// One variable named by BOTH an adapter and a gateway credential is refused
/// even with the store disabled.
///
/// This is the structural half reaching the public API: an operator who wires
/// one variable into both places must learn at load time, not on the day they
/// enable the store. The store stays `enabled: false`, so no store key is
/// resolved; the aliased variable itself must exist, because gateway auth
/// validation resolves `auth.bearer_token` before the adapter rules run, and a
/// missing variable would fail the fixture for an unrelated reason. It is
/// supplied by a temporary `env_files` overlay holding synthetic 32-byte
/// material — the process environment is never mutated.
#[test]
fn one_variable_named_by_both_an_adapter_and_a_bearer_token_is_refused_while_disabled() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let env_path = dir.path().join("adapter-alias.env");
    let aliased = filler_32('z');
    write_owner_only(&env_path, format!("OWUI_SEP_ALIASED={aliased}\n"))
        .expect("fixture env file must be writable");

    let yaml = format!(
        "\
env_files:
  - {}
server:
  port: 18778
security:
  transparency_log:
    enabled: true
auth:
  enabled: true
  bearer_token: env:OWUI_SEP_ALIASED
{}",
        env_path.display(),
        config_yaml(
            "\
\x20 adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_SEP_ALIASED
      allowed_api_key_names:
        - owui-gateway-key
"
        )
    );

    let config: Config =
        serde_yaml::from_str(&yaml).unwrap_or_else(|error| panic!("fixture must parse: {error}"));
    let error = config
        .validate_with_env(&config.env_overlay())
        .expect_err("one variable named in both places is one secret");

    let lower = error.to_string().to_lowercase();
    assert!(
        lower.contains("adapters[0]") && lower.contains("auth.bearer_token"),
        "refusal must name both sides of the alias: {error}"
    );
}

// ── The SHIPPED load path, not just the validation entry point ────────────────
//
// The three cases above drive `serde_yaml::from_str` + `validate_with_env`
// directly. That composition is NOT what a gateway runs: `Config::load_evaluated`
// resolves `env:` secret references INTO the config — inlining
// `auth.bearer_token` and `auth.api_keys[].key_sha256` — and only then validates. On
// that path the structural alias check was handed a gateway credential that no
// longer said `env:` anything, so it matched nothing; and with the store
// disabled the material half is skipped by design. One variable named by both an
// adapter and a gateway credential was therefore accepted in silence by the only
// entry point that actually loads a gateway.
//
// The tests below go through `Config::load_evaluated` against a real file, which
// is the only way to exercise that ordering. Neither of them mutates the process
// environment: material arrives through an `env_files` overlay in a temporary
// directory, and every value is obvious filler.

/// Write a config file and the env file it declares, returning the config path.
///
/// `store_dir`/`authority_dir` are deliberately never created: this is still
/// configuration only, and nothing here opens custody.
fn write_load_fixture(
    dir: &std::path::Path,
    bearer_ref: &str,
    adapter_ref: &str,
    env_body: &str,
) -> std::path::PathBuf {
    let env_path = dir.join("adapter-load.env");
    write_owner_only(&env_path, env_body).expect("fixture env file must be writable");

    let config_path = dir.join("config.yaml");
    write_owner_only(
        &config_path,
        format!(
            "\
env_files:
  - {}
server:
  port: 18779
security:
  transparency_log:
    enabled: true
auth:
  enabled: true
  bearer_token: {bearer_ref}
accounts:
  schema_version: accounts.v1
  enabled: false
  deployment: single_process
  instance_id: openwebui-adapter-load-order
  store_dir: /var/lib/mcp-gateway/accounts/store
  authority_dir: /var/lib/mcp-gateway/accounts/authority
  current_key_id: primary
  keys:
    primary: env:OWUI_LOAD_STORE_KEY
  adapters:
    - kind: openwebui_signed_header
      installation_id: owui-prod-1
      header: X-OpenWebUI-Assertion
      issuer: open-webui
      hmac_secret_ref: {adapter_ref}
      allowed_api_key_names:
        - owui-gateway-key
",
            env_path.display(),
        ),
    )
    .expect("fixture config must be writable");
    config_path
}

/// THE REGRESSION. One variable named by both the adapter and the bearer token
/// must be refused by `Config::load_evaluated` even with the store disabled.
///
/// This fails on a load path that inlines the bearer token before running the
/// structural separation check, because by then `auth.bearer_token` holds
/// filler text rather than `env:OWUI_LOAD_ALIASED` and the two references
/// cannot be compared as references. The disabled store means the material
/// comparison — the only other thing that could catch it — does not run, so
/// nothing else stands behind this.
#[test]
fn load_evaluated_refuses_one_variable_shared_by_an_adapter_and_the_bearer_token() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let aliased = filler_32('z');
    let config_path = write_load_fixture(
        dir.path(),
        "env:OWUI_LOAD_ALIASED",
        "env:OWUI_LOAD_ALIASED",
        &format!(
            "OWUI_LOAD_STORE_KEY={}\nOWUI_LOAD_ALIASED={aliased}\n",
            store_key_b64(0x41),
        ),
    );

    let error = Config::load_evaluated(Some(&config_path))
        .expect_err("one variable named by both an adapter and gateway auth is one secret");

    let rendered = error.to_string();
    let lower = rendered.to_lowercase();
    assert!(
        lower.contains("adapters[0]") && lower.contains("auth.bearer_token"),
        "refusal must name both sides of the alias: {rendered}"
    );
    assert!(
        !rendered.contains(&aliased),
        "refusal must name configuration coordinates, never secret material: {rendered}"
    );
}

/// The positive control for the case above, through the SAME load path: two
/// DISTINCT references are accepted, the adapter reference survives as a
/// reference, and the variable it names is reported among the secret references.
///
/// Without this, the refusal above could be caused by anything the load path
/// does with an `accounts` block rather than by the alias it claims to be about.
/// The `secret_refs` assertion is the second half: an adapter secret is a
/// startup-only secret exactly like an account key, so a reload comparing those
/// names across overlays must be able to see it rotate.
#[test]
fn load_evaluated_accepts_distinct_references_and_reports_the_adapter_variable() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let config_path = write_load_fixture(
        dir.path(),
        "env:OWUI_LOAD_BEARER",
        "env:OWUI_LOAD_ADAPTER_HMAC",
        &format!(
            "OWUI_LOAD_STORE_KEY={}\nOWUI_LOAD_BEARER={}\nOWUI_LOAD_ADAPTER_HMAC={}\n",
            store_key_b64(0x41),
            filler_32('b'),
            filler_32('a'),
        ),
    );

    let evaluated = Config::load_evaluated(Some(&config_path))
        .unwrap_or_else(|error| panic!("separated references must load: {error}"));

    assert!(
        evaluated.secret_refs.contains("OWUI_LOAD_ADAPTER_HMAC"),
        "the adapter signing variable must be reported as a secret reference: {:?}",
        evaluated.secret_refs
    );
    assert!(
        evaluated.secret_refs.contains("OWUI_LOAD_BEARER"),
        "the existing gateway reference must still be reported: {:?}",
        evaluated.secret_refs
    );

    let dumped: serde_yaml::Value =
        serde_yaml::to_value(&evaluated.config).expect("loaded config must re-serialize");
    let hmac_ref = dumped["accounts"]["adapters"][0]["hmac_secret_ref"]
        .as_str()
        .expect("adapter reference must survive the load");
    assert_eq!(
        hmac_ref, "env:OWUI_LOAD_ADAPTER_HMAC",
        "an adapter secret reference must stay a reference, never be inlined"
    );
    assert!(
        !serde_yaml::to_string(&dumped)
            .expect("re-serialize")
            .contains(&filler_32('a')),
        "a rewrite must not carry adapter signing material"
    );
}
