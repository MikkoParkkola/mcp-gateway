// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8044.SURF.2: one `mcp-gateway upgrade` turns a 3.x config into one that
//! loads. It hashes plaintext API keys and deletes the keys 4.0 removed. A key
//! it cannot change safely is named, and the exit status says the config still
//! will not load.
//!
//! Driven through the built binary: the rewrite, the save and the exit status
//! are wired in `main`, and only a real run observes all three.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};
use std::process::Output;

use mcp_gateway::config::{Config, api_key_digest_spec};
use mcp_gateway::gateway::auth::ResolvedAuthConfig;

const PLAINTEXT: &str = "surf2-plaintext-key-0123456789";

/// A data dir stamped with the running version, so no migration runs, and a
/// config file holding `yaml`.
struct Setup {
    dir: tempfile::TempDir,
    config: PathBuf,
}

fn setup(yaml: &str, stamp: &str) -> Setup {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("version.stamp"), stamp).expect("stamp");
    let config = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, yaml).expect("config");
    Setup { dir, config }
}

fn current() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn upgrade(s: &Setup, extra: &[&str]) -> Output {
    gateway_bin::command(s.dir.path(), gateway_bin::Inherit::Environment)
        .arg("--config")
        .arg(&s.config)
        .arg("upgrade")
        .args(extra)
        .arg("--data-dir")
        .arg(s.dir.path())
        .output()
        .expect("the upgrade command runs")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read config")
}

fn plaintext_config() -> String {
    format!(
        "auth:\n  enabled: true\n  api_keys:\n    - name: c1\n      key: \"{PLAINTEXT}\"\n      backends: [\"*\"]\n"
    )
}

/// T1, T4: a literal key becomes its digest, the file loads, the same key
/// still authenticates, and neither the key nor its digest is printed.
#[test]
fn upgrade_hashes_a_plaintext_api_key() {
    let s = setup(&plaintext_config(), current());
    let out = upgrade(&s, &[]);
    assert!(out.status.success(), "upgrade failed: {}", text(&out));
    let after = read(&s.config);
    let digest = api_key_digest_spec(PLAINTEXT.as_bytes());
    assert!(
        after.contains(&format!("key_sha256: \"{digest}\"")),
        "no digest in: {after}"
    );
    assert!(!after.contains(PLAINTEXT), "plaintext left in: {after}");
    let printed = text(&out);
    assert!(
        !printed.contains(PLAINTEXT) && !printed.contains(&digest),
        "upgrade printed the key or its digest: {printed}"
    );
    let config = Config::load(Some(&s.config)).expect("the upgraded config loads");
    let client = ResolvedAuthConfig::from_config(&config.auth)
        .validate_token(PLAINTEXT)
        .expect("the same key still authenticates");
    assert_eq!(client.name, "c1");
}

/// Runs `upgrade` on `before` and requires exactly `after` and a load.
fn upgrade_deletes(before: &str, after: &str) {
    let s = setup(before, current());
    let out = upgrade(&s, &[]);
    assert!(
        out.status.success(),
        "upgrade failed on {before:?}: {}",
        text(&out)
    );
    assert_eq!(read(&s.config), after, "upgrade of {before:?}");
    Config::load(Some(&s.config)).unwrap_or_else(|e| panic!("upgraded {before:?} must load: {e}"));
}

/// T6b: each removed key goes, every other byte stays.
#[test]
fn upgrade_deletes_backend_idle_timeout() {
    upgrade_deletes(
        "backends:\n  x:\n    command: y\n    idle_timeout: 10m\n",
        "backends:\n  x:\n    command: y\n",
    );
}

#[test]
fn upgrade_deletes_backend_circuit_breaker_block() {
    upgrade_deletes(
        "backends:\n  x:\n    command: y\n    circuit_breaker:\n      enabled: false\n    timeout: 5s\n",
        "backends:\n  x:\n    command: y\n    timeout: 5s\n",
    );
}

/// T6b, T7b: a column-0 comment after a removed block stays.
#[test]
fn upgrade_deletes_marketplace_block_and_keeps_the_next_comment() {
    upgrade_deletes(
        "marketplace:\n  marketplace_url: https://plugins.invalid\n  plugin_dir: /tmp/p\n# --- backends ---\nbackends: {}\n",
        "# --- backends ---\nbackends: {}\n",
    );
}

#[test]
fn upgrade_deletes_server_request_timeout() {
    upgrade_deletes(
        "server:\n  request_timeout: 30s\n  port: 39400\n",
        "server:\n  port: 39400\n",
    );
}

/// A key alone in its section takes the emptied section header with it.
#[test]
fn upgrade_deletes_server_ws_port_and_its_empty_section() {
    upgrade_deletes("server:\n  ws_port: 9000\nbackends: {}\n", "backends: {}\n");
}

#[cfg(feature = "cost-governance")]
#[test]
fn upgrade_deletes_cost_governance_currency() {
    upgrade_deletes(
        "cost_governance:\n  enabled: true\n  currency: USD  # label\n",
        "cost_governance:\n  enabled: true\n",
    );
}

/// T6d: `currency` alone in its section.
#[cfg(feature = "cost-governance")]
#[test]
fn upgrade_deletes_a_lone_currency_and_its_section() {
    upgrade_deletes(
        "cost_governance:\n  currency: USD\nbackends: {}\n",
        "backends: {}\n",
    );
}

/// T6c: every occurrence goes, not only the first.
#[test]
fn upgrade_deletes_idle_timeout_from_every_backend() {
    upgrade_deletes(
        "backends:\n  a:\n    command: y\n    idle_timeout: 1m\n  b:\n    command: z\n    idle_timeout: 2m\n",
        "backends:\n  a:\n    command: y\n  b:\n    command: z\n",
    );
}

/// A removed key the rewrite cannot prove safe to delete: flow style.
const FLOW_WS_PORT: &str = "server: {ws_port: 1, port: 39400}\n";

/// A plaintext key `upgrade` must never hash: it names an environment value.
const ENV_KEY: &str = "auth:\n  enabled: true\n  api_keys:\n    - name: c1\n      key: env:SURF2_K\n      backends: [\"*\"]\n";

/// Runs `upgrade` with `extra` on `yaml`, which keeps a key that blocks load,
/// and requires exit 1, `names` in the output, and (for dry runs and
/// unremovable keys) the file unchanged.
fn upgrade_refuses(yaml: &str, extra: &[&str], names: &[&str]) -> String {
    let s = setup(yaml, current());
    let out = upgrade(&s, extra);
    let printed = text(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{extra:?} on {yaml:?}: {printed}"
    );
    for name in names {
        assert!(printed.contains(name), "output must name {name}: {printed}");
    }
    assert!(printed.contains("will not load"), "{printed}");
    assert_eq!(read(&s.config), yaml, "the file must be unchanged");
    printed
}

/// T10a, T10b (quiet), T10f (dry run): an unremovable removed key.
#[test]
fn upgrade_exits_1_when_a_removed_key_stays() {
    upgrade_refuses(FLOW_WS_PORT, &[], &["server.ws_port"]);
    upgrade_refuses(FLOW_WS_PORT, &["--dry-run"], &["server.ws_port"]);
    upgrade_refuses(FLOW_WS_PORT, &["--quiet"], &[]);
    upgrade_refuses(FLOW_WS_PORT, &["--dry-run", "--quiet"], &[]);
}

/// T10e, T10f, T2: a key held in the environment is never hashed or read.
#[test]
fn upgrade_exits_1_on_a_plaintext_key_it_must_not_hash() {
    upgrade_refuses(ENV_KEY, &[], &["c1", "hash-key"]);
    upgrade_refuses(ENV_KEY, &["--dry-run"], &["c1", "hash-key"]);
}

/// T10c: `cache_tools` loads, so leaving it is not a failure.
#[test]
fn upgrade_exits_0_when_only_cache_tools_stays() {
    let yaml = "meta_mcp: {cache_tools: false, enabled: true}\n";
    let s = setup(yaml, current());
    let out = upgrade(&s, &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(read(&s.config), yaml);
}

/// T10d: the exit-1 path still stamps the version and runs the migrations.
#[test]
fn upgrade_exit_1_still_runs_the_migrations() {
    let s = setup(&format!("auth:\n  enabled: false\n{FLOW_WS_PORT}"), "2.0.0");
    let out = upgrade(&s, &[]);
    let printed = text(&out);
    assert_eq!(out.status.code(), Some(1), "{printed}");
    let stamp = std::fs::read_to_string(s.dir.path().join("version.stamp")).expect("stamp");
    assert_eq!(stamp.trim(), current(), "{printed}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("changes need your attention"),
        "{printed}"
    );
}

/// The 3.x config of T11: a plaintext key and three removed keys.
fn three_x_config() -> String {
    format!(
        "{}server:\n  ws_port: 9000\n  port: 39400\nmarketplace:\n  plugin_dir: /tmp/p\nbackends:\n  x:\n    command: y\n    idle_timeout: 10m\n",
        plaintext_config()
    )
}

/// T11: one `upgrade` makes a 3.x config load, in one write.
#[test]
fn one_upgrade_makes_a_three_x_config_load() {
    let s = setup(&three_x_config(), current());
    let out = upgrade(&s, &[]);
    assert!(out.status.success(), "{}", text(&out));
    Config::load(Some(&s.config)).expect("the upgraded 3.x config loads");
}

/// T9: a dry run writes nothing.
#[test]
fn a_dry_run_writes_nothing() {
    let yaml = three_x_config();
    let s = setup(&yaml, current());
    let out = upgrade(&s, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(read(&s.config), yaml);
}

/// An `auth.api_keys` list holding `entries`, indented as list items.
fn api_keys(entries: &str) -> String {
    format!("auth:\n  enabled: true\n  api_keys:\n{entries}")
}

/// T2: a key held in a file or built from a variable is never hashed or read.
#[test]
fn upgrade_leaves_file_and_variable_keys() {
    for value in ["file:/run/k", "\"a-${SURF2_K}\""] {
        upgrade_refuses(
            &api_keys(&format!(
                "    - name: c1\n      key: {value}\n      backends: [\"*\"]\n"
            )),
            &[],
            &["c1", "hash-key"],
        );
    }
}

/// T3: a key whose digest is already set loses its plaintext line only.
#[test]
fn upgrade_drops_a_key_whose_digest_is_set() {
    let digest = api_key_digest_spec(PLAINTEXT.as_bytes());
    upgrade_deletes(
        &api_keys(&format!(
            "    - name: c1\n      key: \"{PLAINTEXT}\"\n      key_sha256: \"{digest}\"\n      backends: [\"*\"]\n"
        )),
        &api_keys(&format!(
            "    - name: c1\n      key_sha256: \"{digest}\"\n      backends: [\"*\"]\n"
        )),
    );
}

/// T3, T3c: a digest that is not this key's, or one held in the environment,
/// is a conflict for the operator; the variable is never read.
#[test]
fn upgrade_leaves_a_key_beside_another_digest() {
    for digest in ["\"sha256:00\"", "env:SURF2_D"] {
        upgrade_refuses(
            &api_keys(&format!(
                "    - name: c1\n      key: \"{PLAINTEXT}\"\n      key_sha256: {digest}\n      backends: [\"*\"]\n"
            )),
            &[],
            &["c1", "hash-key"],
        );
    }
}

/// T3b: a key on a list item's first line keeps the item marker.
#[test]
fn upgrade_hashes_a_list_head_key_in_place() {
    let digest = api_key_digest_spec(PLAINTEXT.as_bytes());
    upgrade_deletes(
        &api_keys(&format!(
            "    - key: \"{PLAINTEXT}\"  # old\n      name: c1\n      backends: [\"*\"]\n"
        )),
        &api_keys(&format!(
            "    - key_sha256: \"{digest}\"\n      name: c1\n      backends: [\"*\"]\n"
        )),
    );
}

/// T3b: dropping a list item's first line would orphan the item, so it stays.
#[test]
fn upgrade_leaves_a_list_head_key_whose_digest_is_set() {
    let digest = api_key_digest_spec(PLAINTEXT.as_bytes());
    upgrade_refuses(
        &api_keys(&format!(
            "    - key: \"{PLAINTEXT}\"\n      key_sha256: \"{digest}\"\n      name: c1\n      backends: [\"*\"]\n"
        )),
        &[],
        &["c1"],
    );
}

/// T3 (P5): only the entry with a key changes, and escapes are decoded
/// before hashing.
#[test]
fn upgrade_hashes_the_decoded_key_of_one_entry() {
    let other = api_key_digest_spec(b"other");
    let digest = api_key_digest_spec("p\tq\u{e9}".as_bytes());
    let entry = |key: &str| {
        api_keys(&format!(
            "    - name: a\n      key_sha256: \"{other}\"\n      backends: [\"*\"]\n    - name: b\n      {key}\n      backends: [\"*\"]\n"
        ))
    };
    upgrade_deletes(
        &entry("key: \"p\\tq\\u00e9\""),
        &entry(&format!("key_sha256: \"{digest}\"")),
    );
}

/// T3 (P5): a key spread over several lines is left.
#[test]
fn upgrade_leaves_a_multi_line_key() {
    upgrade_refuses(
        &api_keys("    - name: c1\n      key: |\n        pt\n      backends: [\"*\"]\n"),
        &[],
        &["c1"],
    );
}

/// T7b: a comment after a removed key stays, byte for byte.
#[test]
fn upgrade_keeps_the_comment_after_a_removed_key() {
    upgrade_deletes(
        "server:\n  ws_port: 1\n  # the port we serve\n  port: 39400\n",
        "server:\n  # the port we serve\n  port: 39400\n",
    );
}

/// A mixed 3.x config: two literal keys and removable keys are fixed in one
/// write, the reference is named, the exit is 1, and a rerun changes nothing.
#[test]
fn a_mixed_config_keeps_its_fixes_and_names_what_is_left() {
    let yaml = format!(
        "{}server:\n  ws_port: 9000\n  port: 39400\nmarketplace:\n  plugin_dir: /tmp/p\n",
        api_keys(&format!(
            "    - name: c1\n      key: \"{PLAINTEXT}\"\n      backends: [\"*\"]\n    - name: c2\n      key: \"second-{PLAINTEXT}\"\n      backends: [\"*\"]\n    - name: c3\n      key: env:SURF2_K\n      backends: [\"*\"]\n"
        ))
    );
    let s = setup(&yaml, current());
    let out = upgrade(&s, &[]);
    let printed = text(&out);
    assert_eq!(out.status.code(), Some(1), "{printed}");
    assert!(
        printed.contains("c3") && printed.contains("hash-key"),
        "{printed}"
    );
    let after = read(&s.config);
    let expected = format!(
        "{}server:\n  port: 39400\n",
        api_keys(&format!(
            "    - name: c1\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n    - name: c2\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n    - name: c3\n      key: env:SURF2_K\n      backends: [\"*\"]\n",
            api_key_digest_spec(PLAINTEXT.as_bytes()),
            api_key_digest_spec(format!("second-{PLAINTEXT}").as_bytes()),
        ))
    );
    assert_eq!(after, expected);
    let again = upgrade(&s, &[]);
    assert_eq!(again.status.code(), Some(1), "{}", text(&again));
    assert_eq!(read(&s.config), expected, "a rerun changes nothing");
}

/// T2, T3c: a referent that exists and holds the key is still never read.
#[test]
fn upgrade_never_reads_an_existing_referent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = dir.path().join("key.txt");
    std::fs::write(&secret, PLAINTEXT).expect("secret file");
    let digest = api_key_digest_spec(PLAINTEXT.as_bytes());
    for value in [
        "env:SURF2_PRESENT".to_owned(),
        format!("file:{}", secret.display()),
    ] {
        let yaml = api_keys(&format!(
            "    - name: c1\n      key: {value}\n      backends: [\"*\"]\n"
        ));
        let s = setup(&yaml, current());
        let out = gateway_bin::command(s.dir.path(), gateway_bin::Inherit::Environment)
            .env("SURF2_PRESENT", PLAINTEXT)
            .env("SURF2_DIGEST", &digest)
            .arg("--config")
            .arg(&s.config)
            .arg("upgrade")
            .arg("--data-dir")
            .arg(s.dir.path())
            .output()
            .expect("the upgrade command runs");
        let printed = text(&out);
        assert_eq!(out.status.code(), Some(1), "{value}: {printed}");
        assert_eq!(read(&s.config), yaml, "{value}");
        assert!(
            !printed.contains(PLAINTEXT) && !printed.contains(&digest),
            "{printed}"
        );
    }
}

/// kimi impl r2: a file no YAML parse can read must never give exit 0 with
/// nothing reported; upgrade exits 1 and names the parse error.
#[test]
fn upgrade_exits_1_on_a_file_it_cannot_parse() {
    let yaml = "server:\n  port: [39400\n";
    let s = setup(yaml, current());
    let out = upgrade(&s, &[]);
    let printed = text(&out);
    assert_eq!(out.status.code(), Some(1), "{printed}");
    assert!(printed.contains("could not be read as YAML"), "{printed}");
    assert_eq!(read(&s.config), yaml);
}

/// kimi impl r2: a key the loader's map cannot hold (a number) does not hide
/// a removed key from upgrade.
#[test]
fn upgrade_removes_a_key_beside_a_numeric_key() {
    let s = setup(
        "x-notes:\n  5: five\nserver:\n  ws_port: 1\n  port: 39400\n",
        current(),
    );
    let out = upgrade(&s, &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        read(&s.config),
        "x-notes:\n  5: five\nserver:\n  port: 39400\n"
    );
}
