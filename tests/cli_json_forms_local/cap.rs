// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! JSON forms of the cap commands (J7-J11, F), a part of cli_json_forms_local split out under the file-size
//! ceiling: the same binary, helpers and literal expectations.

use super::{Path, Value, document, json, run};

/// One capability file `dir/<name>.yaml`: a REST provider, `auth` when `key_var` is given.
fn capability(dir: &Path, name: &str, description: &str, key_var: Option<&str>, tags: &[&str]) {
    let auth = key_var.map_or_else(String::new, |var| {
        format!("auth:\n  required: true\n  type: bearer\n  key: \"env:{var}\"\n")
    });
    let tags = tags
        .iter()
        .map(|t| format!("\"{t}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let yaml = format!(
        "name: {name}\ndescription: {description}\nproviders:\n  primary:\n    service: rest\n    config:\n      \
         base_url: https://api.example.test\n      path: /v1/{name}\n      method: GET\n{auth}\
         metadata:\n  tags: [{tags}]\n"
    );
    std::fs::write(dir.join(format!("{name}.yaml")), yaml).expect("capability");
}

/// A config whose env file holds `GAMMA_CAP_KEY` only.
fn cap_config(root: &Path) -> std::path::PathBuf {
    let env_file = root.join("keys.env");
    mcp_gateway::gateway::test_helpers::write_owner_only(&env_file, "GAMMA_CAP_KEY=present\n")
        .expect("env file");
    let config = root.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config,
        format!(
            "env_files:\n  - '{}'\n",
            env_file.display().to_string().replace('\'', "''")
        ),
    )
    .expect("config");
    config
}

fn list_cap(
    name: &str,
    description: &str,
    auth_type: Option<&str>,
    missing: Option<&str>,
) -> Value {
    json!({"name": name, "description": description, "auth_type": auth_type, "missing_credential": missing})
}

#[test]
fn cap_list_prints_one_document_and_keeps_its_text() {
    let root = tempfile::tempdir().expect("root");
    let caps = root.path().join("caps");
    std::fs::create_dir_all(&caps).expect("caps");
    capability(&caps, "alpha_cap", "Alpha", Some("ALPHA_CAP_KEY"), &[]);
    capability(&caps, "beta_cap", "Beta", None, &[]);
    capability(&caps, "gamma_cap", "Gamma", Some("GAMMA_CAP_KEY"), &[]);
    let config = cap_config(root.path());
    let (config, caps) = (
        config.to_str().expect("utf-8"),
        caps.to_str().expect("utf-8"),
    );

    // The loader lists in directory-read order, which differs between filesystems: lines and items are compared as
    // sets, and the document must keep the text form's order.
    let plain = run(root.path(), &["--config", config, "cap", "list", caps], b"");
    assert_eq!(plain.code, Some(0), "{}", plain.stderr);
    let header = format!("Found 3 capabilities in {caps}:\n\n");
    let listed = plain
        .stdout
        .strip_prefix(header.as_str())
        .unwrap_or_else(|| panic!("header: {:?}", plain.stdout));
    let mut lines: Vec<&str> = listed.lines().collect();
    let text_order: Vec<String> = lines
        .iter()
        .map(|l| l.trim_start().split(' ').next().unwrap_or("").to_owned())
        .collect();
    lines.sort_unstable();
    assert_eq!(
        lines,
        [
            "  alpha_cap - Alpha [bearer] off: needs ALPHA_CAP_KEY",
            "  beta_cap - Beta",
            "  gamma_cap - Gamma [bearer]",
        ]
    );
    let json = run(
        root.path(),
        &["--config", config, "cap", "list", caps, "--json"],
        b"",
    );
    let mut doc = document(&json);
    let json_order: Vec<String> = doc["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .map(|c| c["name"].as_str().unwrap_or("").to_owned())
        .collect();
    assert_eq!(
        json_order, text_order,
        "the document keeps the text form's order"
    );
    doc["capabilities"]
        .as_array_mut()
        .expect("capabilities")
        .sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    assert_eq!(
        doc,
        json!({"schema_version": 1, "directory": caps, "capabilities": [
            list_cap("alpha_cap", "Alpha", Some("bearer"), Some("ALPHA_CAP_KEY")),
            list_cap("beta_cap", "Beta", None, None),
            list_cap("gamma_cap", "Gamma", Some("bearer"), None),
        ]})
    );
    assert_eq!(json.stderr, plain.stderr);

    let empty = root.path().join("empty");
    std::fs::create_dir_all(&empty).expect("empty");
    let empty = empty.to_str().expect("utf-8");
    let none = run(
        root.path(),
        &["--config", config, "cap", "list", empty, "--json"],
        b"",
    );
    assert_eq!(
        document(&none),
        json!({"schema_version": 1, "directory": empty, "capabilities": []})
    );
}

fn indexed(name: &str, description: &str, requires_key: bool, tags: &[&str]) -> Value {
    json!({"name": name, "description": description, "requires_key": requires_key, "tags": tags})
}

#[test]
fn cap_search_and_registry_list_print_one_document() {
    let root = tempfile::tempdir().expect("root");
    let caps = root.path().join("caps");
    std::fs::create_dir_all(&caps).expect("caps");
    capability(
        &caps,
        "stock_quote",
        "Quotes a stock",
        Some("STOCK_KEY"),
        &["finance"],
    );
    capability(
        &caps,
        "weather_now",
        "Current conditions",
        None,
        &["weather", "free"],
    );
    let caps = caps.to_str().expect("utf-8");
    let weather = indexed(
        "weather_now",
        "Current conditions",
        false,
        &["weather", "free"],
    );
    let stock = indexed("stock_quote", "Quotes a stock", true, &["finance"]);

    let hit = run(
        root.path(),
        &["cap", "search", "weather", "-C", caps, "--json"],
        b"",
    );
    assert_eq!(
        document(&hit),
        json!({"schema_version": 1, "query": "weather", "capabilities": [weather.clone()]})
    );
    let miss = run(
        root.path(),
        &["cap", "search", "nothing-matches", "-C", caps, "--json"],
        b"",
    );
    assert_eq!(
        document(&miss),
        json!({"schema_version": 1, "query": "nothing-matches", "capabilities": []})
    );
    let all = run(
        root.path(),
        &["cap", "registry-list", "-C", caps, "--json"],
        b"",
    );
    // The index may follow directory-read order: entries compared as a set, and the text form checked per entry.
    let mut doc = document(&all);
    doc["capabilities"]
        .as_array_mut()
        .expect("capabilities")
        .sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    assert_eq!(
        doc,
        json!({"schema_version": 1, "capabilities": [stock, weather]})
    );
    let plain = run(root.path(), &["cap", "registry-list", "-C", caps], b"");
    assert_eq!(plain.code, Some(0), "{}", plain.stderr);
    for part in [
        "Available capabilities (2):\n\n",
        "  stock_quote - Quotes a stock 🔑\n    Tags: finance\n\n",
        "  weather_now - Current conditions\n    Tags: weather, free\n\n",
    ] {
        assert!(
            plain.stdout.contains(part),
            "{part:?} in {:?}",
            plain.stdout
        );
    }
    assert!(
        plain
            .stdout
            .ends_with("\nAll capabilities are available in the capabilities directory.\n"),
        "{:?}",
        plain.stdout
    );

    let empty = root.path().join("empty");
    std::fs::create_dir_all(&empty).expect("empty");
    let none = run(
        root.path(),
        &[
            "cap",
            "registry-list",
            "-C",
            empty.to_str().expect("utf-8"),
            "--json",
        ],
        b"",
    );
    assert_eq!(
        document(&none),
        json!({"schema_version": 1, "capabilities": []})
    );
}

#[test]
fn cap_validate_prints_provider_auth_and_warnings() {
    let root = tempfile::tempdir().expect("root");
    let file = root.path().join("validate_cap.yaml");
    std::fs::write(
        &file,
        "name: validate_cap\ndescription: Validate now\nproviders:\n  primary:\n    service: rest\n    config:\n      \
         base_url: https://api.example.test\n      path: /v1/now\n      method: GET\n\
         auth:\n  required: true\n  type: bearer\n  key: \"env:VALIDATE_TOKEN\"\n",
    )
    .expect("capability");
    let file = file.to_str().expect("utf-8");
    let plain = run(root.path(), &["cap", "validate", file], b"");
    assert_eq!(
        (plain.code, plain.stdout.as_str(), plain.stderr.as_str()),
        (
            Some(0),
            "✅ validate_cap - valid\n   Validate now\n   Provider: rest (GET)\n   \
             URL: https://api.example.test/v1/now\n   Auth: bearer (env:VALIDATE_TOKEN)\n",
            ""
        )
    );
    let json = run(root.path(), &["cap", "validate", file, "--json"], b"");
    assert_eq!(
        document(&json),
        json!({
            "schema_version": 1, "name": "validate_cap", "description": "Validate now",
            "provider": {"service": "rest", "method": "GET", "base_url": "https://api.example.test",
                         "path": "/v1/now"},
            "auth": {"type": "bearer", "key": "env:VALIDATE_TOKEN"}, "warnings": []
        })
    );

    // One warning (CAP-012, an unread provider key): in the document, and still on stderr in both forms.
    let warned = root.path().join("warned_cap.yaml");
    std::fs::write(
        &warned,
        "name: warned_cap\ndescription: Reads one endpoint.\nproviders:\n  primary:\n    config:\n      \
         base_url: https://api.example.com\n      path: /v1\n      methd: POST\n",
    )
    .expect("capability");
    let warned = warned.to_str().expect("utf-8");
    let plain = run(root.path(), &["cap", "validate", warned], b"");
    let json = run(root.path(), &["cap", "validate", warned, "--json"], b"");
    // Written out (A8): the validator's line for the unread key.
    let warning = "[WARN] CAP-012 (providers): providers.primary.config.methd is not read by this gateway version \
                   and is ignored";
    assert_eq!(
        plain.stderr,
        format!("{warning}\n"),
        "one CAP-012 line on stderr"
    );
    let doc = document(&json);
    assert_eq!(doc["auth"], Value::Null);
    assert_eq!(doc["warnings"], json!([warning]));
    assert_eq!(json.stderr, plain.stderr);

    // A webhook-only capability has no primary provider: provider is null.
    let hook = root.path().join("hook_cap.yaml");
    std::fs::write(
        &hook,
        "name: hook_cap\ndescription: Hooks only.\nproviders: {}\nwebhooks:\n  ping:\n    path: /hook/ping\n    \
         method: POST\n    transform:\n      event_type: \"hook.ping\"\n      data: {}\n",
    )
    .expect("capability");
    let json = run(
        root.path(),
        &["cap", "validate", hook.to_str().expect("utf-8"), "--json"],
        b"",
    );
    let doc = document(&json);
    assert_eq!(doc["provider"], Value::Null, "{doc}");
    assert_eq!(doc["name"], json!("hook_cap"));
}

/// J11 (binary half), X2: an execution failure under `--json` prints nothing on stdout, not even the banner the
/// text form prints before executing; stderr and exit are the text form's.
#[test]
fn cap_test_json_failure_prints_no_banner() {
    let root = tempfile::tempdir().expect("root");
    // A loopback target: the CLI's executor refuses loopback egress, so the call fails before any connection.
    let file = root.path().join("now_cap.yaml");
    std::fs::write(
        &file,
        "name: now_cap\ndescription: Now\nproviders:\n  primary:\n    service: rest\n    config:\n      \
         base_url: http://127.0.0.1:9\n      path: /now\n      method: GET\n",
    )
    .expect("capability");
    let file = file.to_str().expect("utf-8");
    let args = ["cap", "test", file, "--args", "{\"city\": \"Oulu\"}"];
    let plain = run(root.path(), &args, b"");
    assert_eq!(plain.code, Some(1), "{}", plain.stderr);
    assert!(
        plain.stdout.starts_with("Testing capability: now_cap\n"),
        "{}",
        plain.stdout
    );
    let mut flagged = args.to_vec();
    flagged.push("--json");
    let json = run(root.path(), &flagged, b"");
    assert_eq!(
        (json.code, json.stdout.as_str(), json.stderr.as_str()),
        (Some(1), "", plain.stderr.as_str())
    );
}

/// F: an unloadable config (cap list) and a structural error (cap validate) under `--json` print nothing on stdout.
#[test]
fn cap_json_failures_print_no_document() {
    let root = tempfile::tempdir().expect("root");
    let caps = root.path().join("caps");
    std::fs::create_dir_all(&caps).expect("caps");
    capability(&caps, "alpha_cap", "Alpha", None, &[]);
    let broken = root.path().join("broken.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&broken, "server: [this is: not, valid\n")
        .expect("config");
    let structural = root.path().join("structural_cap.yaml");
    std::fs::write(
        &structural,
        "name: structural_cap\ndescription: No base URL.\nproviders:\n  primary:\n    config:\n      path: /v1\n",
    )
    .expect("capability");
    let (broken, caps, structural) = (
        broken.to_str().expect("utf-8"),
        caps.to_str().expect("utf-8"),
        structural.to_str().expect("utf-8"),
    );
    for args in [
        vec!["--config", broken, "cap", "list", caps],
        vec!["cap", "validate", structural],
    ] {
        let plain = run(root.path(), &args, b"");
        let mut flagged = args.clone();
        flagged.push("--json");
        let json = run(root.path(), &flagged, b"");
        assert_eq!(plain.code, Some(1), "{args:?}: {}", plain.stderr);
        assert_eq!(
            (json.code, json.stdout.as_str(), json.stderr.as_str()),
            (plain.code, "", plain.stderr.as_str()),
            "{args:?}"
        );
    }
}
