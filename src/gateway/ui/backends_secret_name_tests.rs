// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which values the panel stores: an env value under a credential name (judged
//! by its last words) and a header, each at least the redactor's short-value
//! bound long; every other value is written as typed and is never a value the
//! redactor holds, so an ordinary setting such as `DEBUG=1` never damages a
//! tool result. Uses the parent's panel fixture.

use serde_json::json;

use super::*;

/// The values the redactor would hold for backend `name` once gateway.yaml
/// loads: the loader's own record of configured credentials (the step that
/// runs before every load overwrites references), kept where the redactor's
/// own rule holds them.
fn held_needles(panel: &Panel, name: &str) -> Vec<String> {
    let (mut config, _) =
        Config::load_literal_with_text(&panel.path()).expect("gateway.yaml loads");
    let mut unresolved = Vec::new();
    let mut configured = crate::config::configured_secrets::ConfiguredByBackend::new();
    crate::config::secret_ref::evaluate_backends(
        &mut config.backends,
        &crate::config::EnvOverlay::none(),
        &mut unresolved,
        &mut configured,
    );
    assert!(unresolved.is_empty(), "{unresolved:?}");
    configured
        .get(name)
        .map(|secrets| {
            secrets
                .iter()
                .filter(|s| crate::security::needles::holds(s))
                .map(|s| s.value.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// T16 (regression): an ordinary setting typed into the panel is written as
/// text and is never a credential the redactor holds, on add and on update;
/// a credential-named value beside it is still stored and held (the control
/// that shows the oracle sees stored values).
#[tokio::test]
async fn t16_plain_settings_are_written_as_text_and_never_redacted() {
    let panel = Panel::new().await;
    let (status, body) = panel
        .add(json!({"name": "b", "url": "http://127.0.0.1:9/mcp",
            "env": {"DEBUG": "1", "LOG_LEVEL": "debug", "API_KEY": TOKEN}}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let env = panel.written("b").env;
    assert_eq!(env.get("DEBUG").map(String::as_str), Some("1"), "{env:?}");
    assert_eq!(env.get("LOG_LEVEL").map(String::as_str), Some("debug"));
    let fields: Vec<&str> = body["secrets_stored"]
        .as_array()
        .expect("secrets_stored")
        .iter()
        .filter_map(|s| s["field"].as_str())
        .collect();
    assert_eq!(fields, ["env.API_KEY"], "{body}");
    let held = held_needles(&panel, "b");
    assert!(held.iter().any(|v| v == TOKEN), "the control: {held:?}");
    for plain in ["1", "debug"] {
        assert!(!held.iter().any(|v| v == plain), "{plain} held: {held:?}");
    }

    let (status, body) = panel
        .update("a", json!({"env": {"DEBUG": "1", "LOG_LEVEL": "debug"}}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let env = panel.written("a").env;
    assert_eq!(env.get("DEBUG").map(String::as_str), Some("1"), "{env:?}");
    assert_eq!(env.get("LOG_LEVEL").map(String::as_str), Some("debug"));
    assert!(held_needles(&panel, "a").is_empty());
}

/// T17: values under credential-like names are stored, each by field, and
/// none of them reaches gateway.yaml.
#[tokio::test]
async fn t17_credential_named_values_are_stored() {
    let panel = Panel::new().await;
    let values = [
        ("API_KEY", "sk-cred-a-41c9"),
        ("X_AUTH_TOKEN", "sk-cred-b-52da"),
        ("DB_PASSWORD", "sk-cred-c-63eb"),
    ];
    let env: serde_json::Map<String, Value> = values
        .iter()
        .map(|(k, v)| ((*k).to_owned(), json!(v)))
        .collect();
    let (status, body) = panel
        .add(json!({"name": "b", "url": "http://127.0.0.1:9/mcp", "env": env}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let fields: Vec<&str> = body["secrets_stored"]
        .as_array()
        .expect("secrets_stored")
        .iter()
        .filter_map(|s| s["field"].as_str())
        .collect();
    assert_eq!(
        fields,
        ["env.API_KEY", "env.DB_PASSWORD", "env.X_AUTH_TOKEN"],
        "{body}"
    );
    assert_eq!(panel.entries().len(), 3, "{:?}", panel.entries());
    let text = panel.text();
    for (_, value) in values {
        assert!(
            !text.contains(value),
            "{value} reached gateway.yaml:\n{text}"
        );
        no_value(&body, value);
    }
}

/// T18: an ordinary setting the panel saved never damages a tool result: a
/// JSON number `1` and the word `debug` come through the redactor's own match
/// unchanged, while the stored credential beside them is still redacted.
#[tokio::test]
async fn t18_a_json_number_in_a_tool_result_survives() {
    let panel = Panel::new().await;
    let (status, body) = panel
        .add(json!({"name": "b", "url": "http://127.0.0.1:9/mcp",
            "env": {"DEBUG": "1", "LOG_LEVEL": "debug", "API_KEY": TOKEN}}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let compiled = crate::security::secret_redaction::Compiled::new(&held_needles(&panel, "b"));
    let mut result = json!({"count": 1, "items": [1, 2], "level": "debug", "note": "debug 1"});
    let before = result.clone();
    assert!(
        !crate::security::secret_redaction::redact_value_with(&mut result, &compiled),
        "{result}"
    );
    assert_eq!(result, before);
    let mut leak = json!({"echo": TOKEN});
    assert!(crate::security::secret_redaction::redact_value_with(
        &mut leak, &compiled
    ));
    assert!(!leak.to_string().contains(TOKEN), "{leak}");
}

/// T19: the credential-name rule, name by name: only a key's last words count
/// (`TOKEN_LIMIT`, `API_KEY_TIMEOUT` and `next_page_token` are settings), in
/// any letter case, split at `_`, `-` and camel case, non-ASCII names
/// included; ordinary settings (the weak words the rule leaves out) and near
/// misses (`TOKENIZER`, `PATH`, `PATTERN`, `SPATIAL_INDEX`, `KEYBOARD_LAYOUT`:
/// a part must equal a listed word, never contain it) are not credentials.
#[test]
fn t19_the_credential_name_rule_name_by_name() {
    use crate::config::secret_values::names_a_credential;
    let stored = [
        "API_KEY",
        "OPENAI_API_KEY",
        "apiKey",
        "APIKEY",
        "X_AUTH_TOKEN",
        "authToken",
        "DB_PASSWORD",
        "db_password",
        "DB_PASSWD",
        "DB_PASSPHRASE",
        "GITHUB_PAT",
        "githubPat",
        "SENTRY_DSN",
        "API-SECRET",
        "CLIENT_SECRET",
        "PRIVATE_KEY",
        "SIGNING_KEY",
        "GOOGLE_CREDENTIALS",
        "SECRET_KEY_BASE",
        "SESSION_KEY",
        "COOKIE_KEY",
        "AUTH_KEY",
        "STRIPE_SECRET",
        "naïve_token",
    ];
    let kept = [
        "DEBUG",
        "LOG_LEVEL",
        "PORT",
        "KEY",
        "SORT_KEY",
        "AUTH_TYPE",
        "AUTH_ENABLED",
        "SESSION_TIMEOUT",
        "COOKIE_SECURE",
        "PRIVATE_MODE",
        "TOKENIZER",
        "PATH",
        "PATTERN",
        "SPATIAL_INDEX",
        "PATH_PREFIX",
        "KEYBOARD_LAYOUT",
        "PASS_THROUGH",
        "TOKEN_LIMIT",
        "PASSWORD_MIN_LENGTH",
        "API_KEY_TIMEOUT",
        "CREDENTIALS_ENABLED",
        "next_page_token",
        "AWS_ACCESS_KEY_ID",
        "café_mode",
    ];
    let wrong: Vec<&str> = stored
        .iter()
        .filter(|k| !names_a_credential(k))
        .chain(kept.iter().filter(|k| names_a_credential(k)))
        .copied()
        .collect();
    assert!(wrong.is_empty(), "judged wrongly: {wrong:?}");
}

/// T20: a credential-named value too short to redact safely is written as
/// typed, through the panel: a boolean under a name ending in `TOKEN`
/// (`HF_HUB_DISABLE_IMPLICIT_TOKEN=1`), `AUTHORIZATION=none`, and a 7-byte
/// `API_KEY`; the redactor holds none of them. An 8-byte `API_KEY` is stored.
#[tokio::test]
async fn t20_a_credential_named_value_too_short_to_redact_stays_text() {
    let panel = Panel::new().await;
    let (status, body) = panel
        .add(
            json!({"name": "b", "url": "http://127.0.0.1:9/mcp", "env": {
                "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
                "AUTHORIZATION": "none",
                "API_KEY": "1234567"
            }}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["secrets_stored"], json!([]), "{body}");
    let env = panel.written("b").env;
    assert_eq!(
        env.get("HF_HUB_DISABLE_IMPLICIT_TOKEN").map(String::as_str),
        Some("1")
    );
    assert_eq!(env.get("AUTHORIZATION").map(String::as_str), Some("none"));
    assert_eq!(env.get("API_KEY").map(String::as_str), Some("1234567"));
    assert!(held_needles(&panel, "b").is_empty());
    assert!(panel.entries().is_empty(), "{:?}", panel.entries());

    let (status, body) = panel
        .add(json!({"name": "c", "url": "http://127.0.0.1:9/mcp", "env": {"API_KEY": "12345678"}}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["secrets_stored"][0]["field"], "env.API_KEY", "{body}");
    assert_ne!(
        panel.written("c").env.get("API_KEY").map(String::as_str),
        Some("12345678")
    );
}

/// T21: the store's length bound is the redactor's own: one byte under it
/// stays text, at it the value is stored.
#[test]
fn t21_the_store_bound_is_the_redactors_short_value_bound() {
    use crate::config::secret_values::stores_env_value;
    let bound = crate::security::needles::SHORT_VALUE_BYTES;
    let under: String = "0123456789abcdef".chars().take(bound - 1).collect();
    let at: String = "0123456789abcdef".chars().take(bound).collect();
    assert!(!stores_env_value("API_KEY", &under));
    assert!(stores_env_value("API_KEY", &at));
    assert!(!stores_env_value("LOG_LEVEL", &at));
}

/// T22: the panel's header bound, at the step that picks what to store (a
/// route cannot reach it: the registry splice writes `Bearer ` and a token, at
/// least the bound already): a header one byte under the bound stays text, one
/// at it is stored.
#[test]
fn t22_the_panel_stores_no_header_shorter_than_the_bound() {
    let bound = crate::security::needles::SHORT_VALUE_BYTES;
    let under: String = "0123456789abcdef".chars().take(bound - 1).collect();
    let at: String = "0123456789abcdef".chars().take(bound).collect();
    let env = std::collections::HashMap::new();
    let headers =
        std::collections::HashMap::from([("X-Short".to_owned(), under), ("X-Long".to_owned(), at)]);
    let picked: Vec<(bool, String)> = super::super::slotting::literals(env.iter(), headers.iter())
        .into_iter()
        .map(|l| (l.header, l.key))
        .collect();
    assert_eq!(picked, [(true, "X-Long".to_owned())]);
}
