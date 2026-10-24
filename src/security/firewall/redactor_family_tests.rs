// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-8757 (Family-fix: redactor-structure-blind): credential-named members
//! beyond `api_key`, one table across every family, name form and value shape.
//! Rows are built in code; a credential-shaped literal would trip the hooks.

use serde_json::{Value, json};

use super::{MARK, carriers, class_value, deliver, descriptions, pat_value};

const PASSWORD: &str = "Credential detected: Password (object member)";
const TOKEN: &str = "Credential detected: OAuth or session token (object member)";
const SECRET: &str = "Credential detected: Client or shared secret (object member)";
const PRIVATE_KEY: &str = "Credential detected: Private Key (object member)";
const AUTHORIZATION: &str = "Credential detected: Authorization header (object member)";
const API_KEY: &str = "Credential detected: Generic API Key in key=value (object member)";
const PAT: &str = "Credential detected: GitHub Personal Access Token";

/// The word "Bearer", built so no literal bearer string sits in the source.
fn bearer() -> String {
    ["Bea", "rer"].concat()
}

/// Every carrier of `{key: value}` (parsed, compact and pretty JSON text),
/// delivered: the value as each carrier ends up, and that carrier's findings.
fn each_carrier(key: &str, value: &Value) -> Vec<(Value, Vec<String>)> {
    let mut out = Vec::new();
    let mut parsed = json!({ key: value.clone() });
    let found = super::scan(&mut parsed);
    out.push((parsed[key].clone(), descriptions(&found)));
    for text in carriers(&json!({ key: value.clone() })) {
        let (delivered, found) = deliver(&text);
        let got: Value = serde_json::from_str(&delivered).expect("still parses");
        out.push((got[key].clone(), descriptions(&found)));
    }
    out
}

fn assert_redacted(key: &str, value: &str, finding: &str) {
    for (got, found) in each_carrier(key, &json!(value)) {
        assert_eq!(got, MARK, "{key} not redacted");
        assert_eq!(found, vec![finding.to_owned()], "{key}: findings");
    }
}

fn assert_kept(key: &str, value: &Value) {
    for (got, found) in each_carrier(key, value) {
        assert_eq!(&got, value, "{key} changed");
        assert!(found.is_empty(), "{key}: unexpected findings {found:?}");
    }
}

/// (key, value, finding) rows every family must redact. RED on base.
fn redacted_rows() -> Vec<(String, String, &'static str)> {
    let mut rows = Vec::new();
    for key in ["private_key", "signingKey", "privatekey", "PRIVATEkey"] {
        rows.push((key.to_owned(), class_value(32), PRIVATE_KEY));
    }
    rows.push((
        "Authorization".to_owned(),
        format!("Basic {}", class_value(24)),
        AUTHORIZATION,
    ));
    rows.push((
        "proxy_authorization".to_owned(),
        class_value(24),
        AUTHORIZATION,
    ));
    for key in [
        "secret",
        "client_secret",
        "clientsecret",
        "CLIENTsecret",
        "consumer_secret",
        "webhookSecret",
        "app_secret",
        "signing_secret",
        "hmac_secret",
        "jwt_secret",
        "session_secret",
        "current_secret",
        "previous_secret",
        "api_secret",
        "apiSecret",
        "apisecret",
        "shared_secret",
    ] {
        rows.push((key.to_owned(), class_value(24), SECRET));
    }
    rows.push((
        "shared_secret".to_owned(),
        "correct horse battery staple x".to_owned(),
        SECRET,
    ));
    rows.push((
        "client_secret".to_owned(),
        format!("sk_live_{}", class_value(24)),
        SECRET,
    ));
    for key in ["password", "passwd", "passphrase", "db_password"] {
        rows.push((key.to_owned(), "hunter2".to_owned(), PASSWORD));
    }
    rows.push(("password".to_owned(), "1111".to_owned(), PASSWORD));
    for key in [
        "access_token",
        "refresh_token",
        "id_token",
        "auth_token",
        "GH_TOKEN",
        "admin_token",
        "bearer_token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "authtoken",
        "ACCESStoken",
        "AccessToken",
        "Access-Token",
        "HTTPSToken",
        "previous_access_token",
        "previous_refresh_token",
    ] {
        rows.push((key.to_owned(), class_value(32), TOKEN));
    }
    rows.push((
        "bot_token".to_owned(),
        format!("123456789:AA{}", class_value(33)),
        TOKEN,
    ));
    for key in ["openaiApiKey", "v1ApiKey"] {
        rows.push((key.to_owned(), format!("sk-{}", class_value(24)), API_KEY));
    }
    rows.push(("aws_secret_access_key".to_owned(), class_value(40), API_KEY));
    rows
}

#[test]
fn f_every_family_redacts_its_credential_named_members() {
    for (key, value, finding) in redacted_rows() {
        assert_redacted(&key, &value, finding);
    }
}

/// Pagination and continuation keys a token family would otherwise take: kept.
#[test]
fn k_pagination_keys_are_kept_with_a_token_shaped_value() {
    for key in [
        "next_page_token",
        "page_token",
        "pageToken",
        "nextToken",
        "nextPageToken",
        "NextToken",
        "continuationToken",
        "ContinuationToken",
        "syncToken",
        "sync_token",
        "next_sync_token",
        "request_sync_token",
        "requestSyncToken",
        "skipToken",
        "$skipToken",
        "prev_token",
        "previous_token",
        "resume_token",
        "start_token",
        "after_token",
        "before_token",
        "marker_token",
        "pagination_token",
        "cursor_token",
        "page_tokens",
        "next_cursor",
        "start_cursor",
        "cursor",
    ] {
        assert_kept(key, &json!(class_value(40)));
    }
}

/// Keys whose last word is not a family name, judged with a value every
/// token and secret class accepts, so only the key rule can keep them.
#[test]
fn d_near_miss_keys_are_kept_with_a_class_value() {
    for key in [
        "token_count",
        "max_tokens",
        "total_tokens",
        "token_type",
        "token_endpoint",
        "token_env",
        "token_revision",
        "existingSecret",
        "isSecret",
        "secretKeyRef",
        "imagePullSecrets",
        "password_policy",
        "password_hint",
        "api_key_id",
        "PWD",
        "myaccesstoken",
        "secrets",
    ] {
        assert_kept(key, &json!(class_value(32)));
    }
}

/// Values a family's guards keep: placeholders, masks, placeholder words,
/// short scheme values, Stripe intent client secrets, numbers.
#[test]
fn g_guarded_values_are_kept() {
    let b = bearer();
    let rows: Vec<(&str, Value)> = vec![
        ("password", json!("")),
        ("password", json!("no")),
        ("password", json!("abc")),
        ("password", json!("${DB_PASSWORD}")),
        ("password", json!("{{ db_password }}")),
        ("password", json!("%(db_password)s")),
        ("password", json!("****")),
        ("password", json!("••••••")),
        ("Authorization", json!(format!("{b} ${{GITHUB_TOKEN}}"))),
        ("token_type", json!(b)),
        ("id-token", json!("write")),
        ("client_secret", json!("pi_3Mxyz_secret_AbC123")),
        ("client_secret", json!("seti_1Abc_secret_XyZ789")),
        ("password", json!(123_456)),
        ("access_token", json!(12_345_678_901_234_567_890_u64)),
        ("client_secret", json!(1.5e300)),
        ("private_key", json!(class_value(31))),
        ("client_secret", json!(class_value(15))),
        ("access_token", json!(class_value(15))),
        ("proxy_authorization", json!(class_value(15))),
        ("Authorization", json!(format!("Basic {}", class_value(7)))),
    ];
    for word in [
        "none", "NULL", "nil", "N/A", "unset", "empty", "Redacted", "hidden", "masked",
    ] {
        assert_kept("password", &json!(word));
    }
    for (key, value) in rows {
        assert_kept(key, &value);
    }
}

/// Floors, trimming and guards from the redacted side.
#[test]
fn b_floors_and_trimming_redact_at_the_boundary() {
    assert_redacted("private_key", &class_value(32), PRIVATE_KEY);
    assert_redacted("client_secret", &class_value(16), SECRET);
    assert_redacted("password", "abcd", PASSWORD);
    assert_redacted("access_token", &class_value(16), TOKEN);
    assert_redacted("proxy_authorization", &class_value(16), AUTHORIZATION);
    assert_redacted(
        "Authorization",
        &format!("Basic {}", class_value(8)),
        AUTHORIZATION,
    );
    assert_redacted("client_secret", &format!("{}\n", class_value(16)), SECRET);
    assert_redacted("access_token", &format!("  {}", class_value(16)), TOKEN);
    assert_redacted("password", "x${DB}y", PASSWORD);
    assert_redacted("password", "nonesuch", PASSWORD);
    assert_redacted("client_secret", "pi_3Mxyz_secret_", SECRET);
    // Kept just under each floor, even with surrounding whitespace.
    assert_kept("client_secret", &json!(format!("{}\n", class_value(15))));
    assert_kept("access_token", &json!(format!("  {}", class_value(15))));
}

/// A member whose whole value a raw pattern already replaced adds no member
/// finding in a new family; family 1 keeps MIK-8756's two findings.
#[test]
fn r_raw_whole_value_matches_add_no_second_finding() {
    for (got, found) in each_carrier("token", &json!(pat_value())) {
        assert_eq!(got, MARK);
        assert_eq!(found, vec![PAT.to_owned()], "one PAT finding");
    }
    for (got, found) in each_carrier("token", &json!(format!("{}\n", pat_value()))) {
        assert_eq!(
            got, MARK,
            "the whole value, newline included, is the marker"
        );
        assert_eq!(
            found,
            vec![PAT.to_owned()],
            "one PAT finding after trimming"
        );
    }
}
