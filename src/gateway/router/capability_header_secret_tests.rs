// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A credential pasted into a capability provider's `headers:` in the editor:
//! a literal value under a credential-named header is refused on save and the
//! file is left unchanged; a placeholder the validator accepts passes; other
//! headers are not judged. Uses the parent's admin gateway fixture.

use super::*;
use std::fmt::Write as _;

/// A literal token in no file before this test; no answer may echo it.
const LITERAL: &str = "tok-0123456789abcdef-canary";

/// `kept`, declaring the input `token`, whose providers carry `headers`
/// (YAML single-quoted, so braces and quotes are literal); `second` adds a
/// second provider carrying the same headers.
fn doc(headers: &[(&str, &str)], second: bool) -> String {
    let block = headers
        .iter()
        .fold(String::new(), |mut acc, (name, value)| {
            let _ = writeln!(acc, "        {name}: '{}'", value.replace('\'', "''"));
            acc
        });
    let provider = |key: &str, path: &str, block: &str| {
        format!(
            "  {key}:\n    service: rest\n    config:\n      base_url: https://api.example.com\n      path: {path}\n      headers:\n{block}"
        )
    };
    let mut text = String::from(
        "fulcrum: \"1.0\"\nname: kept\ndescription: header rows\nschema:\n  input:\n    type: object\n    properties:\n      token:\n        type: string\nproviders:\n",
    );
    if second {
        text += &provider("primary", "/kept", "        Accept: 'application/json'\n");
        text += &provider("fallback", "/kept2", &block);
    } else {
        text += &provider("primary", "/kept", &block);
    }
    text
}

/// One save of `after` over the parent's `kept` file, with the right If-Match.
async fn save(after: &str) -> (StatusCode, String, Fixture, String) {
    let before = capability(CANARY_BEFORE);
    let fx = fixture(&before, AuditFailurePolicy::FailClosed).await;
    let base = sha256_hex(before.as_bytes());
    let (status, body) = fx
        .send(request("PUT", "/ui/api/capabilities/kept", &base, after))
        .await;
    (status, body, fx, before)
}

/// A save that must be refused by field: 422 `literal_in_header`, the file
/// keeps its bytes, the answer never carries `LITERAL`.
async fn assert_refused(case: &str, after: &str) {
    let (status, body, fx, before) = save(after).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{case}: {body}");
    assert!(body.contains("literal_in_header"), "{case}: {body}");
    assert!(
        body.contains("headers"),
        "{case}: the field is named: {body}"
    );
    assert!(!body.contains(LITERAL), "{case}: echoed: {body}");
    let kept = std::fs::read_to_string(&fx.file).expect("the file");
    assert_eq!(kept, before, "{case}: the file changed");
}

/// CAPEDIT.1 + CAPEDIT.3 (fail-fast row): a literal bearer token in a
/// provider header is refused by the save, and the file keeps its bytes.
#[tokio::test]
async fn capedit1_a_literal_header_credential_is_refused_and_the_file_kept() {
    let after = doc(&[("Authorization", &format!("Bearer {LITERAL}"))], false);
    assert_refused("literal bearer", &after).await;
}

/// C8-C11 + C13 (design r2/r3): every literal form under a credential name
/// is refused: a JSON object, an undeclared placeholder, every name variant,
/// another syntax's reference, an expression, and the second provider.
#[tokio::test]
async fn capedit_every_literal_form_is_refused_by_field() {
    let json = format!(r#"{{"api_key":"{LITERAL}"}}"#);
    let cases: Vec<(&str, String)> = vec![
        ("json object", doc(&[("X-Credentials", &json)], false)),
        (
            "undeclared placeholder",
            doc(&[("Authorization", "Bearer {tok0123456789}")], false),
        ),
        ("x-api-key", doc(&[("x-api-key", LITERAL)], false)),
        ("X-Auth-Token", doc(&[("X-Auth-Token", LITERAL)], false)),
        (
            "lowercase authorization",
            doc(&[("authorization", &format!("Bearer {LITERAL}"))], false),
        ),
        (
            "Proxy-Authorization",
            doc(
                &[("Proxy-Authorization", &format!("Basic {LITERAL}"))],
                false,
            ),
        ),
        (
            "Cookie",
            doc(&[("Cookie", &format!("session={LITERAL}"))], false),
        ),
        (
            "dollar template",
            doc(&[("Authorization", "Bearer ${API_TOKEN}")], false),
        ),
        (
            "env: reference",
            doc(&[("Authorization", "env:API_TOKEN")], false),
        ),
        (
            "file: reference",
            doc(&[("Authorization", "file:/run/secret")], false),
        ),
        (
            "keychain: reference",
            doc(&[("Authorization", "keychain:svc")], false),
        ),
        (
            "expression",
            doc(&[("Authorization", "{{input.mode ? 'a' : 'b'}}")], false),
        ),
        (
            "second provider",
            doc(&[("Authorization", &format!("Bearer {LITERAL}"))], true),
        ),
    ];
    for (case, after) in cases {
        assert_refused(case, &after).await;
    }
}

/// C2-C4 + C9 + C13 (CAPEDIT.2): placeholders the validator accepts pass,
/// and headers that name no credential are not judged.
#[tokio::test]
async fn capedit2_accepted_placeholders_and_other_headers_are_saved() {
    let cases: Vec<(&str, String)> = vec![
        (
            "env template",
            doc(&[("Authorization", "Bearer {env.API_KEY}")], false),
        ),
        (
            "keychain template",
            doc(&[("Authorization", "{keychain.svc}")], false),
        ),
        ("declared input", doc(&[("X-Api-Key", "{token}")], false)),
        (
            "non-credential literals",
            doc(
                &[("Accept", "application/json"), ("User-Agent", "x/1.0")],
                false,
            ),
        ),
        (
            "expression elsewhere",
            doc(&[("X-Mode", "{{input.mode ? 'a' : 'b'}}")], false),
        ),
    ];
    for (case, after) in cases {
        let (status, body, _fx, _) = save(&after).await;
        assert_eq!(status, StatusCode::OK, "{case}: {body}");
    }
}

/// A request with no If-Match and a JSON or YAML body.
fn plain(
    method: &str,
    uri: &str,
    ctype: &str,
    body: &str,
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", ctype)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request")
}

/// C5: a create with a literal credential header is refused; no file is made.
#[tokio::test]
async fn capedit5_a_create_with_a_literal_credential_is_refused() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let yaml = doc(&[("Authorization", &format!("Bearer {LITERAL}"))], false)
        .replace("name: kept", "name: fresh");
    let body = serde_json::json!({ "name": "fresh", "yaml": yaml }).to_string();
    let (status, answer) = fx
        .send(plain(
            "POST",
            "/ui/api/capabilities",
            "application/json",
            &body,
        ))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert!(answer.contains("literal_in_header"), "{answer}");
    assert!(!answer.contains(LITERAL), "{answer}");
    assert!(
        !fx.file.with_file_name("fresh.yaml").exists(),
        "a refused create made a file"
    );
}

/// C6 + C12: every validate-only entry reports the refusal by field and
/// writes nothing, never echoing the value.
#[tokio::test]
async fn capedit6_every_validate_only_entry_reports_the_refusal() {
    let after = doc(&[("Authorization", &format!("Bearer {LITERAL}"))], false);
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let before = std::fs::read_to_string(&fx.file).expect("the file");
    let mut header = plain(
        "PUT",
        "/ui/api/capabilities/kept",
        "application/x-yaml",
        &after,
    );
    header
        .headers_mut()
        .insert("x-validate-only", "1".parse().expect("a header value"));
    let entries = [
        (
            "POST validate",
            plain(
                "POST",
                "/ui/api/capabilities/kept/validate",
                "application/x-yaml",
                &after,
            ),
        ),
        (
            "PUT ?validate",
            plain(
                "PUT",
                "/ui/api/capabilities/kept?validate=1",
                "application/x-yaml",
                &after,
            ),
        ),
        ("PUT x-validate-only", header),
    ];
    for (entry, request) in entries {
        let (status, body) = fx.send(request).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{entry}: {body}");
        assert!(
            body.contains("headers"),
            "{entry}: the field is named: {body}"
        );
        assert!(!body.contains(LITERAL), "{entry}: echoed: {body}");
    }
    assert_eq!(std::fs::read_to_string(&fx.file).expect("the file"), before);
}

/// C14: the refusal comes before the stale check, so a literal credential
/// with a stale If-Match answers 422 without a patch that would carry it.
#[tokio::test]
async fn capedit14_a_literal_with_a_stale_base_is_refused_without_a_patch() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let after = doc(&[("Authorization", &format!("Bearer {LITERAL}"))], false);
    let stale = "0".repeat(64);
    let (status, body) = fx
        .send(request("PUT", "/ui/api/capabilities/kept", &stale, &after))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.contains("literal_in_header"), "{body}");
    assert!(!body.contains(LITERAL), "{body}");
}

/// Second leak (red-run finding): a literal JSON credential header was already
/// refused, by the undeclared-placeholder check, but that answer echoed the
/// token in its message and in the returned patch. Whatever refuses it, the
/// answer names no value: neither the message nor any patch carries it.
#[tokio::test]
async fn capedit_a_refused_json_credential_is_echoed_nowhere() {
    let json = format!(r#"{{"api_key":"{LITERAL}"}}"#);
    let (status, body, _fx, _) = save(&doc(&[("X-Credentials", &json)], false)).await;
    assert!(!status.is_success(), "the save went through: {body}");
    let answer: serde_json::Value = serde_json::from_str(&body).expect("a JSON answer");
    let message = answer["message"].as_str().unwrap_or_default();
    let errors = answer["errors"].to_string();
    let patch = answer["patch"].as_str().unwrap_or_default();
    assert!(
        !message.contains(LITERAL),
        "the message echoed it: {message}"
    );
    assert!(
        !errors.contains(LITERAL),
        "the field errors echoed it: {errors}"
    );
    assert!(!patch.contains(LITERAL), "the patch echoed it");
}

/// r4: prove loader acceptance before judging the save's exact refusal.
async fn assert_review_refused(after: &str, field: &str) {
    crate::capability::parse_capability(after)
        .expect("the loader accepts this form before the editor's credential check");
    let (status, body, fx, before) = save(after).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let answer: serde_json::Value = serde_json::from_str(&body).expect("a JSON answer");
    assert_eq!(answer["error"], "literal_in_header", "{body}");
    let errors = answer["errors"].as_array().expect("field errors");
    assert_eq!(errors.len(), 1, "{body}");
    assert_eq!(errors[0]["field"], field, "{body}");
    assert!(
        !body.contains(LITERAL),
        "the answer echoed the literal: {body}"
    );
    assert_eq!(std::fs::read_to_string(&fx.file).expect("the file"), before);
}

/// F1: typed field identifiers read the tagged scalar's source text.
#[tokio::test]
async fn capedit_r4_a_tagged_providers_key_is_refused_by_header_field() {
    let after =
        doc(&[("Authorization", LITERAL)], false).replace("\nproviders:", "\n!x providers:");
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

/// F1: keep a valid primary; the loader reads the second provider's key as String.
#[tokio::test]
async fn capedit_r4_a_numeric_provider_name_is_refused_by_header_field() {
    let after = doc(&[("Authorization", LITERAL)], true).replace("  fallback:", "  123:");
    assert_review_refused(&after, "providers.123.config.headers.Authorization").await;
}

/// F1: the same scalar-to-String loader rule also accepts a boolean key.
#[tokio::test]
async fn capedit_r4_a_boolean_provider_name_is_refused_by_header_field() {
    let after = doc(&[("Authorization", LITERAL)], true).replace("  fallback:", "  true:");
    assert_review_refused(&after, "providers.true.config.headers.Authorization").await;
}

/// F2: the executor merges this provider's `static_params` before filling headers.
#[tokio::test]
async fn capedit_r4_a_static_parameter_credential_is_refused_by_header_field() {
    let after = doc(&[("Authorization", "Bearer {api_key}")], false).replace(
        "      headers:\n",
        &format!("      static_params:\n        api_key: '{LITERAL}'\n      headers:\n"),
    );
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

/// F3 policy row: today the resolver looks up the entire X:-literal as a name;
/// it does not implement a literal default. Tightening that grammar needs review.
#[tokio::test]
async fn capedit_r4_an_env_literal_default_span_is_refused_by_header_field() {
    let value = format!("Bearer {{env.API_KEY:-{LITERAL}}}");
    let after = doc(&[("Authorization", &value)], false);
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

/// F3 policy row: today `secret_name` accepts this whole nonempty suffix too.
#[tokio::test]
async fn capedit_r4_an_env_space_literal_span_is_refused_by_header_field() {
    let value = format!("Bearer {{env.API_KEY {LITERAL}}}");
    let after = doc(&[("Authorization", &value)], false);
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

async fn assert_r5_saved(after: &str) {
    let (status, body, fx, _) = save(after).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let answer: serde_json::Value = serde_json::from_str(&body).expect("a JSON answer");
    assert_eq!(answer["status"], "saved", "{body}");
    assert!(!body.contains(LITERAL), "{body}");
    assert_eq!(std::fs::read_to_string(&fx.file).expect("the file"), after);
}

async fn assert_r5_parse_refused(after: &str, other: &str) {
    let mut messages = Vec::new();
    for text in [after, other] {
        let (status, body, fx, before) = save(text).await;
        assert!(
            [StatusCode::UNPROCESSABLE_ENTITY, StatusCode::BAD_REQUEST].contains(&status),
            "{body}"
        );
        assert!(!body.contains(LITERAL), "{body}");
        let answer: serde_json::Value = serde_json::from_str(&body).expect("a JSON answer");
        let error = &answer["errors"][0];
        let parse_error = crate::yaml::from_str::<crate::yaml::Value>(text)
            .err()
            .unwrap_or_else(|| {
                crate::yaml::from_str::<crate::capability::CapabilityDefinition>(text)
                    .expect_err("typed parse fails")
            });
        let at = parse_error.location().expect("a parser position");
        let top = answer["message"].as_str().expect("a fixed message");
        let detail = error["message"].as_str().expect("a fixed message");
        assert!(!top.is_empty() && !detail.is_empty(), "{body}");
        assert_eq!(
            answer,
            serde_json::json!({
                "error": answer["error"], "message": top,
                "errors": [{"message": detail, "line": at.line(), "column": at.column()}]
            }),
            "no patch, diff, excerpt, or loader fields: {body}"
        );
        let mut header = plain(
            "PUT",
            "/ui/api/capabilities/kept",
            "application/x-yaml",
            text,
        );
        header
            .headers_mut()
            .insert("x-validate-only", "1".parse().expect("a header value"));
        for request in [
            plain(
                "POST",
                "/ui/api/capabilities/kept/validate",
                "application/x-yaml",
                text,
            ),
            plain(
                "PUT",
                "/ui/api/capabilities/kept?validate=1",
                "application/x-yaml",
                text,
            ),
            header,
        ] {
            let (status, body) = fx.send(request).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
            // The validate contract keeps its own keys (`valid`, `status`, the
            // pin and a null diff and digest); what it says about the text is
            // the save's fixed error list, with no submitted byte.
            let validated = serde_json::from_str::<serde_json::Value>(&body).expect("JSON");
            assert_eq!(validated["errors"], answer["errors"], "{body}");
            assert_eq!(validated["valid"], false, "{body}");
            assert!(validated["diff"].is_null(), "no diff: {body}");
            assert!(validated["sha256"].is_null(), "no digest: {body}");
            assert!(!body.contains(LITERAL), "{body}");
        }
        messages.push((top.to_owned(), detail.to_owned()));
        assert_eq!(std::fs::read_to_string(&fx.file).expect("the file"), before);
    }
    assert_eq!(messages[0], messages[1], "parse messages must be fixed");
}

/// R1 guard: `Value::as_str` removes the first header key's tag today.
#[tokio::test]
async fn capedit_r5_a_tagged_duplicate_authorization_is_refused_by_header_field() {
    let after = doc(&[("!x Authorization", &format!("Bearer {LITERAL}"))], false)
        + "        Authorization: '{env.KEY}'\n";
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

#[tokio::test]
async fn capedit_r5_an_escaped_duplicate_authorization_is_refused_without_bytes() {
    let after = doc(
        &[(r#""Authoriz\u0061tion""#, &format!("Bearer {LITERAL}"))],
        false,
    ) + "        Authorization: '{env.KEY}'\n";
    crate::capability::parse_capability(&after)
        .expect("the typed loader accepts duplicate headers");
    let other = after.replace(r#""Authoriz\u0061tion""#, "'Authorization'");
    assert_r5_parse_refused(&after, &other).await;
}

/// R2 guard: the current provider-entry visitor keeps both entries for inspection.
#[tokio::test]
async fn capedit_r5_a_tagged_duplicate_provider_is_refused_by_header_field() {
    let after = doc(&[("Authorization", &format!("Bearer {LITERAL}"))], false)
        .replace("  primary:", "  !x primary:");
    let safe = doc(&[("Authorization", "{env.KEY}")], false);
    let after = after + safe.split_once("providers:\n").expect("providers").1;
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

/// R3 guard: the existing exact-key static lookup also covers `api_key`.
#[tokio::test]
async fn capedit_r5_a_static_runtime_api_key_is_refused_by_header_field() {
    let after = doc(&[("Authorization", "Bearer {api_key}")], false).replace(
        "      headers:\n",
        &format!("      static_params: {{api_key: '{LITERAL}'}}\n      headers:\n"),
    );
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

/// R3 guard: the existing exact-key static lookup also covers `oauth.x`.
#[tokio::test]
async fn capedit_r5_a_static_oauth_name_is_refused_by_header_field() {
    let after = doc(&[("Authorization", "Bearer {oauth.x}")], false).replace(
        "      headers:\n",
        &format!("      static_params: {{oauth.x: '{LITERAL}'}}\n      headers:\n"),
    );
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

/// R3 guard: the existing exact-key static lookup also covers `service_auth_header`.
#[tokio::test]
async fn capedit_r5_a_static_auth_header_name_is_refused_by_header_field() {
    let after = doc(&[("Authorization", "Bearer {service_auth_header}")], false).replace(
        "      headers:\n",
        &format!("      static_params: {{service_auth_header: '{LITERAL}'}}\n      headers:\n"),
    );
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

#[tokio::test]
async fn capedit_r5_an_input_enum_is_refused_by_header_field() {
    let after = doc(&[("Authorization", "Bearer {token}")], false).replace(
        "        type: string\n",
        &format!("        type: string\n        enum: ['{LITERAL}']\n"),
    );
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

#[tokio::test]
async fn capedit_r5_an_input_const_is_refused_by_header_field() {
    let after = doc(&[("Authorization", "Bearer {token}")], false).replace(
        "        type: string\n",
        &format!("        type: string\n        const: '{LITERAL}'\n"),
    );
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

#[tokio::test]
async fn capedit_r5_an_input_examples_is_refused_by_header_field() {
    let after = doc(&[("Authorization", "Bearer {token}")], false).replace(
        "        type: string\n",
        &format!("        type: string\n        examples: ['{LITERAL}']\n"),
    );
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

#[tokio::test]
async fn capedit_r5_a_root_anyof_input_const_is_refused_by_header_field() {
    let after = doc(&[("Authorization", "Bearer {token}")], false).replace(
        "    type: object\n",
        &format!(
            "    type: object\n    anyOf: [{{properties: {{token: {{const: '{LITERAL}'}}}}}}]\n"
        ),
    );
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

/// R5 guard: keep the r4 env-name restriction, including this exact space spelling.
#[tokio::test]
async fn capedit_r5_an_env_name_with_whitespace_is_refused_by_header_field() {
    let after = doc(&[("Authorization", "{env.API_KEY SECRET}")], false);
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

/// R5 guard: the current keychain word check already excludes whitespace.
#[tokio::test]
async fn capedit_r5_a_keychain_name_with_whitespace_is_refused_by_header_field() {
    let after = doc(
        &[("Authorization", &format!("{{keychain.svc {LITERAL}}}"))],
        false,
    );
    assert_review_refused(&after, "providers.primary.config.headers.Authorization").await;
}

#[tokio::test]
async fn capedit_r5_a_dynamic_provider_timeout_parse_error_has_only_fixed_diagnostics() {
    let after = doc(&[("Authorization", "{env.KEY}")], false)
        .replace("  primary:", &format!("  {LITERAL}:"))
        .replace("    service: rest", "    timeout: []\n    service: rest");
    let error = crate::capability::parse_capability(&after).expect_err("invalid timeout");
    assert!(
        error.to_string().contains(&format!("providers.{LITERAL}")),
        "{error}"
    );
    let other = after
        .replace(LITERAL, "another-provider")
        .replace("timeout: []", "timeout: {}");
    assert_r5_parse_refused(&after, &other).await;
}

/// A1: currently refused by the narrower keychain charset; green after the fix.
#[tokio::test]
async fn capedit_r5_a_keychain_service_with_a_slash_is_saved() {
    assert_r5_saved(&doc(&[("Authorization", "{keychain.team/service}")], false)).await;
}

/// A2 guard: a plain OAuth name is already saved.
#[tokio::test]
async fn capedit_r5_a_oauth_reference_is_saved() {
    assert_r5_saved(&doc(&[("Authorization", "{oauth.gmail}")], false)).await;
}

/// A3 guard: a scheme followed by an env reference is already saved.
#[tokio::test]
async fn capedit_r5_a_env_reference_after_bearer_is_saved() {
    assert_r5_saved(&doc(&[("Authorization", "Bearer {env.TOKEN}")], false)).await;
}

/// A3 guard: the final empty default is already saved.
#[tokio::test]
async fn capedit_r5_a_env_reference_with_an_empty_default_is_saved() {
    assert_r5_saved(&doc(&[("Authorization", "{env.TOKEN:-}")], false)).await;
}

/// A4 guard: type and description alone leave the input value-free.
#[tokio::test]
async fn capedit_r5_a_plain_declared_input_with_description_is_saved() {
    let after = doc(&[("Authorization", "{token}")], false).replace(
        "        type: string\n",
        "        type: string\n        description: Supplied by the caller\n",
    );
    assert_r5_saved(&after).await;
}
