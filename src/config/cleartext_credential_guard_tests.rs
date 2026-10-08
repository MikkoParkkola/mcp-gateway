// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The cleartext-credential guard on remote backends.

use super::*;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};

// A registrable DNS name, not a reserved one: the point of most rows here
// is a host the gateway must treat as remote.
const REMOTE: &str = "internal-host";

fn http_backend(url: &str) -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: Some(false),
            protocol_version: None,
        },
        ..Default::default()
    }
}

fn with_oauth(mut backend: BackendConfig) -> BackendConfig {
    backend.oauth = Some(OAuthConfig {
        enabled: true,
        scopes: Vec::new(),
        client_id: None,
        client_secret: None,
        callback_host: None,
        callback_port: None,
        callback_path: None,
        token_refresh_buffer_secs: 300,
        shared_account: false,
    });
    backend
}

fn config_with(backend: BackendConfig) -> Config {
    let mut config = Config::default();
    config.backends.insert("b".to_string(), backend);
    config
}

// Every row drives the whole validator rather than the private helper: the
// guard is only worth anything if it is reached from the entry point that
// config load actually calls.
fn validate(backend: BackendConfig) -> Result<()> {
    config_with(backend).validate()
}

fn refusal(backend: BackendConfig) -> String {
    match validate(backend) {
        Err(error) => error.to_string(),
        Ok(()) => panic!("expected the config to be refused, it was accepted"),
    }
}

// Row 1 — the guard must not fire on TLS. A guard that refuses everything
// passes every REFUSED row and is still wrong.
#[test]
fn https_non_loopback_with_credential_passes() {
    let backend = with_oauth(http_backend(&format!("https://{REMOTE}:8080")));
    assert!(validate(backend).is_ok());
}

// Row 2 — the case the whole change exists for.
#[test]
fn cleartext_non_loopback_with_credential_is_refused() {
    let backend = with_oauth(http_backend(&format!("http://{REMOTE}:8080")));
    let message = refusal(backend);
    assert!(
        message.contains("cleartext"),
        "refusal should say what is wrong: {message}"
    );
}

// Row 3 — cleartext alone is a posture, not a leak. Refusing it would break
// every plain internal backend that carries no credential at all.
#[test]
fn cleartext_non_loopback_without_credential_passes() {
    let backend = http_backend(&format!("http://{REMOTE}:8080"));
    assert!(validate(backend).is_ok());
}

// Rows 4-8, 21 — the loopback carve-out, one row per way of spelling it.
// 127.0.0.2 and the decimal form are the rows that a `== "127.0.0.1"`
// comparison fails; LOCALHOST is the row a case-sensitive compare fails.
#[test]
fn loopback_spellings_with_credential_pass() {
    for url in [
        "http://127.0.0.1:8080",
        "http://127.0.0.2:8080",
        "http://[::1]:8080",
        "http://localhost:8080",
        "http://LOCALHOST:8080",
        "http://2130706433/",
    ] {
        let backend = with_oauth(http_backend(url));
        assert!(
            validate(backend).is_ok(),
            "{url} is loopback and must not be refused"
        );
    }
}

// Row 9 — the opt-out is the whole reason a refusal is acceptable. If this
// row fails the guard is a wall, not a gate.
#[test]
fn explicit_opt_in_permits_cleartext_credentials() {
    let mut backend = with_oauth(http_backend(&format!("http://{REMOTE}:8080")));
    backend.allow_cleartext_credentials = true;
    assert!(validate(backend).is_ok());
}

// Row 10 — identity propagation mints a per-user credential for this
// backend, so the backend is credential-bearing whether or not oauth is set.
#[test]
fn identity_propagation_counts_as_a_credential() {
    let mut backend = http_backend(&format!("http://{REMOTE}"));
    backend.identity_propagation = Some(IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: "https://backend.invalid".to_string(),
        required: false,
        session_mode: SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    });
    let message = refusal(backend);
    assert!(
        message.contains("cleartext"),
        "identity propagation is a credential path: {message}"
    );
}

// Row 11 — secret injection puts the credential on the wire by definition.
#[test]
fn secret_injection_counts_as_a_credential() {
    let mut backend = http_backend(&format!("http://{REMOTE}"));
    backend.secrets = vec![crate::secret_injection::CredentialRule {
        name: "api_key".to_string(),
        credential_type: crate::secret_injection::CredentialType::ApiKey,
        value: "env:SOME_KEY".to_string(),
        inject_as: crate::secret_injection::InjectTarget::Header,
        inject_key: "Authorization".to_string(),
        tools: vec!["*".to_string()],
    }];
    let message = refusal(backend);
    assert!(
        message.contains("cleartext"),
        "secret injection is a credential path: {message}"
    );
}

// Rows 12-13 — any static header, not a known-name list. A guard that only
// knows `Authorization` misses the header half of the real deployments,
// which is why row 13 is separate from row 12.
#[test]
fn any_static_header_counts_as_a_credential() {
    for header in ["Authorization", "X-Custom-Token"] {
        let mut backend = http_backend(&format!("http://{REMOTE}"));
        backend.headers = HashMap::from([(header.to_string(), "value".to_string())]);
        let message = refusal(backend);
        assert!(
            message.contains("cleartext"),
            "header {header} is a credential path: {message}"
        );
    }
}

// Row 14 — userinfo IS the credential; reqwest turns it into a Basic header.
// No other credential is configured on this backend.
#[test]
fn url_userinfo_alone_counts_as_a_credential() {
    let backend = http_backend(&format!("http://user:pw@{REMOTE}"));
    let message = refusal(backend);
    assert!(
        message.contains("cleartext"),
        "userinfo is a credential path: {message}"
    );
}

// Row 2 — a username with NO password. The guard ORs the two userinfo arms
// (`src/config/mod.rs:1031-1032`), so either half alone is a credential.
// Row 14 above pairs them and would survive a loosening to require both;
// this row is what forbids that loosening.
#[test]
fn url_username_without_a_password_counts_as_a_credential() {
    let backend = http_backend(&format!("http://user@{REMOTE}"));
    let message = refusal(backend);
    assert!(
        message.contains("cleartext"),
        "a username alone is a credential path: {message}"
    );
}

// The other half of Row 2: a password with no username. Same predicate,
// opposite arm, so a loosening in either direction fails a test.
#[test]
fn url_password_without_a_username_counts_as_a_credential() {
    let backend = http_backend(&format!("http://:pw@{REMOTE}"));
    let message = refusal(backend);
    assert!(
        message.contains("cleartext"),
        "a password alone is a credential path: {message}"
    );
}

// Row 15 — a disabled backend connects to nothing, so it leaks nothing.
#[test]
fn disabled_backend_skips_the_cleartext_guard() {
    let mut backend = with_oauth(http_backend(&format!("http://{REMOTE}:8080")));
    backend.enabled = false;
    assert!(validate(backend).is_ok());
}

// Row 18 — and the skip drops ONLY the new predicate. An empty or malformed
// URL on a disabled backend keeps failing exactly as it does today,
// otherwise the skip has quietly widened what config load accepts.
#[test]
fn disabled_backend_still_fails_the_existing_url_checks() {
    for url in ["", "not a url"] {
        let mut backend = http_backend(url);
        backend.enabled = false;
        assert!(
            validate(backend).is_err(),
            "a disabled backend with url {url:?} must still be refused"
        );
    }
}

// Rows 19, 19b — a query string on a backend URL is operator-supplied
// per-request material sent in cleartext. Whether it is benign is not
// decidable here, so both spellings are refused.
#[test]
fn url_query_counts_as_a_credential() {
    for url in [
        &format!("http://{REMOTE}/mcp?tenant=acme"),
        &format!("http://{REMOTE}/mcp?api_key=secret"),
    ] {
        let message = refusal(http_backend(url));
        assert!(
            message.contains("cleartext"),
            "a query is credential-bearing material: {message}"
        );
    }
}

// Row 20 — MIK-7221: the refusal is printed on startup and pasted into
// support threads. It may name the backend and nothing else. An implementer
// who copies `OidcError::InsecureJwksUri`, which echoes the URL, fails here.
#[test]
fn refusal_message_names_the_backend_and_leaks_nothing() {
    let message = refusal(http_backend(&format!("http://user:pw@{REMOTE}")));
    // The quoted name, not a bare `b`: the word "backend" appears in the
    // remediation sentence, so a substring check on the letter alone would
    // pass on a message that names nothing.
    assert!(
        message.contains("'b'"),
        "the refusal must name the backend: {message}"
    );
    for leaked in ["user:pw", REMOTE, "http://"] {
        assert!(
            !message.contains(leaked),
            "refusal leaked {leaked:?}: {message}"
        );
    }
}

// Rows 16-17 — the a2a transport is the second spelling of the same URL.
// Guarding one and not the other is how the first guard stops mattering.
#[cfg(feature = "a2a")]
#[test]
fn a2a_url_is_guarded_on_the_same_terms() {
    let a2a = |url: &str| BackendConfig {
        transport: TransportConfig::A2a {
            a2a_url: url.to_string(),
            a2a_agent_card_path: None,
        },
        ..Default::default()
    };
    let message = refusal(with_oauth(a2a(&format!("http://{REMOTE}"))));
    assert!(
        message.contains("cleartext"),
        "a2a carries credentials over the same wire: {message}"
    );
    assert!(validate(with_oauth(a2a(&format!("https://{REMOTE}")))).is_ok());
}

// MIK-8063: credentials written into an a2a_url's userinfo are credentials on
// the wire too (sent as HTTP Basic), on the same terms as any other.
#[cfg(feature = "a2a")]
#[test]
fn a2a_url_userinfo_is_a_credential_on_the_same_terms() {
    let a2a = |url: &str| BackendConfig {
        transport: TransportConfig::A2a {
            a2a_url: url.to_string(),
            a2a_agent_card_path: None,
        },
        ..Default::default()
    };
    let userinfo = ["operator", "pw-7f3a"].join(":");
    let message = refusal(a2a(&format!("http://{userinfo}@{REMOTE}")));
    assert!(message.contains("cleartext"), "{message}");
    assert!(
        !message.contains("pw-7f3a"),
        "the refusal never echoes the credential"
    );
    assert!(validate(a2a(&format!("https://{userinfo}@{REMOTE}"))).is_ok());
    assert!(validate(a2a(&format!("http://{userinfo}@127.0.0.1:9"))).is_ok());
}
