// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C9 / SECRET.2: `file:` secret references, one grammar with `env:`.

use super::*;

/// Writes `body` to `dir/name` with `mode` and returns the absolute path.
fn secret(dir: &std::path::Path, name: &str, body: &[u8], mode: u32) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }
    #[cfg(not(unix))]
    let _ = mode;
    path
}

fn config_file(dir: &std::path::Path, yaml: &str) -> std::path::PathBuf {
    secret(dir, "gateway.yaml", yaml.as_bytes(), 0o600)
}

/// Auth on needs the audit log (D1), so it points beside the secret.
fn bearer_yaml(path: &std::path::Path) -> String {
    format!(
        "auth:\n  enabled: true\n  bearer_token: 'file:{}'\nsecurity:\n  transparency_log:\n    enabled: true\n    path: '{}'\n",
        path.display(),
        path.with_file_name("audit.jsonl").display()
    )
}

fn resolve(path: &std::path::Path) -> Result<String> {
    let text = format!("file:{}", path.display());
    SecretRef::parse(&text).resolve("auth.bearer_token", &EnvOverlay::none())
}

#[test]
fn file_ref_resolves_bearer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tok = secret(dir.path(), "tok", b"tok\n", 0o600);
    let cfg = Config::load(Some(&config_file(dir.path(), &bearer_yaml(&tok))))
        .expect("a 0600 file: reference loads");
    assert_eq!(cfg.auth.bearer_token.as_deref(), Some("tok"));
}

#[test]
fn file_ref_strips_one_newline_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let two = secret(dir.path(), "two", b"tok\n\n", 0o600);
    let crlf = secret(dir.path(), "crlf", b"tok\r\n", 0o600);
    let none = secret(dir.path(), "none", b"tok", 0o600);
    assert_eq!(resolve(&two).unwrap(), "tok\n");
    assert_eq!(resolve(&crlf).unwrap(), "tok");
    assert_eq!(resolve(&none).unwrap(), "tok");
}

#[test]
fn file_ref_relative_path_refused() {
    for spelling in ["file:tok", "file:~/tok", "file:"] {
        let err = SecretRef::parse(spelling)
            .resolve("auth.bearer_token", &EnvOverlay::none())
            .expect_err("a relative file: path is refused");
        let msg = err.to_string();
        assert!(
            msg.contains("auth.bearer_token") && msg.contains("absolute"),
            "{spelling}: {msg}"
        );
    }
}

#[cfg(unix)]
#[test]
fn file_ref_bad_file_refused() {
    const CONTENT: &[u8] = b"s3cr3t-c9-content";
    let dir = tempfile::tempdir().expect("tempdir");
    let loose = secret(dir.path(), "loose", CONTENT, 0o644);
    let empty = secret(dir.path(), "empty", b"", 0o600);
    let newline = secret(dir.path(), "newline", b"\n", 0o600);
    let big = secret(dir.path(), "big", &vec![b'a'; 64 * 1024 + 1], 0o600);
    let binary = secret(dir.path(), "binary", &[0xff, 0xfe, 0x00], 0o600);
    let missing = dir.path().join("missing");
    let directory = dir.path().join("adir");
    std::fs::create_dir(&directory).expect("mkdir");
    // No `${VAR}` expansion in a path: this is the literal name, which is absent.
    let templated = dir.path().join("${C9_TOKEN_PATH}");
    for (path, expect) in [
        (&directory, "adir"),
        (&templated, "No such file"),
        (&loose, "0644"),
        (&empty, "empty"),
        (&newline, "empty"),
        (&big, "64 KiB"),
        (&binary, "UTF-8"),
        (&missing, "No such file"),
    ] {
        let msg = resolve(path).expect_err("refused").to_string();
        assert!(msg.contains(expect), "{expect}: {msg}");
        assert!(msg.contains("auth.bearer_token"), "field missing: {msg}");
        assert!(!msg.contains("s3cr3t"), "content leaked: {msg}");
    }
}

#[test]
fn file_ref_at_exact_cap_accepted() {
    // The cap is on the raw bytes, before the newline strip.
    let dir = tempfile::tempdir().expect("tempdir");
    let full = secret(dir.path(), "full", &vec![b'a'; 64 * 1024], 0o600);
    assert_eq!(resolve(&full).unwrap().len(), 64 * 1024);
    let mut body = vec![b'a'; 64 * 1024 - 1];
    body.push(b'\n');
    let newline = secret(dir.path(), "newline", &body, 0o600);
    assert_eq!(resolve(&newline).unwrap().len(), 64 * 1024 - 1);
}

#[cfg(unix)]
#[test]
fn file_ref_bad_file_fails_the_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let loose = secret(dir.path(), "loose", b"tok\n", 0o644);
    let err = Config::load(Some(&config_file(dir.path(), &bearer_yaml(&loose))))
        .expect_err("a group/world-readable secret file fails the load");
    let msg = err.to_string();
    assert!(
        msg.contains("auth.bearer_token") && msg.contains("0644"),
        "{msg}"
    );
}

#[cfg(unix)]
#[test]
fn message_signing_file_key_error_propagates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let loose = secret(dir.path(), "key", &[b'k'; 40], 0o644);
    let mut signing = SecurityConfig::default().message_signing;
    signing.enabled = true;
    signing.shared_secret = format!("file:{}", loose.display());
    let err = signing
        .resolve_with_env(&EnvOverlay::none())
        .expect_err("a loose key file is refused");
    let msg = err.to_string();
    assert!(msg.contains("0644"), "the file's own reason is lost: {msg}");
    assert!(!msg.contains("environment value"), "{msg}");
}

#[test]
fn message_signing_file_key_resolves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = "k".repeat(40);
    let path = secret(dir.path(), "key", format!("{key}\n").as_bytes(), 0o600);
    let mut signing = SecurityConfig::default().message_signing;
    signing.enabled = true;
    signing.shared_secret = format!("file:{}", path.display());
    let resolved = signing
        .resolve_with_env(&EnvOverlay::none())
        .expect("a 0600 key file resolves");
    assert_eq!(resolved.shared_secret, key);
}

/// C2's group-read rule: a file this process owns may not be group-readable.
/// (Group read on a file another uid owns, the `fsGroup` mount, is allowed;
/// that branch is `secret_file_refusal`'s own unit test, since a test cannot
/// create a file another uid owns.)
#[cfg(unix)]
#[test]
fn file_ref_group_readable_own_file_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = secret(dir.path(), "g", b"tok\n", 0o440);
    let msg = resolve(&path)
        .expect_err("0440 own file refused")
        .to_string();
    assert!(msg.contains("0440") && msg.contains("read it"), "{msg}");
}

#[test]
fn metrics_token_file_ref() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tok = secret(dir.path(), "metrics", b"scrape\n", 0o600);
    let server = ServerConfig {
        metrics_token: Some(format!("file:{}", tok.display())),
        ..ServerConfig::default()
    };
    assert_eq!(
        server.resolve_metrics_token(&EnvOverlay::none()).as_deref(),
        Some("scrape")
    );
    let missing = ServerConfig {
        metrics_token: Some(format!("file:{}", dir.path().join("nope").display())),
        ..ServerConfig::default()
    };
    assert_eq!(missing.resolve_metrics_token(&EnvOverlay::none()), None);
}

#[test]
fn rewrite_keeps_file_ref_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tok = secret(dir.path(), "tok", b"c9-material\n", 0o600);
    let path = config_file(dir.path(), &bearer_yaml(&tok));
    let cfg = Config::load_literal(Some(&path)).expect("literal load");
    let saved = serde_yaml::to_string(&cfg).expect("serialise");
    assert!(
        saved.contains(&format!("file:{}", tok.display())),
        "reference text lost: {saved}"
    );
    assert!(
        !saved.contains("c9-material"),
        "material reached the rewrite"
    );
}

#[test]
fn file_digest_not_in_debug() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tok = secret(dir.path(), "tok", b"c9-debug\n", 0o600);
    let evaluated =
        Config::load_evaluated(Some(&config_file(dir.path(), &bearer_yaml(&tok)))).expect("loads");
    let bytes: [u8; 32] = {
        use sha2::Digest as _;
        sha2::Sha256::digest(b"c9-debug").into()
    };
    let hex = bytes.iter().fold(String::new(), |mut hex, b| {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
        hex
    });
    let listed = format!("{bytes:?}");
    let shown = format!("{evaluated:?}");
    assert!(shown.contains("tok"), "the path is recorded: {shown}");
    assert!(
        !shown.contains(&hex) && !shown.contains(&listed[1..20]),
        "a digest reached Debug: {shown}"
    );
}

/// E4 stores an API key as its digest; a `file:` may hold that digest.
#[test]
fn api_key_digest_file_ref_resolves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let digest = format!("sha256:{}", crate::hashing::sha256_hex(b"c9-api-key"));
    let file = secret(
        dir.path(),
        "digest",
        format!("{digest}\n").as_bytes(),
        0o600,
    );
    let yaml = format!(
        "auth:\n  api_keys:\n    - name: ci\n      key_sha256: 'file:{}'\n",
        file.display()
    );
    let cfg = Config::load(Some(&config_file(dir.path(), &yaml))).expect("a file: digest loads");
    assert_eq!(
        cfg.auth.api_keys[0].key_sha256.as_deref(),
        Some(digest.as_str())
    );
}
