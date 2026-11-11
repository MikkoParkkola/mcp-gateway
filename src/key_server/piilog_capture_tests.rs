// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! No raw email in key-server output. Each case runs in a child process that
//! installs the production log pipeline (the bounded writer and the one fmt
//! layer, JSON or text) as the global subscriber before any runtime starts,
//! drives a real signed exchange and a stored-token use, then checks every
//! captured byte. A child keeps the global subscriber out of other tests.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use super::oidc_test_harness::{AUD, Harness, ISS_A, ISS_B, config_yaml};
use crate::log_writer::{self, NoticeFormat};

const CASE: &str = "MCP_GW_TEST_PIILOG_CASE";
/// Mixed case with a plus tag: neither this nor its lower-cased form may
/// appear anywhere in the output.
const EMAIL: &str = "Ada.Lovelace+Audit@Example.COM";
const SUBJECT: &str = "opaque-subject-7f3a";
/// A hung child fails the row instead of holding a test worker.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);
/// Logged last; its presence proves the queue drained everything before it.
const LAST: &str = "piilog-sentinel-last";

/// Run [`child`] for `case` under a watchdog; output goes to files so a large
/// capture cannot fill a pipe and stall the child.
fn in_child(case: &str) {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("stdout");
    let err_path = dir.path().join("stderr");
    let mut proc = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "key_server::piilog_capture_tests::child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CASE, case)
        .env_remove("RUST_LOG")
        .stdout(Stdio::from(
            std::fs::File::create(&out_path).expect("stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&err_path).expect("stderr file"),
        ))
        .spawn()
        .expect("spawn child");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = proc.try_wait().expect("wait") {
            break Some(status);
        }
        if started.elapsed() > CHILD_DEADLINE {
            let _ = proc.kill();
            let _ = proc.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let read =
        |p: &Path| String::from_utf8_lossy(&std::fs::read(p).unwrap_or_default()).into_owned();
    let (stdout, stderr) = (read(&out_path), read(&err_path));
    let Some(status) = status else {
        panic!("{case}: the child ran past {CHILD_DEADLINE:?} and was killed\n{stdout}\n{stderr}");
    };
    assert!(status.success(), "{case}: child failed\n{stdout}\n{stderr}");
    // Printed only after the child's checks, so a child that ran nothing
    // cannot read as a pass.
    assert!(
        stdout.contains(&format!("piilog {case} child ok")),
        "{case}: the child ran no case\n{stdout}\n{stderr}"
    );
}

/// Markers the capture must hold, and markers it must not.
type Markers = (&'static [&'static str], &'static [&'static str]);

/// A sink the writer thread fills and the child reads back.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
#[ignore = "run by the cases below, in a child process"]
#[allow(
    clippy::too_many_lines,
    reason = "one arm per capture case, each a few lines"
)]
fn child() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    let format = match case.as_str() {
        "json" | "delegated" | "denials" | "email_subject" => NoticeFormat::Json,
        "text" => NoticeFormat::Text,
        other => panic!("unknown case {other}"),
    };
    let captured = Captured::default();
    let (writer, flush) = log_writer::spawn(
        Box::new(captured.clone()),
        log_writer::LOG_QUEUE_LINES,
        log_writer::LOG_QUEUE_BYTES,
        format,
    )
    .expect("writer thread");
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("trace"))
        .with(crate::log_layer(format, writer.clone()))
        .try_init()
        .expect("the child's only global subscriber");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (required, forbidden): Markers = rt.block_on(async {
        let yaml = config_yaml(
            "[]",
            &format!(
                "policies:\n  - match: {{ issuer: \"{ISS_A}\" }}\n    \
                 scopes: {{ backends: [\"*\"], tools: [\"*\"], rate_limit: 0 }}\n"
            ),
        );
        let h = Harness::start(&yaml).await;
        // The email is planted in every claim that can carry text.
        let claims = json!({
            "email": EMAIL, "email_verified": true, "aud": AUD,
            "name": format!("Ada <{EMAIL}>"), "groups": [EMAIL, "staff"], "nickname": EMAIL,
        });
        let markers = match case.as_str() {
            "json" | "text" => exchange_and_use(&h, &claims).await,
            "delegated" => delegated(&h, &claims).await,
            "denials" => denials(&h, &claims).await,
            "email_subject" => email_subjects(&h).await,
            other => panic!("unknown case {other}"),
        };
        tokio::spawn(async { tracing::info!("piilog-sentinel-task") })
            .await
            .expect("task");
        tokio::task::spawn_blocking(|| tracing::info!("piilog-sentinel-blocking"))
            .await
            .expect("blocking");
        markers
    });
    std::thread::spawn(|| tracing::info!("piilog-sentinel-thread"))
        .join()
        .expect("thread");
    rt.shutdown_timeout(Duration::from_secs(5));
    tracing::info!("{LAST}");
    let dropped = writer.dropped_lines();
    drop(flush);

    let bytes = captured.0.lock().expect("capture lock").clone();
    let text = String::from_utf8_lossy(&bytes);
    assert_eq!(
        dropped, 0,
        "the writer dropped lines; the capture is incomplete"
    );
    for marker in [
        "piilog-sentinel-task",
        "piilog-sentinel-blocking",
        "piilog-sentinel-thread",
        LAST,
    ]
    .iter()
    .chain(required)
    {
        assert!(
            text.contains(marker),
            "{case}: no {marker:?} in the capture:\n{text}"
        );
    }
    // Email-shaped subjects reach audit lines by design (the stated limit);
    // what this case checks is the warning itself.
    if case == "email_subject" {
        email_subject_checks(&text);
        println!("piilog {case} child ok");
        return;
    }
    for marker in forbidden {
        assert!(
            !text.contains(marker),
            "{case}: {marker:?} in the capture:\n{text}"
        );
    }
    let leaks: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(EMAIL) || l.to_lowercase().contains(&EMAIL.to_lowercase()))
        .collect();
    assert!(
        leaks.is_empty(),
        "{case}: {} line(s) carry the email:\n{}",
        leaks.len(),
        leaks.join("\n")
    );
    if matches!(case.as_str(), "json" | "text") {
        safe_identity_checks(&text);
    }
    println!("piilog {case} child ok");
}

/// The issued record carries every `SafeIdentity` field with its expected
/// value: the exact subject and issuer, the email's keyed hash, version 1 and
/// the key's id. The audit JSON is escaped inside a JSON log line, so the
/// check reads the text with backslashes removed.
fn safe_identity_checks(text: &str) {
    let key = crate::key_server::email_hash::EmailHashKey::for_test();
    let issued = text
        .lines()
        .find(|l| l.contains("token.issued"))
        .expect("a token.issued line")
        .replace('\\', "");
    for field in [
        format!("\"subject\":\"{SUBJECT}\""),
        format!("\"issuer\":\"{ISS_A}\""),
        format!("\"email_hash\":\"{}\"", key.hash(EMAIL)),
        "\"email_hash_version\":1".to_owned(),
        format!("\"email_hash_key_id\":\"{}\"", key.key_id()),
    ] {
        assert!(issued.contains(&field), "{field} missing from {issued}");
    }
    for gone in ["\"email\":", "\"name\":", "\"groups\":"] {
        assert!(!issued.contains(gone), "{gone} still in {issued}");
    }
}

#[test]
fn a_json_log_of_exchange_and_use_carries_no_email() {
    in_child("json");
}

#[test]
fn a_text_log_of_exchange_and_use_carries_no_email() {
    in_child("text");
}

/// A signed exchange, then a use of the stored token.
async fn exchange_and_use(h: &Harness, claims: &serde_json::Value) -> Markers {
    let (status, body) = h.exchange(&h.mint(ISS_A, SUBJECT, claims)).await;
    assert_eq!(status, 200, "exchange: {body}");
    let bearer = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    assert!(
        h.ks.validate_token(&bearer).await.is_some(),
        "stored token use"
    );
    (&["token.issued", "token.used", SUBJECT], &[])
}

/// A raw ID token presented as a bearer: verified and matched, no token
/// minted and no stored-token use.
async fn delegated(h: &Harness, claims: &serde_json::Value) -> Markers {
    let verified =
        h.ks.verify_bearer_identity(&h.mint(ISS_A, SUBJECT, claims))
            .await;
    let (_, identity) = verified.expect("the delegated bearer verifies and matches a rule");
    assert_eq!(identity.subject(), SUBJECT);
    (&["Policy rule matched"], &["token.issued", "token.used"])
}

/// Every refusal: no matching rule, an invalid token, an expired token, a
/// revoked token's use; plus the identity's own `Debug`.
async fn denials(h: &Harness, claims: &serde_json::Value) -> Markers {
    let (status, body) = h.exchange(&h.mint(ISS_B, SUBJECT, claims)).await;
    assert_eq!(status, 403, "no rule for issuer B: {body}");
    // Caller input that used to reach the refusal record verbatim.
    let resp = reqwest::Client::new()
        .post(format!("http://{}/auth/token", h.addr))
        .form(&[("grant_type", EMAIL), ("subject_token", "x")])
        .send()
        .await
        .expect("post");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a hostile grant_type is refused"
    );
    // The email (with its at-sign spelled out) inside the issuer, the email
    // itself in the subject and a claim: an unknown issuer, refused.
    let hostile_issuer = format!("https://{}.evil.test", EMAIL.replace('@', "-at-"));
    let mut issuer_claims = claims.clone();
    issuer_claims["note"] = json!(EMAIL);
    let (status, _) = h
        .exchange(&h.mint(&hostile_issuer, EMAIL, &issuer_claims))
        .await;
    assert_ne!(
        status, 200,
        "an unknown issuer carrying the email is refused"
    );
    // A configured issuer, signed by the right key, but with the email as its
    // key id: unknown kid, refused before any signature check.
    let info = h.key.key_info();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(EMAIL.to_owned());
    let now = i64::try_from(crate::clock::unix_secs().expect("a clock after the epoch"))
        .expect("seconds fit i64");
    let kid_token = jsonwebtoken::encode(
        &header,
        &json!({"iss": ISS_A, "sub": SUBJECT, "aud": AUD, "iat": now, "exp": now + 300}),
        &jsonwebtoken::EncodingKey::from_ec_pem(info.private_key_pem.as_bytes()).expect("pem"),
    )
    .expect("sign");
    let (status, _) = h.exchange(&kid_token).await;
    assert_ne!(status, 200, "an email-bearing kid is refused");
    let (status, _) = h.exchange("not.a.jwt").await;
    assert_ne!(status, 200, "a garbage token is refused");
    let mut expired = claims.clone();
    expired["exp"] = json!(1);
    expired["iat"] = json!(0);
    let (status, _) = h.exchange(&h.mint(ISS_A, SUBJECT, &expired)).await;
    assert_ne!(status, 200, "an expired token is refused");
    let (status, body) = h.exchange(&h.mint(ISS_A, SUBJECT, claims)).await;
    assert_eq!(status, 200, "exchange: {body}");
    let bearer = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    // The bulk route, as an offboarding admin would use it.
    let issuer: String = url::form_urlencoded::byte_serialize(ISS_A.as_bytes()).collect();
    let (status, body) = h
        .revoke(&format!("issuer={issuer}&subject={SUBJECT}"))
        .await;
    assert_eq!(status, 200, "bulk revoke: {body}");
    assert!(
        h.ks.validate_token(&bearer).await.is_none(),
        "a revoked token is refused"
    );
    let identity = h
        .verify(&h.mint(ISS_A, SUBJECT, claims))
        .await
        .expect("verifies");
    tracing::info!(?identity, "piilog identity debug");
    (
        &[
            "No policy rule matched",
            "token.revoked",
            "piilog identity debug",
        ],
        &[],
    )
}

#[test]
fn a_delegated_sign_in_logs_no_email_and_mints_nothing() {
    in_child("delegated");
}

#[test]
fn refusals_and_the_identity_debug_carry_no_email() {
    in_child("denials");
}

const SUBJECT_WARNING: &str = "this identity provider's subjects are email addresses";

/// Provider A sends two email-shaped subjects, one of them twice; provider B
/// sends one and is refused by policy (the warning comes before policy).
async fn email_subjects(h: &Harness) -> Markers {
    let second = concat!("grace", "@", "example", ".org");
    for subject in [EMAIL, EMAIL, second] {
        let (status, body) = h.exchange(&h.mint(ISS_A, subject, &json!({}))).await;
        assert_eq!(status, 200, "{subject}: {body}");
    }
    let (status, body) = h.exchange(&h.mint(ISS_B, EMAIL, &json!({}))).await;
    assert_eq!(status, 403, "no rule for issuer B: {body}");
    (&[SUBJECT_WARNING], &[])
}

/// Exactly one warning per provider, each carrying the subject's hash and
/// never the subject's text.
fn email_subject_checks(text: &str) {
    let warnings: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(SUBJECT_WARNING))
        .collect();
    assert_eq!(
        warnings.len(),
        2,
        "one warning per provider:\n{}",
        warnings.join("\n")
    );
    let hash = crate::key_server::email_hash::EmailHashKey::for_test().hash(EMAIL);
    for issuer in [ISS_A, ISS_B] {
        let mine: Vec<&&str> = warnings.iter().filter(|l| l.contains(issuer)).collect();
        assert_eq!(mine.len(), 1, "{issuer}: {warnings:?}");
        assert!(
            mine[0].contains(&hash),
            "{issuer}: the warning carries the subject's hash"
        );
        assert!(
            !mine[0].to_lowercase().contains(&EMAIL.to_lowercase()),
            "{issuer}: the warning prints the subject"
        );
    }
}

#[test]
fn email_shaped_subjects_warn_once_per_provider_with_only_a_hash() {
    in_child("email_subject");
}
