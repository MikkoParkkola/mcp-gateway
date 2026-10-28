// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C1/R1, C3/R2, C8, C9, C11: the per-fetch credential gates both entries,
//! is random, dies on expiry, and never reaches a log line or a refusal.

use super::{
    ENTRIES, Entry, GLOBAL, NPM, begin, connect_bytes, connect_status, ip, open, rig, send, status,
};
use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

/// The OS random source failing refuses this preview with an error; the
/// proxy, and so the gateway, keeps serving.
#[tokio::test]
async fn c8_a_failed_random_source_refuses_and_the_proxy_lives() {
    let mut rig = rig().await;
    rig.proxy.random = |_| Err(io::Error::other("no entropy"));
    let refused = rig.proxy.begin_fetch();
    assert!(matches!(
        refused,
        Err(crate::preview_sandbox::Refusal::Step(_))
    ));
    let st = status(&send(&rig, Entry::Tcp, &connect_bytes("pypi.org:443", None)).await);
    assert_eq!(st, 407, "the proxy stopped answering");
}

/// C1/R1, kills "port open outside a fetch": during a fetch both entries
/// carry a tunnel; with no live credential neither admits anything, nothing
/// more is dialled, and the port stays bound.
#[tokio::test]
async fn c1_outside_a_fetch_nothing_is_admitted_and_the_port_stays_bound() {
    let rig = rig().await;
    let cred = begin(&rig);
    // During the fetch, each entry opens a tunnel that carries bytes, so a
    // proxy that refuses everything cannot pass this row.
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    for entry in ENTRIES {
        let mut t = open(&rig, entry, &bytes).await.expect("connect");
        assert_eq!(status(&t.head().await), 200, "refused during the fetch");
        assert!(t.echoes().await, "the tunnel carried no bytes");
    }
    let dialled = rig.connect.dials().len();
    rig.proxy.expire(&cred);
    for entry in ENTRIES {
        let st = connect_status(&rig, entry, "registry.npmjs.org:443", &cred).await;
        assert_ne!(st, 200, "a tunnel opened outside a fetch");
    }
    assert_eq!(
        rig.connect.dials().len(),
        dialled,
        "dialled outside a fetch"
    );
    let rebind = TcpListener::bind((Ipv4Addr::LOCALHOST, rig.proxy.port())).await;
    assert!(rebind.is_err(), "the port was released");
}

/// C3, kills "credential check removed": a missing, wrong or expired
/// credential gets 407 through either entry, and nothing is dialled.
#[tokio::test]
async fn c3_missing_wrong_or_expired_credential_gets_407() {
    let rig = rig().await;
    let old = begin(&rig);
    rig.proxy.expire(&old);
    let live = begin(&rig);
    let wrong = format!("Basic {}", base64_of("not-the-secret:"));
    for entry in ENTRIES {
        let missing = connect_bytes("registry.npmjs.org:443", None);
        assert_eq!(status(&send(&rig, entry, &missing).await), 407);
        let bad = connect_bytes("registry.npmjs.org:443", Some(&wrong));
        assert_eq!(status(&send(&rig, entry, &bad).await), 407);
        let st = connect_status(&rig, entry, "registry.npmjs.org:443", &old).await;
        assert_eq!(st, 407, "an expired credential was not refused");
    }
    assert_eq!(
        connect_status(&rig, Entry::Tcp, "registry.npmjs.org:443", &live).await,
        200
    );
    assert_eq!(rig.connect.dials().len(), 1, "only the live CONNECT dials");
}

/// R2, kills "credential check removed" on the Unix socket alone.
#[tokio::test]
async fn r2_the_unix_socket_requires_the_credential() {
    let rig = rig().await;
    let live = begin(&rig);
    let missing = connect_bytes("pypi.org:443", None);
    assert_eq!(status(&send(&rig, Entry::Unix, &missing).await), 407);
    assert_eq!(
        connect_status(&rig, Entry::Unix, "pypi.org:443", &live).await,
        200
    );
}

/// C11, kills "credential check removed": duplicate headers, a non-Basic
/// scheme and a malformed Basic value each get 407, even beside a valid one.
#[tokio::test]
async fn c11_duplicate_non_basic_and_malformed_auth_get_407() {
    let rig = rig().await;
    let cred = begin(&rig);
    let good = cred.basic();
    let duplicate = format!(
        "CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\
         Proxy-Authorization: {good}\r\nProxy-Authorization: {good}\r\n\r\n"
    );
    let token = good.trim_start_matches("Basic ").to_owned();
    let cases = [
        duplicate,
        connect_text("pypi.org:443", &format!("Bearer {token}")),
        connect_text("pypi.org:443", &format!("basic {token}")),
        connect_text("pypi.org:443", "Basic !!!not-base64!!!"),
        connect_text("pypi.org:443", "Basic "),
        connect_text("pypi.org:443", &token),
    ];
    for case in cases {
        for entry in ENTRIES {
            let st = status(&send(&rig, entry, case.as_bytes()).await);
            assert_eq!(st, 407, "{case:?}");
        }
    }
    assert!(rig.connect.dials().is_empty());
}

fn base64_of(s: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(s)
}

fn connect_text(authority: &str, auth: &str) -> String {
    String::from_utf8(connect_bytes(authority, Some(auth))).expect("ascii")
}

/// C8/V3, kills "constant credential": credentials differ per fetch, carry
/// at least 32 random bytes as URL-safe base64, and an expired one from
/// fetch 1 is refused during fetch 2.
#[tokio::test]
async fn c8_credentials_are_random_per_fetch_and_the_old_one_is_dead() {
    let rig = rig().await;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..16 {
        let c = begin(&rig);
        rig.proxy.expire(&c);
        assert!(seen.insert(c.secret().to_owned()), "repeated credential");
        let s = c.secret();
        assert!(s.len() >= 43, "under 32 bytes of base64: {}", s.len());
        assert!(
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }
    let first = begin(&rig);
    rig.proxy.expire(&first);
    let second = begin(&rig);
    assert_ne!(first.secret(), second.secret());
    let host = "registry.npmjs.org:443";
    assert_eq!(connect_status(&rig, Entry::Tcp, host, &first).await, 407);
    assert_eq!(connect_status(&rig, Entry::Tcp, host, &second).await, 200);
}

/// Collects every tracing line the proxy emits.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// C9, kills "credential logged or echoed": the secret, its base64 and its
/// percent-encoded forms appear in no log line and no refusal text.
#[tokio::test]
async fn c9_the_credential_never_reaches_a_log_line_or_a_refusal() {
    crate::test_log_capture::keep_interest_open();
    let logs = LogBuf::default();
    let sink = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let rig = rig().await;
    let cred = begin(&rig);
    let mut texts = Vec::new();
    // Refusals that carry the live credential: bad host, bad port, denied
    // address, disagreeing Host, non-CONNECT, duplicate header.
    rig.resolve.set("evil.test", vec![GLOBAL]);
    for authority in [
        "evil.test:443",
        "registry.npmjs.org:80",
        "93.184.216.34:443",
    ] {
        let bytes = connect_bytes(authority, Some(&cred.basic()));
        texts.push(send(&rig, Entry::Tcp, &bytes).await);
    }
    rig.resolve.set(NPM, vec![ip("127.0.0.1")]);
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    texts.push(send(&rig, Entry::Unix, &bytes).await);
    let dup = format!(
        "CONNECT pypi.org:443 HTTP/1.1\r\nProxy-Authorization: {0}\r\nProxy-Authorization: {0}\r\n\r\n",
        cred.basic()
    );
    texts.push(send(&rig, Entry::Tcp, dup.as_bytes()).await);
    let get = format!(
        "GET / HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n",
        cred.basic()
    );
    texts.push(send(&rig, Entry::Tcp, get.as_bytes()).await);
    rig.proxy.expire(&cred);
    texts.push(send(&rig, Entry::Tcp, &bytes).await);

    let token = cred.basic().trim_start_matches("Basic ").to_owned();
    let pct = |s: &str| {
        s.replace('=', "%3D")
            .replace('+', "%2B")
            .replace('/', "%2F")
    };
    let needles = [
        cred.secret().to_owned(),
        token.clone(),
        pct(&token),
        base64_of(cred.secret()),
        pct(&base64_of(cred.secret())),
    ];
    let log = String::from_utf8_lossy(&logs.0.lock().expect("lock")).into_owned();
    for needle in &needles {
        assert!(
            !log.contains(needle.as_str()),
            "credential form in a log line"
        );
        for text in &texts {
            assert!(
                !text.contains(needle.as_str()),
                "credential form in {text:?}"
            );
        }
    }
    assert!(
        texts.iter().all(|t| status(t) != 0),
        "a refusal had no status"
    );
}
