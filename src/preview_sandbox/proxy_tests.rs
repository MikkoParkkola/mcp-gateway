// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! P1 rows C1-C11 (and R1-R3): the allowlist proxy admits only the three
//! registries on 443, behind a per-fetch credential, and dials only pinned,
//! permitted addresses. The three injected parts are unit-test fakes here, not
//! the `sandbox-fixtures` seams.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UnixStream};

use super::{AllowlistProxy, Connect, Credential, Interfaces, Resolve};

/// A globally routable address no deny rule covers.
const GLOBAL: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
const NPM: &str = "registry.npmjs.org";

/// Suspends a fake call until the test releases it (C10).
#[derive(Default)]
struct Gate {
    on: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl Gate {
    fn close(&self) {
        self.on.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    async fn pass(&self) {
        if self.on.load(std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
    }
}

#[derive(Default)]
struct FakeResolve {
    table: Mutex<HashMap<String, Vec<IpAddr>>>,
    gate: Gate,
}

impl FakeResolve {
    fn set(&self, host: &str, addrs: Vec<IpAddr>) {
        self.table
            .lock()
            .expect("lock")
            .insert(host.to_owned(), addrs);
    }
}

#[async_trait]
impl Resolve for FakeResolve {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.gate.pass().await;
        self.table
            .lock()
            .expect("lock")
            .get(host)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such host"))
    }
}

/// Records every dial, then connects to the local echo server.
struct FakeConnect {
    dials: Mutex<Vec<SocketAddr>>,
    echo: SocketAddr,
    gate: Gate,
}

impl FakeConnect {
    fn dials(&self) -> Vec<SocketAddr> {
        self.dials.lock().expect("lock").clone()
    }
}

#[async_trait]
impl Connect for FakeConnect {
    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        self.dials.lock().expect("lock").push(addr);
        self.gate.pass().await;
        TcpStream::connect(self.echo).await
    }
}

struct FakeInterfaces(Mutex<Vec<IpAddr>>);

impl Interfaces for FakeInterfaces {
    fn addresses(&self) -> Vec<IpAddr> {
        self.0.lock().expect("lock").clone()
    }
}

/// Which entry a request uses.
#[derive(Clone, Copy)]
enum Entry {
    Tcp,
    Unix,
}

const ENTRIES: [Entry; 2] = [Entry::Tcp, Entry::Unix];

struct Rig {
    proxy: AllowlistProxy,
    resolve: Arc<FakeResolve>,
    connect: Arc<FakeConnect>,
    interfaces: Arc<FakeInterfaces>,
}

/// A rig whose registry names resolve to [`GLOBAL`].
async fn rig() -> Rig {
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let echo_addr = echo.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let resolve = Arc::new(FakeResolve::default());
    for host in [NPM, "pypi.org", "files.pythonhosted.org"] {
        resolve.set(host, vec![GLOBAL]);
    }
    let connect = Arc::new(FakeConnect {
        dials: Mutex::new(Vec::new()),
        echo: echo_addr,
        gate: Gate::default(),
    });
    let interfaces = Arc::new(FakeInterfaces(Mutex::new(Vec::new())));
    let proxy = AllowlistProxy::bind(resolve.clone(), connect.clone(), interfaces.clone())
        .await
        .expect("proxy bind");
    Rig {
        proxy,
        resolve,
        connect,
        interfaces,
    }
}

/// Raw CONNECT bytes for `authority`, with an optional auth header value.
fn connect_bytes(authority: &str, auth: Option<&str>) -> Vec<u8> {
    let mut s = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(v) = auth {
        s.push_str(&format!("Proxy-Authorization: {v}\r\n"));
    }
    s.push_str("\r\n");
    s.into_bytes()
}

/// Read until the blank line ending the response head, or EOF or a timeout.
async fn read_head<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    let read = async {
        while !out.ends_with(b"\r\n\r\n") {
            match s.read(&mut byte).await {
                Ok(1) => out.push(byte[0]),
                _ => break,
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(30), read).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// The numeric status of a response head; 0 when there is none (closed).
fn status(head: &str) -> u16 {
    head.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// Send `bytes` through `entry` and return the response head.
async fn send(rig: &Rig, entry: Entry, bytes: &[u8]) -> String {
    match open(rig, entry, bytes).await {
        Some(Opened::Tcp(mut s)) => read_head(&mut s).await,
        Some(Opened::Unix(mut s)) => read_head(&mut s).await,
        None => String::new(),
    }
}

enum Opened {
    Tcp(TcpStream),
    Unix(UnixStream),
}

/// Connect through `entry` and write `bytes`; `None` when the connection
/// itself is refused.
async fn open(rig: &Rig, entry: Entry, bytes: &[u8]) -> Option<Opened> {
    match entry {
        Entry::Tcp => {
            let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.proxy.port()))
                .await
                .ok()?;
            s.write_all(bytes).await.ok()?;
            Some(Opened::Tcp(s))
        }
        Entry::Unix => {
            let mut s = UnixStream::connect(rig.proxy.unix_path()).await.ok()?;
            s.write_all(bytes).await.ok()?;
            Some(Opened::Unix(s))
        }
    }
}

/// CONNECT `authority` with `cred`'s header; the response status.
async fn connect_status(rig: &Rig, entry: Entry, authority: &str, cred: &Credential) -> u16 {
    let bytes = connect_bytes(authority, Some(&cred.basic()));
    status(&send(rig, entry, &bytes).await)
}

/// After a 200, bytes written to the tunnel come back from the echo server.
async fn tunnel_echoes<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S) -> bool {
    if s.write_all(b"ping").await.is_err() {
        return false;
    }
    let mut buf = [0u8; 4];
    matches!(
        tokio::time::timeout(Duration::from_secs(30), s.read_exact(&mut buf)).await,
        Ok(Ok(_))
    ) && &buf == b"ping"
}

/// C1/R1, kills "port open outside a fetch": with no live credential neither
/// entry admits anything, nothing is dialled, and the port stays bound.
#[tokio::test]
async fn c1_outside_a_fetch_nothing_is_admitted_and_the_port_stays_bound() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    rig.proxy.expire(&cred);
    for entry in ENTRIES {
        let st = connect_status(&rig, entry, "registry.npmjs.org:443", &cred).await;
        assert_ne!(st, 200, "a tunnel opened outside a fetch");
    }
    assert!(rig.connect.dials().is_empty());
    let rebind = TcpListener::bind((Ipv4Addr::LOCALHOST, rig.proxy.port())).await;
    assert!(rebind.is_err(), "the port was released");
}

/// C2, kills "suffix host match": exactly the three registries on 443 open a
/// tunnel to the pinned address.
#[tokio::test]
async fn c2_only_the_three_registries_on_443_are_admitted() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    for host in ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"] {
        for entry in ENTRIES {
            let bytes = connect_bytes(&format!("{host}:443"), Some(&cred.basic()));
            let opened = open(&rig, entry, &bytes).await.expect("connect");
            let ok = match opened {
                Opened::Tcp(mut s) => {
                    status(&read_head(&mut s).await) == 200 && tunnel_echoes(&mut s).await
                }
                Opened::Unix(mut s) => {
                    status(&read_head(&mut s).await) == 200 && tunnel_echoes(&mut s).await
                }
            };
            assert!(ok, "{host} was not admitted");
        }
    }
    let dials = rig.connect.dials();
    assert!(!dials.is_empty());
    assert!(dials.iter().all(|d| *d == SocketAddr::new(GLOBAL, 443)));
}

/// C2, kills "suffix host match": near-miss names and ports get 403 and no
/// dial.
#[tokio::test]
async fn c2_near_miss_hosts_and_ports_are_refused_with_403() {
    let rig = rig().await;
    for host in [
        "evilregistry.npmjs.org",
        "registry.npmjs.org.evil.test",
        "npmjs.org",
        "pypi.org.evil.test",
        "notpypi.org",
        "pythonhosted.org",
    ] {
        rig.resolve.set(host, vec![GLOBAL]);
    }
    let cred = rig.proxy.begin_fetch();
    for authority in [
        "evilregistry.npmjs.org:443",
        "registry.npmjs.org.evil.test:443",
        "npmjs.org:443",
        "pypi.org.evil.test:443",
        "notpypi.org:443",
        "pythonhosted.org:443",
        "registry.npmjs.org:80",
        "registry.npmjs.org:8443",
        "pypi.org:22",
    ] {
        for entry in ENTRIES {
            let st = connect_status(&rig, entry, authority, &cred).await;
            assert_eq!(st, 403, "{authority}");
        }
    }
    assert!(rig.connect.dials().is_empty());
}

/// C3, kills "credential check removed": a missing, wrong or expired
/// credential gets 407 through either entry, and nothing is dialled.
#[tokio::test]
async fn c3_missing_wrong_or_expired_credential_gets_407() {
    let rig = rig().await;
    let old = rig.proxy.begin_fetch();
    rig.proxy.expire(&old);
    let live = rig.proxy.begin_fetch();
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
    let live = rig.proxy.begin_fetch();
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
    let cred = rig.proxy.begin_fetch();
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

use super::deny_vectors::DENIED;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap_or_else(|_| panic!("bad address {s}"))
}

/// C4, kills "a range deleted": every denied address, alone, refuses the
/// CONNECT with 403 and nothing is dialled.
#[tokio::test]
async fn c4_every_denied_address_refuses_the_connect() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    for denied in DENIED {
        rig.resolve.set(NPM, vec![ip(denied)]);
        let st = connect_status(&rig, Entry::Tcp, "registry.npmjs.org:443", &cred).await;
        assert_eq!(st, 403, "{denied} was not refused");
    }
    assert!(rig.connect.dials().is_empty(), "{:?}", rig.connect.dials());
}

/// C4, kills "a range deleted" on the Unix entry: a sample of both families.
#[tokio::test]
async fn c4_denied_addresses_are_refused_through_the_unix_socket() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    for denied in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "::ffff:127.0.0.1",
    ] {
        rig.resolve.set(NPM, vec![ip(denied)]);
        let st = connect_status(&rig, Entry::Unix, "registry.npmjs.org:443", &cred).await;
        assert_eq!(st, 403, "{denied}");
    }
    assert!(rig.connect.dials().is_empty());
}

/// C4, kills "only the bad address skipped": a mixed answer (permitted plus
/// denied, both orders, v4 and v6) refuses the whole CONNECT with no dial.
#[tokio::test]
async fn c4_a_mixed_answer_refuses_the_whole_connect() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    let global6 = ip("2606:4700::1111");
    for bad in ["127.0.0.1", "10.0.0.1", "::1", "fe80::1", "::ffff:10.0.0.1"] {
        let bad = ip(bad);
        for answer in [
            vec![GLOBAL, bad],
            vec![bad, GLOBAL],
            vec![global6, bad],
            vec![bad, global6],
        ] {
            rig.resolve.set(NPM, answer.clone());
            let st = connect_status(&rig, Entry::Tcp, "registry.npmjs.org:443", &cred).await;
            assert_eq!(st, 403, "{answer:?}");
        }
    }
    assert!(rig.connect.dials().is_empty(), "{:?}", rig.connect.dials());
}

/// C4i, kills "interface guard deleted": an otherwise permitted global
/// address that is the host's own is refused, as are its mapped and
/// compatible IPv6 forms.
#[tokio::test]
async fn c4i_a_host_interface_address_is_refused_in_every_form() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    *rig.interfaces.0.lock().expect("lock") = vec![GLOBAL];
    // 93.184.216.34 = 5db8:d822
    for form in ["93.184.216.34", "::ffff:5db8:d822", "::5db8:d822"] {
        rig.resolve.set(NPM, vec![ip(form)]);
        let st = connect_status(&rig, Entry::Tcp, "registry.npmjs.org:443", &cred).await;
        assert_eq!(st, 403, "{form}");
    }
    assert!(rig.connect.dials().is_empty());
}

/// C4i, kills "interface set cached": the set is read at each CONNECT.
#[tokio::test]
async fn c4i_the_interface_set_is_read_at_each_connect() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    let host = "registry.npmjs.org:443";
    assert_eq!(connect_status(&rig, Entry::Tcp, host, &cred).await, 200);
    *rig.interfaces.0.lock().expect("lock") = vec![GLOBAL];
    assert_eq!(connect_status(&rig, Entry::Tcp, host, &cred).await, 403);
    *rig.interfaces.0.lock().expect("lock") = Vec::new();
    assert_eq!(connect_status(&rig, Entry::Tcp, host, &cred).await, 200);
}

impl Opened {
    async fn head(&mut self) -> String {
        match self {
            Self::Tcp(s) => read_head(s).await,
            Self::Unix(s) => read_head(s).await,
        }
    }

    async fn echoes(&mut self) -> bool {
        match self {
            Self::Tcp(s) => tunnel_echoes(s).await,
            Self::Unix(s) => tunnel_echoes(s).await,
        }
    }

    /// True when the stream is dead: a write or read fails or hits EOF.
    async fn closed(&mut self) -> bool {
        !self.echoes().await
    }
}

/// An open, working tunnel through `entry` under `cred`.
async fn open_tunnel(rig: &Rig, entry: Entry, cred: &Credential) -> Opened {
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let mut t = open(rig, entry, &bytes).await.expect("connect");
    assert_eq!(status(&t.head().await), 200);
    assert!(t.echoes().await, "tunnel does not echo before expiry");
    t
}

/// C5, kills "tunnels kept on expiry": expiry closes a tunnel already open.
#[tokio::test]
async fn c5_expiry_closes_tunnels_already_open() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    let mut t = open_tunnel(&rig, Entry::Tcp, &cred).await;
    rig.proxy.expire(&cred);
    assert!(t.closed().await, "tunnel survived expiry");
}

/// R3, kills "tunnels kept on expiry" on the Unix socket.
#[tokio::test]
async fn r3_expiry_closes_tunnels_opened_through_the_unix_socket() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    let mut t = open_tunnel(&rig, Entry::Unix, &cred).await;
    rig.proxy.expire(&cred);
    assert!(t.closed().await, "tunnel survived expiry");
}

/// C6, kills "git hosts admitted": git hosting names are refused with 403.
#[tokio::test]
async fn c6_git_hosts_are_refused() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    for host in [
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeload.github.com",
        "git.sr.ht",
    ] {
        rig.resolve.set(host, vec![GLOBAL]);
        for entry in ENTRIES {
            let st = connect_status(&rig, entry, &format!("{host}:443"), &cred).await;
            assert_eq!(st, 403, "{host}");
        }
    }
    assert!(rig.connect.dials().is_empty());
}

/// C7, kills "method check removed": other methods are refused even with a
/// valid credential and an allowlisted target.
#[tokio::test]
async fn c7_non_connect_methods_are_refused() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    let auth = cred.basic();
    for method in [
        "GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE", "TRACE", "get", "CONNECTX",
    ] {
        let req = format!(
            "{method} http://registry.npmjs.org/ HTTP/1.1\r\nHost: registry.npmjs.org\r\n\
             Proxy-Authorization: {auth}\r\n\r\n"
        );
        let st = status(&send(&rig, Entry::Tcp, req.as_bytes()).await);
        assert!(matches!(st, 400 | 403 | 405), "{method} gave {st}");
    }
    assert!(rig.connect.dials().is_empty());
}

/// C7, kills "authority checks loosened": malformed or non-canonical
/// authorities are refused.
#[tokio::test]
async fn c7_non_canonical_authorities_are_refused() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    for authority in [
        "93.184.216.34:443",
        "[2606:4700::1111]:443",
        "user@registry.npmjs.org:443",
        "user:pw@registry.npmjs.org:443",
        "registry%2Enpmjs.org:443",
        "%72egistry.npmjs.org:443",
        "registry.npmjs.org.:443",
        "REGISTRY.NPMJS.ORG:443",
        "Registry.npmjs.org:443",
        "registry.npmjs.org:0443",
        "registry.npmjs.org: 443",
        "registry.npmjs.org:443 ",
        "registry.npmjs.org",
        "registry.npmjs.org:",
        ":443",
    ] {
        for entry in ENTRIES {
            let st = connect_status(&rig, entry, authority, &cred).await;
            assert!(matches!(st, 400 | 403), "{authority:?} gave {st}");
        }
    }
    assert!(rig.connect.dials().is_empty());
}

/// C7, kills "Host header ignored": a Host header disagreeing with the CONNECT
/// authority is refused.
#[tokio::test]
async fn c7_a_disagreeing_host_header_is_refused() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    let req = format!(
        "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: github.com:443\r\n\
         Proxy-Authorization: {}\r\n\r\n",
        cred.basic()
    );
    let st = status(&send(&rig, Entry::Tcp, req.as_bytes()).await);
    assert!(matches!(st, 400 | 403), "gave {st}");
    assert!(rig.connect.dials().is_empty());
}

/// C8/V3, kills "constant credential": credentials differ per fetch, carry
/// at least 32 random bytes as URL-safe base64, and an expired one from
/// fetch 1 is refused during fetch 2.
#[tokio::test]
async fn c8_credentials_are_random_per_fetch_and_the_old_one_is_dead() {
    let rig = rig().await;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..16 {
        let c = rig.proxy.begin_fetch();
        rig.proxy.expire(&c);
        assert!(seen.insert(c.secret().to_owned()), "repeated credential");
        let s = c.secret();
        assert!(s.len() >= 43, "under 32 bytes of base64: {}", s.len());
        assert!(
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }
    let first = rig.proxy.begin_fetch();
    rig.proxy.expire(&first);
    let second = rig.proxy.begin_fetch();
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
    let cred = rig.proxy.begin_fetch();
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

/// C10, kills "a tunnel usable after expiry": expiry while a CONNECT is
/// suspended in resolution leaves no usable tunnel and no dial.
#[tokio::test]
async fn c10_expiry_during_resolution_leaves_no_usable_tunnel() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    rig.resolve.gate.close();
    let port = rig.proxy.port();
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let task = tokio::spawn(async move {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.ok()?;
        s.write_all(&bytes).await.ok()?;
        let ok = status(&read_head(&mut s).await) == 200 && tunnel_echoes(&mut s).await;
        Some(ok)
    });
    rig.resolve.gate.entered.notified().await;
    rig.proxy.expire(&cred);
    rig.resolve.gate.release.notify_one();
    let usable = task.await.expect("task");
    assert_ne!(usable, Some(true), "a tunnel was usable after expiry");
    assert!(rig.connect.dials().is_empty(), "dialled after expiry");
}

/// C10, kills "a tunnel usable after expiry": expiry while a CONNECT is
/// suspended in the dial leaves no usable tunnel.
#[tokio::test]
async fn c10_expiry_during_dialling_leaves_no_usable_tunnel() {
    let rig = rig().await;
    let cred = rig.proxy.begin_fetch();
    rig.connect.gate.close();
    let port = rig.proxy.port();
    let bytes = connect_bytes("registry.npmjs.org:443", Some(&cred.basic()));
    let task = tokio::spawn(async move {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.ok()?;
        s.write_all(&bytes).await.ok()?;
        let ok = status(&read_head(&mut s).await) == 200 && tunnel_echoes(&mut s).await;
        Some(ok)
    });
    rig.connect.gate.entered.notified().await;
    rig.proxy.expire(&cred);
    rig.connect.gate.release.notify_one();
    let usable = task.await.expect("task");
    assert_ne!(usable, Some(true), "a tunnel was usable after expiry");
}
