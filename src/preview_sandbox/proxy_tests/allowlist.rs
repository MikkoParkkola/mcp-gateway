// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C2, C6, C7: only CONNECT to the three registries on 443, named exactly, ASCII case aside,
//! is admitted.

use super::{GLOBAL, begin, connect_bytes, connect_status, open, rig, send, status};
use std::net::SocketAddr;

/// C2, kills "suffix host match": exactly the three registries on 443 open a
/// tunnel to the pinned address.
#[tokio::test]
async fn c2_only_the_three_registries_on_443_are_admitted() {
    let rig = rig().await;
    let cred = begin(&rig);
    for host in ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"] {
        let bytes = connect_bytes(&format!("{host}:443"), Some(&cred.basic()));
        let mut opened = open(&rig, &bytes).await.expect("connect");
        let ok = status(&opened.head().await) == 200 && opened.echoes().await;
        assert!(ok, "{host} was not admitted");
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
    let cred = begin(&rig);
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
        let st = connect_status(&rig, authority, &cred).await;
        assert_eq!(st, 403, "{authority}");
    }
    assert!(rig.connect.dials().is_empty());
}

/// C6, kills "git hosts admitted": git hosting names are refused with 403.
#[tokio::test]
async fn c6_git_hosts_are_refused() {
    let rig = rig().await;
    let cred = begin(&rig);
    for host in [
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeload.github.com",
        "git.sr.ht",
    ] {
        rig.resolve.set(host, vec![GLOBAL]);
        let st = connect_status(&rig, &format!("{host}:443"), &cred).await;
        assert_eq!(st, 403, "{host}");
    }
    assert!(rig.connect.dials().is_empty());
}

/// C7, kills "method check removed": other methods are refused even with a
/// valid credential and an allowlisted target.
#[tokio::test]
async fn c7_non_connect_methods_are_refused() {
    let rig = rig().await;
    let cred = begin(&rig);
    let auth = cred.basic();
    for method in [
        "GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE", "TRACE", "get", "CONNECTX",
    ] {
        let req = format!(
            "{method} http://registry.npmjs.org/ HTTP/1.1\r\nHost: registry.npmjs.org\r\n\
             Proxy-Authorization: {auth}\r\n\r\n"
        );
        let st = status(&send(&rig, req.as_bytes()).await);
        assert!(matches!(st, 400 | 403 | 405), "{method} gave {st}");
    }
    assert!(rig.connect.dials().is_empty());
}

/// C7, kills "authority checks loosened": malformed or non-canonical
/// authorities are refused.
#[tokio::test]
async fn c7_non_canonical_authorities_are_refused() {
    let rig = rig().await;
    let cred = begin(&rig);
    for authority in [
        "93.184.216.34:443",
        "[2606:4700::1111]:443",
        "user@registry.npmjs.org:443",
        "user:pw@registry.npmjs.org:443",
        "registry%2Enpmjs.org:443",
        "%72egistry.npmjs.org:443",
        "registry.npmjs.org.:443",
        "registry.npmjs.org:0443",
        "registry.npmjs.org: 443",
        "registry.npmjs.org:443 ",
        "registry.npmjs.org",
        "registry.npmjs.org:",
        ":443",
    ] {
        let st = connect_status(&rig, authority, &cred).await;
        assert!(matches!(st, 400 | 403), "{authority:?} gave {st}");
    }
    assert!(rig.connect.dials().is_empty());
}

/// C7, kills "Host header ignored": a Host header disagreeing with the CONNECT
/// authority is refused.
#[tokio::test]
async fn c7_a_disagreeing_host_header_is_refused() {
    let rig = rig().await;
    let cred = begin(&rig);
    let req = format!(
        "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: github.com:443\r\n\
         Proxy-Authorization: {}\r\n\r\n",
        cred.basic()
    );
    let st = status(&send(&rig, req.as_bytes()).await);
    assert!(matches!(st, 400 | 403), "gave {st}");
    assert!(rig.connect.dials().is_empty());
}

/// Kills "an uppercase registry name or Host is refused as a different authority".
#[tokio::test]
async fn t2_an_uppercase_registry_name_is_admitted() {
    let rig = rig().await;
    let cred = begin(&rig);
    for authority in ["REGISTRY.NPMJS.ORG:443", "Registry.npmjs.org:443"] {
        assert_eq!(
            connect_status(&rig, authority, &cred).await,
            200,
            "{authority}"
        );
    }
    let req = format!(
        "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: REGISTRY.npmjs.org:443\r\n\
         Proxy-Authorization: {}\r\n\r\n",
        cred.basic()
    );
    assert_eq!(status(&send(&rig, req.as_bytes()).await), 200);
    let dials = rig.connect.dials();
    assert!(!dials.is_empty());
    assert!(dials.iter().all(|d| *d == SocketAddr::new(GLOBAL, 443)));
}

/// Kills "a request head over 8 KiB is still dialled".
#[tokio::test]
async fn t2_a_head_over_eight_kib_is_refused() {
    let rig = rig().await;
    let cred = begin(&rig);
    let req = format!(
        "CONNECT registry.npmjs.org:443 HTTP/1.1\r\n\
         Proxy-Authorization: {}\r\n\
         X-Pad: {}\r\n\r\n",
        cred.basic(),
        "a".repeat(9000)
    );
    // The proxy stops reading at 8 KiB and the socket buffer is that size, so
    // the refusal is only visible while the rest of the head is still written.
    let stream = tokio::net::UnixStream::connect(rig.proxy.unix_path())
        .await
        .expect("connect");
    let (mut reader, mut writer) = stream.into_split();
    let (head, _) = tokio::join!(super::read_head(&mut reader), async {
        use tokio::io::AsyncWriteExt as _;
        let _ = writer.write_all(req.as_bytes()).await;
    });
    assert_eq!(status(&head), 400);
    assert!(rig.connect.dials().is_empty());
}
