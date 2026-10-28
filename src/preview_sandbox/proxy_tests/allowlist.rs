// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C2, C6, C7: only CONNECT to the three registries on 443, named exactly,
//! is admitted.

use super::{
    ENTRIES, Entry, GLOBAL, Opened, begin, connect_bytes, connect_status, open, read_head, rig,
    send, status, tunnel_echoes,
};
use std::net::SocketAddr;

/// C2, kills "suffix host match": exactly the three registries on 443 open a
/// tunnel to the pinned address.
#[tokio::test]
async fn c2_only_the_three_registries_on_443_are_admitted() {
    let rig = rig().await;
    let cred = begin(&rig);
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
        for entry in ENTRIES {
            let st = connect_status(&rig, entry, authority, &cred).await;
            assert_eq!(st, 403, "{authority}");
        }
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
    let cred = begin(&rig);
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
    let cred = begin(&rig);
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
    let cred = begin(&rig);
    let req = format!(
        "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: github.com:443\r\n\
         Proxy-Authorization: {}\r\n\r\n",
        cred.basic()
    );
    let st = status(&send(&rig, Entry::Tcp, req.as_bytes()).await);
    assert!(matches!(st, 400 | 403), "gave {st}");
    assert!(rig.connect.dials().is_empty());
}
