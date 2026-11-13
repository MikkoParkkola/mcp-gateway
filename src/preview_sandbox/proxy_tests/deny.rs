// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C4, C4i: an answer holding any denied address, or one of the host's own,
//! refuses the whole CONNECT with no dial.

use super::{GLOBAL, NPM, begin, connect_status, deny_vectors::DENIED, ip, rig};

/// C4, kills "a range deleted": every denied address, alone, refuses the
/// CONNECT with 403 and nothing is dialled.
#[tokio::test]
async fn c4_every_denied_address_refuses_the_connect() {
    let rig = rig().await;
    let cred = begin(&rig);
    for denied in DENIED {
        rig.resolve.set(NPM, vec![ip(denied)]);
        let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
        assert_eq!(st, 403, "{denied} was not refused");
    }
    assert!(rig.connect.dials().is_empty(), "{:?}", rig.connect.dials());
}

/// C4, kills "a range deleted" on the Unix entry: a sample of both families.
#[tokio::test]
async fn c4_denied_addresses_are_refused_through_the_unix_socket() {
    let rig = rig().await;
    let cred = begin(&rig);
    for denied in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "::ffff:127.0.0.1",
    ] {
        rig.resolve.set(NPM, vec![ip(denied)]);
        let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
        assert_eq!(st, 403, "{denied}");
    }
    assert!(rig.connect.dials().is_empty());
}

/// C4, kills "only the bad address skipped": a mixed answer (permitted plus
/// denied, both orders, v4 and v6) refuses the whole CONNECT with no dial.
#[tokio::test]
async fn c4_a_mixed_answer_refuses_the_whole_connect() {
    let rig = rig().await;
    let cred = begin(&rig);
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
            let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
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
    let cred = begin(&rig);
    *rig.interfaces.0.lock().expect("lock") = vec![GLOBAL];
    // 93.184.216.34 = 5db8:d822
    for form in ["93.184.216.34", "::ffff:5db8:d822", "::5db8:d822"] {
        rig.resolve.set(NPM, vec![ip(form)]);
        let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
        assert_eq!(st, 403, "{form}");
    }
    assert!(rig.connect.dials().is_empty());
}

/// C4i, kills "interface set cached": the set is read at each CONNECT.
#[tokio::test]
async fn c4i_the_interface_set_is_read_at_each_connect() {
    let rig = rig().await;
    let cred = begin(&rig);
    let host = "registry.npmjs.org:443";
    assert_eq!(connect_status(&rig, host, &cred).await, 200);
    *rig.interfaces.0.lock().expect("lock") = vec![GLOBAL];
    assert_eq!(connect_status(&rig, host, &cred).await, 403);
    *rig.interfaces.0.lock().expect("lock") = Vec::new();
    assert_eq!(connect_status(&rig, host, &cred).await, 200);
}
