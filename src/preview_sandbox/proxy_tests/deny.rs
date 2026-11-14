// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C4, C4i: an answer holding any denied address, or one of the host's own,
//! refuses the whole CONNECT with no dial.

use super::{GLOBAL, NPM, OTHER, begin, connect_status, deny_vectors::DENIED, ip, rig};

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
    *rig.interfaces.0.lock().expect("lock") = Some(vec![(GLOBAL, 32)]);
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
    *rig.interfaces.0.lock().expect("lock") = Some(vec![(GLOBAL, 32)]);
    assert_eq!(connect_status(&rig, host, &cred).await, 403);
    *rig.interfaces.0.lock().expect("lock") = Some(Vec::new());
    assert_eq!(connect_status(&rig, host, &cred).await, 200);
}

/// C4i, kills "a host-owned prefix compared as one address": a LOCAL route
/// over a public prefix makes every address in it the host's own, in every
/// form.
#[tokio::test]
async fn c4i_an_address_inside_a_host_owned_prefix_is_refused() {
    let rig = rig().await;
    let cred = begin(&rig);
    // 93.184.216.0/24 holds GLOBAL (93.184.216.34 = 5db8:d822) but is not it.
    *rig.interfaces.0.lock().expect("lock") = Some(vec![(ip("93.184.216.0"), 24)]);
    for form in ["93.184.216.34", "::ffff:5db8:d822", "::5db8:d822"] {
        rig.resolve.set(NPM, vec![ip(form)]);
        let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
        assert_eq!(st, 403, "{form}");
    }
    assert!(rig.connect.dials().is_empty(), "{:?}", rig.connect.dials());
    // Just outside the prefix: admitted, so the refusals above are the prefix's.
    rig.resolve.set(NPM, vec![ip("93.184.217.34")]);
    let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
    assert_eq!(st, 200);
}

/// C4i, G1 (T2), kills "host-owned addresses filtered, not refused": a mixed
/// answer, one permitted and one host-owned, refuses in both orders.
#[tokio::test]
async fn c4i_a_mixed_answer_with_a_host_address_refuses_in_both_orders() {
    let rig = rig().await;
    let cred = begin(&rig);
    *rig.interfaces.0.lock().expect("lock") = Some(vec![(OTHER, 32)]);
    for answer in [vec![GLOBAL, OTHER], vec![OTHER, GLOBAL]] {
        rig.resolve.set(NPM, answer.clone());
        let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
        assert_eq!(st, 403, "{answer:?}");
    }
    assert!(rig.connect.dials().is_empty(), "{:?}", rig.connect.dials());
}

/// C4i, kills "an unreadable interface set reads as empty": the CONNECT is
/// refused and nothing is dialled.
#[tokio::test]
async fn c4i_an_unreadable_interface_set_refuses_with_no_dial() {
    let rig = rig().await;
    let cred = begin(&rig);
    *rig.interfaces.0.lock().expect("lock") = None;
    let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
    assert_eq!(st, 403);
    assert!(rig.connect.dials().is_empty(), "{:?}", rig.connect.dials());
}

/// C4i, kills "an IPv6 host-owned prefix compared as one address": an IPv6
/// local route over a public prefix makes every address in it the host's.
#[tokio::test]
async fn c4i_an_address_inside_a_host_owned_ipv6_prefix_is_refused() {
    let rig = rig().await;
    let cred = begin(&rig);
    *rig.interfaces.0.lock().expect("lock") = Some(vec![(ip("2606:4700:10::"), 64)]);
    rig.resolve.set(NPM, vec![ip("2606:4700:10::1234")]);
    let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
    assert_eq!(st, 403);
    assert!(rig.connect.dials().is_empty(), "{:?}", rig.connect.dials());
    // Just outside the prefix: admitted, so the refusal above is the prefix's.
    rig.resolve.set(NPM, vec![ip("2606:4700:11::1234")]);
    let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
    assert_eq!(st, 200);
}

/// C4i, kills "an IPv4-mapped or compatible host network keeps its IPv6
/// prefix length": `::ffff:93.184.216.0/120` is the IPv4 /24, in both forms.
#[tokio::test]
async fn c4i_a_mapped_host_prefix_covers_its_ipv4_addresses() {
    let rig = rig().await;
    let cred = begin(&rig);
    for net in ["::ffff:93.184.216.0", "::93.184.216.0"] {
        *rig.interfaces.0.lock().expect("lock") = Some(vec![(ip(net), 120)]);
        rig.resolve.set(NPM, vec![GLOBAL]);
        let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
        assert_eq!(st, 403, "{net}/120");
        // Just outside the /24: admitted, so the refusal is the prefix's.
        rig.resolve.set(NPM, vec![ip("93.184.217.34")]);
        let st = connect_status(&rig, "registry.npmjs.org:443", &cred).await;
        assert_eq!(st, 200, "{net}/120");
    }
}

/// C4i, kills "a mask edge is off": prefix lengths 0, the family width and
/// past it, in both families and across them.
#[test]
fn c4i_network_containment_edges() {
    use super::super::within;
    let v4 = ip("93.184.216.34");
    let v6 = ip("2606:4700::1111");
    // /0 covers its whole family, and only that family.
    assert!(within(v4, ip("0.0.0.0"), 0));
    assert!(!within(v6, ip("0.0.0.0"), 0));
    assert!(within(v6, ip("::"), 0));
    // The family width is the one address; a length past it counts as the width.
    assert!(within(v4, v4, 32));
    assert!(!within(ip("93.184.216.35"), v4, 32));
    assert!(within(v4, v4, 40));
    assert!(within(v6, v6, 128));
    assert!(!within(ip("2606:4700::1112"), v6, 128));
    // An IPv4 address against a mapped IPv6 network, and the mapped address
    // against an IPv4 network.
    assert!(within(v4, ip("::ffff:93.184.216.0"), 120));
    assert!(within(ip("::ffff:93.184.216.34"), ip("93.184.216.0"), 24));
    assert!(!within(ip("93.184.217.34"), ip("::ffff:93.184.216.0"), 120));
}

/// C4i, kills "a native IPv6 network is read only through the mapped form":
/// `::/88` holds `::1:0:0` literally, though reading `::` as the mapped
/// `::ffff:0:0` would miss it.
#[test]
fn c4i_a_low_native_network_is_matched_literally() {
    use super::super::within;
    assert!(within(ip("::1:0:0"), ip("::"), 88));
    assert!(within(ip("::1:0:0"), ip("::"), 95));
    assert!(!within(ip("::1:0:0"), ip("::"), 96));
}
