// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A server update that sends a new command or address keeps the transport
//! members it did not send, when the kind stays the same.

use super::*;

/// The transport a server holding `stored` has after one update sending
/// `new`.
fn updated(stored: TransportConfig, new: TransportConfig) -> TransportConfig {
    let mut cfg = empty_config();
    add_backend(&mut cfg, "svc", stored, String::new(), HashMap::new()).unwrap();
    let change = BackendUpdate {
        transport: Some(new),
        ..Default::default()
    };
    update_backend(&mut cfg, "svc", change).unwrap();
    cfg.backends["svc"].transport.clone()
}

/// XPORT.1: a new command or address of the same kind replaces that one
/// value; the folder, protocol version, HTTP mode and agent card path stay.
/// A change of kind still builds the transport fresh.
#[test]
fn xport1_a_same_kind_update_keeps_the_members_it_did_not_send() {
    let version = || Some("2025-06-18".to_owned());

    let TransportConfig::Stdio {
        command,
        cwd,
        protocol_version,
    } = updated(
        TransportConfig::Stdio {
            command: "old-server".into(),
            cwd: Some("/srv/tools".into()),
            protocol_version: version(),
        },
        stdio_transport("new-server"),
    )
    else {
        panic!("leg 1: no longer a command");
    };
    assert_eq!(
        (command.as_str(), cwd.as_deref(), protocol_version),
        ("new-server", Some("/srv/tools"), version()),
        "leg 1"
    );

    let TransportConfig::Http {
        http_url,
        streamable_http,
        protocol_version,
    } = updated(
        TransportConfig::Http {
            http_url: "https://one.example/mcp".into(),
            streamable_http: Some(true),
            protocol_version: version(),
        },
        TransportConfig::for_url("https://two.example/mcp"),
    )
    else {
        panic!("leg 2: no longer HTTP");
    };
    assert_eq!(
        (http_url.as_str(), streamable_http, protocol_version),
        ("https://two.example/mcp", Some(true), version()),
        "leg 2"
    );

    let http = TransportConfig::Http {
        http_url: "https://one.example/mcp".into(),
        streamable_http: None,
        protocol_version: version(),
    };
    let TransportConfig::WebSocket {
        ws_url,
        protocol_version,
    } = updated(http, TransportConfig::for_url("wss://three.example/ws"))
    else {
        panic!("leg 3: not a websocket");
    };
    assert_eq!(
        (ws_url.as_str(), protocol_version),
        ("wss://three.example/ws", None),
        "leg 3: a change of kind starts fresh"
    );

    let socket = TransportConfig::WebSocket {
        ws_url: "wss://four.example/ws".into(),
        protocol_version: version(),
    };
    let TransportConfig::WebSocket {
        ws_url,
        protocol_version,
    } = updated(socket, TransportConfig::for_url("wss://five.example/ws"))
    else {
        panic!("leg 5: no longer a websocket");
    };
    assert_eq!(
        (ws_url.as_str(), protocol_version),
        ("wss://five.example/ws", version()),
        "leg 5"
    );

    #[cfg(feature = "a2a")]
    agent_legs();
}

/// Legs 4 and 6 of XPORT.1: an address or an agent transport on an A2A
/// server keeps the agent kind and its card path; a websocket address is a
/// change of kind and starts fresh.
#[cfg(feature = "a2a")]
fn agent_legs() {
    let card = || Some("/.well-known/agent.json".to_owned());
    let agent = || TransportConfig::A2a {
        a2a_url: "https://agent.example".into(),
        a2a_agent_card_path: card(),
    };
    for (new, want, leg) in [
        (
            TransportConfig::for_url("https://other.example"),
            "https://other.example",
            "leg 4: an address",
        ),
        (
            TransportConfig::A2a {
                a2a_url: "https://third.example".into(),
                a2a_agent_card_path: None,
            },
            "https://third.example",
            "leg 4: an agent transport",
        ),
    ] {
        let TransportConfig::A2a {
            a2a_url,
            a2a_agent_card_path,
        } = updated(agent(), new)
        else {
            panic!("{leg}: no longer an agent");
        };
        assert_eq!(
            (a2a_url.as_str(), a2a_agent_card_path),
            (want, card()),
            "{leg}"
        );
    }

    let TransportConfig::WebSocket {
        ws_url,
        protocol_version,
    } = updated(agent(), TransportConfig::for_url("wss://six.example/ws"))
    else {
        panic!("leg 6: not a websocket");
    };
    assert_eq!(
        (ws_url.as_str(), protocol_version),
        ("wss://six.example/ws", None),
        "leg 6: a change of kind starts fresh"
    );
}
