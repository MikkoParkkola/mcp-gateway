// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use serde_yaml::Value;

const COMPOSE: &str = include_str!("../deploy/single-node/docker-compose.yaml");

/// A container binds `0.0.0.0` to receive anything at all, and on a non-loopback
/// bind the Host gate admits a NAME only when `server.public_url` declares one.
///
/// Everything here dials a name: the client on the host reaches
/// `http://localhost:39400`, and the healthcheck inside the container dials
/// `localhost` too. Undeclared, all of it is refused as a rebinding attempt
/// while the port stays open.
#[test]
fn the_compose_service_declares_the_name_clients_dial() {
    let compose: Value = serde_yaml::from_str(COMPOSE).expect("compose yaml must parse");
    let service = &compose["services"]["mcp-gateway"];

    let command = service["command"]
        .as_sequence()
        .expect("command is a list")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(
        command.contains(&"0.0.0.0"),
        "this test exists because the container binds a non-loopback address"
    );

    let public_url = service["environment"]["MCP_GATEWAY_SERVER__PUBLIC_URL"]
        .as_str()
        .expect("a 0.0.0.0 bind must declare the name clients dial");
    assert!(
        public_url.contains("localhost:39400"),
        "the declared name must be the one the published port answers on, got {public_url}"
    );
}

/// C3: `init` writes authentication on, so the container's 0.0.0.0 bind carries
/// a credential over plain HTTP. Only the loopback publish keeps it off the
/// network, which is what `host_local_publish` asserts.
#[test]
fn the_compose_service_names_its_loopback_publish_as_the_cleartext_boundary() {
    let compose: Value = serde_yaml::from_str(COMPOSE).expect("compose yaml must parse");
    let service = &compose["services"]["mcp-gateway"];
    assert_eq!(
        service["environment"]["MCP_GATEWAY_SERVER__CLEARTEXT_HTTP"].as_str(),
        Some("host_local_publish")
    );
    let ports = service["ports"].as_sequence().expect("ports is a list");
    assert!(!ports.is_empty(), "the service publishes its port");
    for port in ports {
        assert!(
            is_loopback_publish(port),
            "host_local_publish is honest only while every publish is loopback: {port:?}"
        );
    }
}

/// Short syntax `HOST_IP:HOST:CONTAINER`, or the long map form, whose `host_ip`
/// defaults to every interface when omitted.
fn is_loopback_publish(port: &Value) -> bool {
    match port {
        Value::String(p) => p.starts_with("127.0.0.1:"),
        Value::Mapping(_) => port["host_ip"].as_str() == Some("127.0.0.1"),
        other => panic!("unrecognised ports entry {other:?}"),
    }
}

/// Both `ports:` syntaxes, loopback and not: a long-syntax entry without
/// `host_ip` publishes on every interface.
#[test]
fn both_port_syntaxes_are_judged() {
    for (yaml, loopback) in [
        ("\"127.0.0.1:39400:39400\"", true),
        ("\"39400:39400\"", false),
        ("\"0.0.0.0:39400:39400\"", false),
        (
            "{target: 39400, published: 39400, host_ip: 127.0.0.1}",
            true,
        ),
        ("{target: 39400, published: 39400}", false),
    ] {
        let port: Value = serde_yaml::from_str(yaml).expect("yaml");
        assert_eq!(is_loopback_publish(&port), loopback, "{yaml}");
    }
}
