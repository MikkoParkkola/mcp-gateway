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
