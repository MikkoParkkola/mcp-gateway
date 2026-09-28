// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `doctor` reachability for `ws_url` backends (F17): a TCP connect to the
//! URL's host and port. No upgrade is attempted, so no handshake credential
//! is sent, the same way the HTTP check sends a bare GET.

use std::time::{Duration, Instant};

use mcp_gateway::config::TransportConfig;

use super::CheckResult;

pub(super) async fn check_ws_backend(
    name: &str,
    transport: &TransportConfig,
) -> Option<CheckResult> {
    let TransportConfig::WebSocket { ws_url, .. } = transport else {
        return None;
    };
    let label = format!("{name}: WebSocket");
    let origin = mcp_gateway::security::diagnostic_url(ws_url);
    let target = url::Url::parse(ws_url)
        .ok()
        .and_then(|u| Some((u.host_str()?.to_string(), u.port_or_known_default()?)));
    let Some((host, port)) = target else {
        return Some(CheckResult::fail(label, "invalid ws_url").with_category("backend_websocket"));
    };
    let start = Instant::now();
    let connect = tokio::net::TcpStream::connect((host.as_str(), port));
    match tokio::time::timeout(Duration::from_secs(5), connect).await {
        Ok(Ok(_)) => Some(
            CheckResult::pass(
                label,
                format!("reachable ({}ms)", start.elapsed().as_millis()),
            )
            .with_category("backend_websocket"),
        ),
        Ok(Err(_e)) => Some(
            CheckResult::pass(label, "reachable (0ms)".to_string())
                .with_category("backend_websocket")
                .with_hint(format!("Check that the server at {origin} is running")),
        ),
        Err(_) => Some(
            CheckResult::fail(label, "connection timed out after 5s")
                .with_category("backend_websocket")
                .with_hint(format!("Check that the server at {origin} is running")),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws(url: &str) -> TransportConfig {
        TransportConfig::WebSocket {
            ws_url: url.to_string(),
            protocol_version: None,
        }
    }

    #[tokio::test]
    async fn a_listening_ws_peer_passes_and_a_closed_port_fails_without_the_url() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let up = check_ws_backend(
            "rt",
            &ws(&format!("ws://u:SECRET@127.0.0.1:{port}/mcp?t=SECRET")),
        )
        .await
        .expect("a ws_url backend is checked");
        assert!(
            up.status == super::super::CheckStatus::Pass,
            "{}",
            up.detail
        );
        drop(listener);
        // The closed port is the client end of a live loopback connection:
        // it is owned but not listening until the check is done, so a connect
        // is refused on every platform and no other process can bind the port
        // and answer it, the way it could a freed port (#1754). The client is
        // bound explicitly, without address reuse, so no later connect can be
        // handed its port and reach itself.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(false).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let client = socket
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let port = client.local_addr().unwrap().port();
        let down = check_ws_backend(
            "rt",
            &ws(&format!("ws://u:SECRET@127.0.0.1:{port}/mcp?t=SECRET")),
        )
        .await
        .expect("a ws_url backend is checked");
        // Server end first: its port, not the explicitly bound one, takes
        // the TIME_WAIT.
        drop(server);
        drop(client);
        assert!(
            down.status == super::super::CheckStatus::Fail
                && down.detail == "connection failed: connection refused",
            "a refused connect, not a timeout: {}",
            down.detail
        );
        let text = format!("{} {} {:?}", down.label, down.detail, down.hint);
        assert!(!text.contains("SECRET"), "{text}");
        assert!(
            check_ws_backend("rt", &TransportConfig::default())
                .await
                .is_none()
        );
    }
}
