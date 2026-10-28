// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A real socket: a client that stops reading fills the kernel's buffers, the
//! server's write stalls, and the 30 s write limit closes the stream. The
//! runtime clock is paused, so the limit passes without waiting for it; the
//! socket, the HTTP server and the transport are real.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};

use super::*;

/// Enough long-named servers that one status frame is a few hundred KB.
const SERVERS: usize = 300;
/// Status changes pushed at the stalled client: far more than any buffer holds.
const CHANGES: usize = 100;

fn big_gateway(state: &AppState) -> Arc<crate::backend::Backend> {
    for i in 0..SERVERS {
        let name = format!("{i:0>200}");
        let _ = state
            .backends
            .register(http_backend_at(&name, "http://127.0.0.1:9/mcp"));
    }
    let name = format!("{:0>200}", 0);
    state.backends.get(&name).expect("registered")
}

async fn serve(state: &Arc<AppState>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    let app = create_router(Arc::clone(state)).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

#[tokio::test]
async fn a_client_that_stops_reading_a_real_socket_is_closed_and_its_slot_returns() {
    let (state, _dir) = fixture().await;
    let busy = big_gateway(&state);
    let addr = serve(&state).await;
    let socket = TcpSocket::new_v4().expect("socket");
    socket
        .set_recv_buffer_size(4096)
        .expect("small receive buffer");
    let mut client = socket.connect(addr).await.expect("connect");
    let ask =
        format!("GET {STREAM} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {BEARER}\r\n\r\n");
    client.write_all(ask.as_bytes()).await.expect("request");
    // One read proves the stream opened; after that the client never reads.
    let mut head = [0u8; 512];
    let n = client.read(&mut head).await.expect("response head");
    let head = String::from_utf8_lossy(&head[..n]);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let hub = state.dashboard_bootstrap.stream_hub();
    assert_eq!(hub.open_streams(), 1);
    for _ in 0..CHANGES {
        busy.shared_entry_for_test()
            .failsafe
            .record_success(Duration::from_millis(5));
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert!(
        yield_until(|| hub.open_streams() == 0).await,
        "the write limit closed it"
    );
    assert!(!hub.watcher_running(), "and the watcher stopped with it");
    let fresh = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert_eq!(fresh.status, StatusCode::OK, "a new stream is admitted");
    drop(client);
}
