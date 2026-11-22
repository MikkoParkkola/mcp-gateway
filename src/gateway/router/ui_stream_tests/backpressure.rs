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
/// The most status changes a row pushes, one per 300 ms step: four times what
/// the stack has ever been seen to hold before a send waits, and 120 s of
/// paused time, four times the 30 s write limit a closing row waits out.
const MAX_FILL: usize = 400;
/// A client receive buffer far above the 4 KiB rows: a stand-in for a socket
/// stack that holds more frames before a send has to wait.
const LARGE_RECV_BUFFER: u32 = 4 << 20;

/// Pushes status changes at a client that has stopped reading until a send
/// waits for channel room, and returns how many changes that took. How many
/// frames fit between the stream and the client depends on the OS's socket
/// buffering, so no fixed count is sure to block. Gives up after `bound`
/// changes with the stream's state, so a stream that closed reads as that.
async fn fill_until_a_send_waits(
    busy: &crate::backend::Backend,
    hub: &crate::gateway::ui::stream::StreamHub,
    bound: usize,
) -> Result<usize, String> {
    for pushed in 1..=bound {
        busy.shared_entry_for_test()
            .failsafe
            .record_success(Duration::from_millis(5));
        tokio::time::sleep(Duration::from_millis(300)).await;
        if hub.sends_awaiting_room() == 1 {
            println!("a send waited for room after {pushed} status changes");
            return Ok(pushed);
        }
    }
    Err(format!(
        "no send waited for room after {bound} status changes: {} open streams, {} sends waiting",
        hub.open_streams(),
        hub.sends_awaiting_room()
    ))
}

/// What a push until the stream closes saw: the changes pushed, the steps on
/// which a send waited for room, and the paused time from the sample that first
/// showed the last wait to the sample that first showed the close.
struct Closed {
    pushed: usize,
    waiting_steps: usize,
    last_wait_to_close: Duration,
}

/// Pushes status changes, one per 300 ms step, at a client that has stopped
/// reading until the stream closes. A waiting send is one reservation; when it
/// completes on a drain, the next push makes a newer frame, so a new
/// reservation waits, and the first one to wait the full write limit closes
/// the stream. So the push goes on across drains and never stops at a sample
/// with no send waiting. Gives up after `bound` changes with what it saw.
async fn push_until_the_stream_closes(
    busy: &crate::backend::Backend,
    hub: &crate::gateway::ui::stream::StreamHub,
    bound: usize,
) -> Result<Closed, String> {
    let (mut waiting_steps, mut episodes, mut run, mut longest) = (0, 0, 0, 0);
    let mut last_wait = None;
    for pushed in 1..=bound {
        busy.shared_entry_for_test()
            .failsafe
            .record_success(Duration::from_millis(5));
        tokio::time::sleep(Duration::from_millis(300)).await;
        if hub.open_streams() == 0 {
            // Both stamps are paused time, the clock the write limit runs on.
            let last_wait_to_close =
                last_wait.map_or(Duration::ZERO, |at: tokio::time::Instant| at.elapsed());
            return Ok(Closed {
                pushed,
                waiting_steps,
                last_wait_to_close,
            });
        }
        if hub.sends_awaiting_room() == 1 {
            if run == 0 {
                episodes += 1;
                last_wait = Some(tokio::time::Instant::now());
            }
            run += 1;
            waiting_steps += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    Err(format!(
        "the stream stayed open after {bound} status changes: a send waited on {waiting_steps} steps, \
         in {episodes} waiting episodes, the longest {longest} steps"
    ))
}

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
    // port-check: the listener serves on in the spawned task
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
    a_stalled_client_is_closed(4096).await;
}

// No large-buffer twin of the row above. On a loaded host the paused clock
// races ahead while the kernel keeps moving frames into a big receive buffer
// in real time, and each frame it takes lets the waiting send finish, so the
// 30 s wait starts over. How often that happens depends on the buffer's size,
// not on any count of steps, so no fixed bound is sure to see the close.
async fn a_stalled_client_is_closed(buffer: u32) {
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
    let busy = big_gateway(&state);
    let addr = serve(&state).await;
    let socket = TcpSocket::new_v4().expect("socket");
    socket
        .set_recv_buffer_size(buffer)
        .expect("receive buffer size");
    // The kernel may clamp the request (Linux caps it at rmem_max): print what it kept beside the fill count.
    let granted = socket.recv_buffer_size().expect("granted receive buffer");
    println!("receive buffer: asked {buffer} bytes, granted {granted}");
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
    let closed = push_until_the_stream_closes(&busy, hub, MAX_FILL)
        .await
        .unwrap_or_else(|why| panic!("{why}"));
    println!(
        "closed after {} status changes; a send waited on {} steps; last wait to close {:?}",
        closed.pushed, closed.waiting_steps, closed.last_wait_to_close
    );
    assert!(
        closed.waiting_steps > 0,
        "a send waited before the close: real backpressure"
    );
    // At least the 30 s limit less one 300 ms sample step. No upper bound: a
    // drain and a new reservation inside one step are not sampled, which makes
    // a correct close measure longer than 30 s.
    assert!(
        closed.last_wait_to_close >= Duration::from_millis(29_700),
        "the write limit closed it: the last wait lasted the limit, not {:?}",
        closed.last_wait_to_close
    );
    assert!(!hub.watcher_running(), "and the watcher stopped with it");
    let fresh = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert_eq!(fresh.status, StatusCode::OK, "a new stream is admitted");
    drop(client);
}

#[tokio::test]
async fn a_blocked_write_cannot_stretch_the_credential_recheck() {
    a_logout_closes_a_blocked_stream(4096).await;
}

#[tokio::test]
async fn a_blocked_write_behind_a_large_receive_buffer_cannot_stretch_it_either() {
    a_logout_closes_a_blocked_stream(LARGE_RECV_BUFFER).await;
}

/// The write limit starts only once a send waits, and the fill stops within one
/// 300 ms step of that, so the logout lands well inside the 30 s limit.
async fn a_logout_closes_a_blocked_stream(buffer: u32) {
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
    let busy = big_gateway(&state);
    let cookie = issue(&state);
    let addr = serve(&state).await;
    let socket = TcpSocket::new_v4().expect("socket");
    socket
        .set_recv_buffer_size(buffer)
        .expect("receive buffer size");
    // The kernel may clamp the request (Linux caps it at rmem_max): print what it kept beside the fill count.
    let granted = socket.recv_buffer_size().expect("granted receive buffer");
    println!("receive buffer: asked {buffer} bytes, granted {granted}");
    let mut client = socket.connect(addr).await.expect("connect");
    let ask = format!(
        "GET {STREAM} HTTP/1.1\r\nHost: {addr}\r\nCookie: {SESSION_COOKIE}={cookie}\r\n\r\n"
    );
    client.write_all(ask.as_bytes()).await.expect("request");
    let mut head = [0u8; 512];
    let n = client.read(&mut head).await.expect("response head");
    assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"));
    let hub = state.dashboard_bootstrap.stream_hub();
    fill_until_a_send_waits(&busy, hub, MAX_FILL)
        .await
        .unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(hub.open_streams(), 1, "still blocked, not yet timed out");
    assert_eq!(
        hub.sends_awaiting_room(),
        1,
        "a channel reservation is pending: real backpressure"
    );
    let out = Request::builder()
        .method("POST")
        .uri("/dashboard/logout")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_346))))
        .body(Body::empty())
        .unwrap();
    let _ = create_router(Arc::clone(&state))
        .oneshot(out)
        .await
        .unwrap();
    let revoked = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(hub.open_streams(), 0, "closed within a few re-check ticks");
    assert!(revoked.elapsed() < Duration::from_secs(5));
    drop(client);
}

#[tokio::test]
async fn a_fill_with_no_stream_open_stops_at_its_bound_and_says_so() {
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
    let busy = big_gateway(&state);
    let hub = state.dashboard_bootstrap.stream_hub();
    assert_eq!(hub.open_streams(), 0);
    let why = fill_until_a_send_waits(&busy, hub, 5)
        .await
        .expect_err("with nothing open, no send can wait");
    // One delimited match, so "10 open streams" or a nonzero waiting count cannot pass.
    assert!(
        why.contains("after 5 status changes: 0 open streams, 0 sends waiting"),
        "{why}"
    );
}
