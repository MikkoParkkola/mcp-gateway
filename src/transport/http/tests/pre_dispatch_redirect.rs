// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.SUB.4: a connect failure is pre-dispatch only without a redirect.

use super::*;

/// Reads one HTTP/1.1 request (head, then `content-length` body bytes) so the
/// fake server answers only after the client finished sending. Closing a
/// socket with unread request bytes resets the connection, which the client
/// reports as a canceled request instead of the response under test.
async fn drain_request(stream: &mut tokio::net::TcpStream) {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let length = String::from_utf8_lossy(&buf[..head_end])
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < head_end + length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The falsifier for the pre-dispatch signal, at the only level where a
/// redirect can actually be followed.
///
/// `safe_request_error_for` is told whether the transport's redirect counter
/// moved across the send. That claim is worth nothing unless the policy
/// closure really increments on a followed hop, and the classifier's own unit
/// rows cannot show it -- they pass the bit in by hand. This row builds the
/// real client, makes it follow a real 307 into a closed port, and asserts
/// both halves: the counter moved, and the resulting connect failure was NOT
/// released as pre-dispatch. A 307 re-submits the body, so the origin that
/// redirected may already have executed the call.
#[tokio::test]
async fn a_connect_failure_after_a_followed_redirect_is_not_pre_dispatch() {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Same host AND port as the base URL: `evaluate_redirect` refuses a
    // cross-origin hop, so a redirect is only ever followed within one origin.
    // `localhost` is a name rather than an IP literal, which is what clears the
    // SSRF guard on a loopback target.
    let target = format!("http://localhost:{port}/moved");
    let server = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Close the port BEFORE answering, so the hop the client is about
            // to take is deterministically refused rather than racing this
            // task's exit.
            drop(listener);
            drain_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {target}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    let base = format!("http://localhost:{port}/mcp");
    let transport =
        HttpTransport::new(&base, HashMap::new(), Duration::from_secs(5), true).unwrap();
    *transport.message_url.write() = Some(base);

    let err = transport.request("tools/call", None).await.unwrap_err();
    assert_eq!(
        transport.redirects_followed.load(Ordering::SeqCst),
        1,
        "precondition: the policy must have followed exactly one hop, or this \
         row proves nothing about the redirect case: {err}"
    );
    assert!(
        err.to_string().contains("connection failed"),
        "precondition: the hop must have been REFUSED. A timeout or a rejected \
         redirect would satisfy every other assertion here while testing \
         nothing about the redirect case: {err}"
    );
    assert!(
        !err.is_pre_dispatch(),
        "the 307 re-submitted the body, so the redirecting origin may already \
         have executed the call; releasing the idempotency key here would \
         admit a second execution: {err}"
    );
    assert!(matches!(err, Error::Transport(_)), "{err}");

    server.abort();
}

/// The positive control beside it: no redirect, connect refused, key released.
/// Without this row the counter could be wired to a constant `false` and the
/// falsifier above would still be green.
#[tokio::test]
async fn an_unredirected_connect_failure_is_pre_dispatch_end_to_end() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let base = format!("http://{addr}/mcp");
    let transport =
        HttpTransport::new(&base, HashMap::new(), Duration::from_secs(5), true).unwrap();
    *transport.message_url.write() = Some(base);

    let err = transport.request("tools/call", None).await.unwrap_err();
    assert_eq!(transport.redirects_followed.load(Ordering::SeqCst), 0);
    assert!(
        err.to_string().contains("connection failed"),
        "precondition: the port must have refused, not timed out: {err}"
    );
    assert!(
        err.is_pre_dispatch(),
        "a refused connection wrote no bytes, so the key must be released: {err}"
    );
}
