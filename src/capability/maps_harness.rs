// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Map tools' test harness: a stub that records every request, reached through
//! a per-row `.test` hostname that a test resolver maps to it, so the
//! executor runs in normal mode (cache on) and every row has its own host.
//!
//! Not `crate::test_fixture_host`: that client resolves one fixed name and is
//! installed raw (`with_test_http_client`), without the production redirect
//! policy these rows test; here both clients come from the production
//! construction (`client::build_over`) over a resolver that answers any
//! `.test` name, or fails every lookup and counts them.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::Response;
use parking_lot::Mutex;

use crate::capability::CapabilityExecutor;

/// One request the stub received.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) path: String,
    pub(crate) query: Vec<(String, String)>,
    pub(crate) headers: HeaderMap,
}

/// What the stub answers.
#[derive(Debug, Clone)]
pub(crate) enum Reply {
    /// `status` with `content_type` and `body`.
    Body {
        status: u16,
        content_type: String,
        body: String,
    },
    /// 302 to `location`.
    Redirect(String),
    /// Never sends headers.
    Stall,
}

impl Reply {
    pub(crate) fn json(body: &str) -> Self {
        Self::Body {
            status: 200,
            content_type: "application/json".to_owned(),
            body: body.to_owned(),
        }
    }

    pub(crate) fn status(status: u16) -> Self {
        Self::Body {
            status,
            content_type: "application/json".to_owned(),
            body: "{}".to_owned(),
        }
    }
}

/// A running stub on `127.0.0.1:<port>`.
pub(crate) struct Stub {
    pub(crate) port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Stub {
    pub(crate) async fn start(reply: Reply) -> Self {
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let record = Arc::clone(&seen);
        let app = axum::Router::new().fallback(move |request: Request<Body>| {
            let record = Arc::clone(&record);
            let reply = reply.clone();
            async move {
                let query = request
                    .uri()
                    .query()
                    .map(|q| {
                        url::form_urlencoded::parse(q.as_bytes())
                            .map(|(k, v)| (k.into_owned(), v.into_owned()))
                            .collect()
                    })
                    .unwrap_or_default();
                record.lock().push(Seen {
                    path: request.uri().path().to_owned(),
                    query,
                    headers: request.headers().clone(),
                });
                match reply {
                    Reply::Body {
                        status,
                        content_type,
                        body,
                    } => Response::builder()
                        .status(StatusCode::from_u16(status).expect("status"))
                        .header(header::CONTENT_TYPE, content_type)
                        .body(Body::from(body))
                        .expect("response"),
                    Reply::Redirect(location) => Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, location)
                        .body(Body::empty())
                        .expect("response"),
                    Reply::Stall => std::future::pending::<Response>().await,
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        Self { port, seen }
    }

    /// `http://<host>:<port><path>` for this stub.
    pub(crate) fn url(&self, host: &str, path: &str) -> String {
        format!("http://{host}:{}{path}", self.port)
    }

    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().clone()
    }

    pub(crate) fn count(&self) -> usize {
        self.seen.lock().len()
    }
}

/// Answers every `.test` name with `127.0.0.1`, or fails every lookup, and
/// counts lookups either way.
#[derive(Clone, Default)]
pub(crate) struct Names {
    pub(crate) lookups: Arc<AtomicUsize>,
    fail: bool,
}

impl Names {
    pub(crate) fn failing() -> Self {
        Self {
            lookups: Arc::default(),
            fail: true,
        }
    }

    pub(crate) fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl crate::security::ssrf::HostResolver for Names {
    fn lookup(
        &self,
        host: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::Result<Vec<IpAddr>>> + Send + '_>>
    {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let answer = if self.fail || !host.to_ascii_lowercase().ends_with(".test") {
            Err(crate::Error::Protocol(format!(
                "test resolver: no answer for {host}"
            )))
        } else {
            Ok(vec![IpAddr::from([127, 0, 0, 1])])
        };
        Box::pin(async move { answer })
    }
}

/// An executor in normal mode whose clients resolve through `names`.
pub(crate) fn executor(names: Names) -> CapabilityExecutor {
    CapabilityExecutor::with_test_resolver(names)
}
