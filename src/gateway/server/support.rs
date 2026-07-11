// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Support functions for the gateway server.
//!
//! Contains free functions used during server startup and shutdown:
//! - [`log_startup_banner`]: emits the startup info block to the tracing log.
//! - [`serve_tls`]: starts the mTLS HTTPS listener via `axum-server`.
//! - [`shutdown_signal`]: awaits Ctrl+C / SIGTERM and broadcasts shutdown.
//! - [`build_persisted_costs`]: converts an enforcer snapshot to the
//!   persistence format (cost-governance feature only).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use futures::future::BoxFuture;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::signal;
use tokio_rustls::server::TlsStream;
use tower::{Layer, Service};
use tracing::{info, warn};

use crate::backend::BackendRegistry;
use crate::config::Config;
use crate::mtls::CertIdentity;

/// Emit the startup banner to the tracing log.
///
/// Logs version, listen address, backend count, auth status,
/// Meta-MCP URLs, streaming URLs, and per-backend direct access paths.
pub(super) fn log_startup_banner(config: &Config, backends: &BackendRegistry) {
    info!("============================================================");
    info!("MCP GATEWAY v{}", env!("CARGO_PKG_VERSION"));
    info!("============================================================");
    info!(host = %config.server.host, port = %config.server.port, "Listening");
    info!(backends = backends.all().len(), "Backends registered");

    if config.auth.enabled {
        let key_count = config.auth.api_keys.len();
        let has_bearer = config.auth.bearer_token.is_some();
        info!(
            "AUTHENTICATION enabled (bearer={}, api_keys={})",
            has_bearer, key_count
        );
    } else {
        warn!("AUTHENTICATION disabled - gateway is open to all requests");
    }

    if config.meta_mcp.enabled {
        info!("META-MCP (compact tool surface, on-demand discovery):");
        info!(
            "  POST http://{}:{}/mcp  (requests)",
            config.server.host, config.server.port
        );
    }

    if config.streaming.enabled {
        info!("STREAMING (real-time notifications):");
        info!(
            "  GET  http://{}:{}/mcp  (SSE stream)",
            config.server.host, config.server.port
        );
        if !config.streaming.auto_subscribe.is_empty() {
            info!(
                "  Auto-subscribe backends: {:?}",
                config.streaming.auto_subscribe
            );
        }
    }

    info!("Direct backend access:");
    for backend in backends.all() {
        info!("  /mcp/{}", backend.name);
    }
    info!("============================================================");
}

/// Start the HTTPS (mTLS) server using `axum-server`.
///
/// Builds a `rustls::ServerConfig` from `mtls_config`, wraps it in
/// `axum-server`'s `RustlsConfig`, and runs until the `shutdown_fut` resolves.
pub(super) async fn serve_tls(
    app: axum::Router,
    addr: SocketAddr,
    mtls_config: &crate::mtls::MtlsConfig,
    shutdown_fut: impl std::future::Future<Output = ()> + Send + 'static,
) -> crate::Result<()> {
    use crate::mtls::cert_manager::build_tls_config;

    let rustls_cfg = build_tls_config(mtls_config)?;
    let rustls_config = RustlsConfig::from_config(Arc::new(rustls_cfg));

    info!(
        addr = %addr,
        require_client_cert = mtls_config.require_client_cert,
        "mTLS listener starting"
    );

    let handle = axum_server::Handle::new();
    let handle_for_shutdown = handle.clone();

    // Bridge our broadcast-based shutdown signal to the axum-server handle
    tokio::spawn(async move {
        shutdown_fut.await;
        handle_for_shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });

    let acceptor = PeerCertIdentityAcceptor::new(RustlsAcceptor::new(rustls_config));

    axum_server::bind(addr)
        .acceptor(acceptor)
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .map_err(|e| crate::Error::Tls(format!("TLS server error: {e}")))
}

#[derive(Debug, Clone)]
struct PeerCertIdentityAcceptor {
    inner: RustlsAcceptor,
}

impl PeerCertIdentityAcceptor {
    fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for PeerCertIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = PeerCertIdentityService<S>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();

        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let identity = client_identity_from_peer_chain(stream.get_ref().1.peer_certificates())?;
            let service = PeerCertIdentityLayer::new(identity).layer(service);

            Ok((stream, service))
        })
    }
}

fn client_identity_from_peer_chain(
    peer_certs: Option<&[CertificateDer<'static>]>,
) -> io::Result<Option<CertIdentity>> {
    let Some(leaf) = peer_certs.and_then(|certs| certs.first()) else {
        return Ok(None);
    };

    CertIdentity::from_der(leaf.as_ref())
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

#[derive(Debug, Clone)]
struct PeerCertIdentityLayer {
    identity: Option<CertIdentity>,
}

impl PeerCertIdentityLayer {
    fn new(identity: Option<CertIdentity>) -> Self {
        Self { identity }
    }
}

impl<S> Layer<S> for PeerCertIdentityLayer {
    type Service = PeerCertIdentityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PeerCertIdentityService {
            inner,
            identity: self.identity.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct PeerCertIdentityService<S> {
    inner: S,
    identity: Option<CertIdentity>,
}

impl<S, B> Service<axum::http::Request<B>> for PeerCertIdentityService<S>
where
    S: Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: axum::http::Request<B>) -> Self::Future {
        if let Some(identity) = self.identity.clone() {
            request.extensions_mut().insert(identity);
        }

        self.inner.call(request)
    }
}

/// Shutdown signal handler.
///
/// Resolves on Ctrl+C (all platforms) or SIGTERM (Unix only), then broadcasts
/// the shutdown signal to all subscriber tasks.
pub(super) async fn shutdown_signal(shutdown_tx: tokio::sync::broadcast::Sender<()>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("Shutdown signal received");
    let _ = shutdown_tx.send(());
}

/// Build a `PersistedCosts` snapshot from the current enforcer state.
#[cfg(feature = "cost-governance")]
pub(super) fn build_persisted_costs(
    snap: &crate::cost_accounting::enforcer::EnforcerSnapshot,
) -> crate::cost_accounting::persistence::PersistedCosts {
    use crate::cost_accounting::persistence::ToolTotal;

    let tool_totals = snap
        .tool_daily
        .iter()
        .map(|(name, &daily_usd)| {
            (
                name.clone(),
                ToolTotal {
                    call_count: 0,
                    total_cost_usd: daily_usd,
                    avg_cost_usd: 0.0,
                },
            )
        })
        .collect();

    crate::cost_accounting::persistence::PersistedCosts {
        saved_at: crate::cost_accounting::persistence::now_secs(),
        tool_totals,
        key_totals: snap.key_daily.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::future::{Ready, ready};

    use axum::http::Request;
    use rcgen::string::Ia5String;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    fn spiffe_leaf_der(uri: &str) -> Vec<u8> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test-agent");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(uri).unwrap())];

        let key_pair = KeyPair::generate().expect("key generation failed");
        params
            .self_signed(&key_pair)
            .expect("cert generation failed")
            .der()
            .to_vec()
    }

    #[test]
    fn peer_chain_identity_extracts_spiffe_svid_leaf() {
        let leaf = CertificateDer::from(spiffe_leaf_der("spiffe://example.test/agent/alpha"));
        let identity = client_identity_from_peer_chain(Some(&[leaf]))
            .expect("peer chain should parse")
            .expect("identity should be present");

        assert_eq!(identity.san_uris, vec!["spiffe://example.test/agent/alpha"]);
        assert_eq!(identity.display_name, "spiffe://example.test/agent/alpha");
    }

    #[test]
    fn peer_chain_identity_is_absent_without_client_certificate() {
        let identity = client_identity_from_peer_chain(None).expect("missing chain is allowed");
        assert!(identity.is_none());

        let empty_identity =
            client_identity_from_peer_chain(Some(&[])).expect("empty chain is allowed");
        assert!(empty_identity.is_none());
    }

    #[test]
    fn peer_chain_identity_rejects_malformed_certificate() {
        let malformed = CertificateDer::from(vec![0, 1, 2, 3]);

        let error = client_identity_from_peer_chain(Some(&[malformed]))
            .expect_err("malformed peer certificate must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn peer_cert_identity_service_inserts_identity_extension() {
        let identity = CertIdentity {
            san_uris: vec!["spiffe://example.test/agent/alpha".to_owned()],
            display_name: "spiffe://example.test/agent/alpha".to_owned(),
            ..CertIdentity::default()
        };
        let mut service = PeerCertIdentityLayer::new(Some(identity.clone())).layer(EchoIdentity);

        let inserted_identity = futures::executor::block_on(service.call(Request::new(())))
            .expect("echo service should not fail");

        assert_eq!(inserted_identity, Some(identity));
    }

    #[derive(Clone)]
    struct EchoIdentity;

    impl Service<Request<()>> for EchoIdentity {
        type Response = Option<CertIdentity>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<()>) -> Self::Future {
            ready(Ok(request.extensions().get::<CertIdentity>().cloned()))
        }
    }
}
