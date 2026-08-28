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

use crate::gateway::auth::DashboardBootstrap;
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
pub(super) fn log_startup_banner(
    config: &Config,
    backends: &BackendRegistry,
    bootstrap: Option<&DashboardBootstrap>,
    // Only the unix branch below reads it; Windows has no mode bits to check.
    #[cfg_attr(not(unix), allow(unused_variables))] config_path: Option<&std::path::Path>,
) {
    info!("============================================================");
    info!("MCP GATEWAY v{}", env!("CARGO_PKG_VERSION"));
    info!("============================================================");
    info!(host = %config.server.host, port = %config.server.port, "Listening");
    info!(backends = backends.all().len(), "Backends registered");

    // An existing config predates the 0600 write path, so it may still be
    // readable by other local accounts — and it now carries a generated admin
    // credential. Reported, not silently changed: re-permissioning a file the
    // operator owns is the kind of surprise that starts the next report.
    #[cfg(unix)]
    if let Some(path) = config_path {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    path = %path.display(),
                    mode = format!("{mode:o}"),
                    "CONFIG READABLE BY OTHER LOCAL USERS: it holds this gateway's \
                     credentials. Fix with: chmod 600 <path>"
                );
            }
        }
    }

    if config.auth.enabled {
        // Print the dashboard link. A browser navigation carries no
        // Authorization header, so without this an operator with a perfectly
        // good credential still cannot open the dashboard. The value is
        // single-use and is not the credential itself.
        // Loopback only. The link carries an admin-granting value and the log
        // it is printed to may be shipped elsewhere; on a network listener the
        // reader of that log would not even need to be on the machine.
        if crate::gateway::router::is_loopback_bind(&config.server.host)
            && let Some(value) = bootstrap.and_then(DashboardBootstrap::peek)
        {
            if let Some(reason) = dashboard_link_refusal(config) {
                warn!("DASHBOARD link not printed: {reason}");
            } else {
                info!(
                    "DASHBOARD (opens once, then remembered in this browser): \
                     {}://{}/dashboard?bootstrap={}",
                    if config.mtls.enabled { "https" } else { "http" },
                    url_authority(&config.server.host, config.server.port),
                    value
                );
            }
        }

        let key_count = config.auth.api_keys.len();
        let has_bearer = config.auth.bearer_token.is_some();
        info!(
            "AUTHENTICATION enabled (bearer={}, api_keys={})",
            has_bearer, key_count
        );
    } else {
        warn!("AUTHENTICATION disabled - every local caller is anonymous");
        // Formatted from the one list, not repeated from it. This banner named
        // two tools that had been removed from the admin set, which is what a
        // fourth hand-maintained copy of a roster does.
        warn!(
            "  Anonymous holds no admin: {} and the admin dashboard are unavailable.",
            crate::gateway::router::ADMIN_META_TOOLS.join(", ")
        );
        // The roster above is formatted from the one list rather than repeated
        // from it: a hand-written copy here named two tools that had already
        // been removed from the admin set.
        //
        // Two audiences below, and the short version serves neither. A NEW
        // install should run `init`, which generates the credential and writes
        // the whole shape; telling them to hand-edit YAML sends them to do
        // badly what a command does correctly. An EXISTING install cannot
        // re-run `init` over a config it already has, and enabling auth alone
        // gates EVERY path — so an operator who follows the short version loses
        // the MCP client they already configured, which is worse than the
        // missing dashboard they set out to fix.
        warn!("  To use them, either:");
        warn!("    - run `mcp-gateway init` for a new install: it generates the");
        warn!("      credential and writes the config, including public_paths; or");
        warn!("    - on an existing config, set auth.enabled = true with a bearer");
        warn!("      token AND list /health and /mcp under auth.public_paths, so");
        warn!("      tool calls keep working. The credential gates management, not tools.");
        // A loopback bind keeps this to callers already on the machine. A
        // wildcard or LAN bind hands the same unauthenticated surface, and the
        // credentials behind it, to the network.
        if !crate::gateway::router::is_loopback_bind(&config.server.host) {
            warn!(
                host = %config.server.host,
                "  BIND IS NOT LOOPBACK: unauthenticated callers on the network can \
                 invoke every configured backend with this gateway's credentials. \
                 Set auth.enabled = true, or bind 127.0.0.1."
            );
        }
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
/// Takes an ALREADY BOUND listener rather than an address.
///
/// It used to bind its own, while the caller had bound the same address for the
/// plain path — so every mTLS gateway died on "address already in use". Binding
/// once in the caller and handing the socket here is what makes the two paths
/// share an address they cannot fight over, and it keeps the bind BEFORE the
/// startup banner and the warm-start, so a taken port is still reported before
/// the process claims to be listening.
pub(super) async fn serve_tls(
    app: axum::Router,
    listener: std::net::TcpListener,
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

    axum_server::from_tcp(listener)
        .map_err(|e| crate::Error::Tls(format!("TLS listener setup failed: {e}")))?
        .acceptor(acceptor)
        .handle(handle)
        // WITH connect info: `try_dashboard_bootstrap` needs the real peer
        // address to tell a local browser from a forwarded request, and a
        // header cannot tell it that.
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
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

/// The route that carries tool-invocation authority (`router::create_router_with`).
const TOOL_ROUTE: &str = "/mcp";

/// The per-backend routes, `/mcp/{name}`, as a prefix. Separate from
/// [`TOOL_ROUTE`] because the trailing slash is load-bearing: it is what
/// distinguishes a path SEGMENT from a name that merely begins with the same
/// letters, and `/mcp-status` is not a tool route.
const TOOL_ROUTE_PREFIX: &str = "/mcp/";

/// Format a host and port as a URL authority, bracketing an IPv6 literal.
///
/// `::1` written into a URL unbracketed parses as an empty host followed by
/// port `:1`, so the link a browser is handed is not navigable. Names and IPv4
/// literals pass through unchanged.
fn url_authority(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Why the printed dashboard link would not work, when it would not.
///
/// Redemption sets a `Secure` session cookie whenever a `public_url` declares
/// HTTPS, because a proxy may terminate TLS in front of this listener. The link
/// is plain HTTP on a loopback bind, and a browser discards a `Secure` cookie
/// that arrives over HTTP — so following the link would spend the single-use
/// value and land on a dashboard that still reads as logged out. Printing the
/// reason instead of the dead link is what tells the operator which knob moved.
fn dashboard_link_refusal(config: &Config) -> Option<String> {
    let public = config.server.public_url.as_deref()?;
    if config.mtls.enabled || !public.starts_with("https://") {
        return None;
    }
    Some(format!(
        "server.public_url is {public}, so the dashboard session cookie is marked Secure and \
         a browser discards it over this plain-HTTP listener. Set mtls.enabled to serve this \
         listener over HTTPS, or remove server.public_url while you redeem the link — \
         redemption is loopback-only, so the HTTPS front end cannot perform it."
    ))
}

/// Why an unauthenticated gateway must not serve HTTP on this bind, if it must not.
///
/// Returned as a message rather than logged, so the caller refuses before
/// binding a listener and a test can assert the decision without starting a
/// server. `None` means the configuration may serve.
///
/// A once-at-startup check WAS sufficient when the only inputs were
/// `server.host`, which is restart-required
/// (`config_reload::ConfigPatch::server_changed`), and the auth state, which is
/// snapshotted into the router at construction and never replaced by a reload.
///
/// It is no longer sufficient on its own, and this comment used to claim it was.
/// `server.public_url` is deliberately hot-reloadable — the origin gate re-reads
/// it per request so a reload takes effect at once — so adding a non-loopback
/// `public_url` to a running gateway reaches the state this refusal exists to
/// prevent, without passing through it.
///
/// [`reload_posture_refusal`] closes that: a reload which would enter the state
/// is refused rather than applied. This function stays the single place that
/// decides what the state IS, and is called from both.
#[must_use]
pub fn network_bind_refusal(config: &Config) -> Option<String> {
    if config.server.allow_unauthenticated_network_bind {
        return None;
    }

    // A loopback bind is not on its own a reason to stop asking. Declaring
    // `server.public_url` with a non-loopback host says the gateway is reached
    // from elsewhere — through a tunnel or a reverse proxy — and the origin
    // gate admits that hostname precisely so those requests work. Combined with
    // a public `/mcp`, the whole tool surface is then reachable from wherever
    // that proxy is, with no credential, while the operator's config says
    // `auth.enabled: true` and reads as protected.
    //
    // Keyed on the declared reachability rather than the bind address, because
    // the bind address is not where such a request arrives from.
    let declared_public_host = config
        .server
        .public_url
        .as_deref()
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(str::to_string))
        .filter(|h| !crate::gateway::router::is_loopback_bind(h));

    if crate::gateway::router::is_loopback_bind(&config.server.host)
        && declared_public_host.is_none()
    {
        return None;
    }

    // `auth.enabled` alone is not the question. What matters is whether a
    // caller can invoke tools without a credential: a public path covering the
    // MCP endpoint leaves every backend reachable with the gateway's keys,
    // whatever the auth flag says.
    //
    // The question is whether a public prefix covers the TOOL surface, asked
    // with the same prefix semantics authentication itself uses
    // (`gateway::auth`, `ResolvedAuthConfig::is_public_path`, which matches with
    // `path.starts_with(p)`). Two earlier spellings were both wrong:
    //
    // - "any entry that is not `/health`" refuses a gateway that lists
    //   `/metrics`, which is a documented and legitimate shape and grants
    //   nothing — the scrape route is merged outside the auth layer anyway.
    // - "any entry that is not `/health` and is not empty" skipped the one
    //   entry that opens everything. A blank string is a prefix of every path,
    //   so a stray dash in a YAML list makes the whole gateway public while the
    //   config reads as secured.
    //
    // Asking about the tool routes directly covers both: `""` and `"/"` and
    // `"/m"` all prefix-match `/mcp`, while `/health` and `/metrics` do not.
    //
    // Scope, so the omission is deliberate rather than missed: a public path
    // over the ADMIN surface is a different exposure with a different control —
    // the anonymous identity holds no admin — and this refusal is about a caller
    // invoking every configured backend.
    let tools_are_public = config.auth.public_paths.iter().any(|p| {
        // Two ways a configured prefix opens a tool route, and no third:
        //
        // - it is a prefix of `/mcp` itself: `""`, `"/"`, `"/m"`, `"/mcp"`;
        // - it is a prefix of some `/mcp/{name}`, which means it starts with
        //   `/mcp/` — the SLASH is what makes it a path segment.
        //
        // The slash is the whole correction. Asking only whether `p` starts
        // with `/mcp` refuses `/mcp-status`, `/mcpx`, `/mcp.json` and
        // `/mcp%2Ffoo`, none of which axum routes to a tool and none of which
        // makes a tool call public — `is_public_path` asks whether the REQUEST
        // path starts with `p`, and `/mcp` does not start with `/mcp-status`.
        // That is a denial of service on a legitimate config: the gateway
        // refuses to start, and the operator's own health endpoint is why.
        TOOL_ROUTE.starts_with(p.as_str()) || p.starts_with(TOOL_ROUTE_PREFIX)
    });
    if config.auth.enabled && !tools_are_public {
        return None;
    }

    // `auth` is not the only credential the tool surface can demand, and this
    // check used to behave as though it were — refusing to start two shapes the
    // project ships and documents as secure:
    //
    // - mTLS with `require_client_cert`, where a caller without a certificate
    //   signed by the configured CA is rejected during the TLS handshake, before
    //   any HTTP exists to be public (`mtls::config`, `serve_tls`).
    // - `agent_auth`, whose middleware wraps every route and answers 401 to a
    //   request carrying no valid agent JWT (`gateway::oauth`, layered inside
    //   the standard auth layer in `router::create_router_with`).
    //
    // Either one means the tools are NOT invocable without a credential, which
    // is the whole question. Refusing them denied service to precisely the most
    // carefully secured deployments — the third time this refusal has been
    // wrong in the over-refusing direction, and the reason the test below
    // enumerates the gates rather than trusting this list to stay complete.
    // Two ways mTLS gates the tools, and the second is easy to miss. Required
    // client certificates reject at the handshake. But a policy with rules also
    // denies: `MtlsPolicy::evaluate` returns `Deny` when rules are configured
    // and no verified certificate identity is present, so a gateway with
    // OPTIONAL certificates and a non-empty policy still admits nobody without
    // one. Refusing that config was the same over-refusal one layer down.
    let mtls_gates_tools = config.mtls.enabled
        && (config.mtls.require_client_cert || !config.mtls.policies.is_empty());
    // `enabled` is enough HERE because it cannot be enabled and toothless:
    // `Config::validate` refuses to load a config whose agent key material
    // could not reject anybody (MIK-7258), so a forgeable agent never reaches
    // a running gateway.
    //
    // This function grew three patches trying to judge key strength itself —
    // an empty secret, then a short one, then an `env:` reference resolving to
    // either, then one sound agent masking a forgeable sibling. Each patch was
    // correct and the next review found the next hole, which is the shape of a
    // check living in the wrong place. Validation owns key soundness; this owns
    // whether a credential is demanded at all.
    if mtls_gates_tools || config.agent_auth.enabled {
        return None;
    }
    // The message names the condition that actually fired. Saying only
    // "authentication is disabled" invited the wrong fix: an operator turns auth
    // on, keeps /mcp public, and the tools stay open to the network.
    let cause = if config.auth.enabled {
        "tools are reachable without a credential (auth.public_paths covers more than /health)"
    } else {
        "authentication is disabled"
    };
    // Two ways to be reachable, and the remedy differs. A wide bind is fixed by
    // narrowing it; a declared public_url cannot be — the operator wants that
    // reachability — so there the only fix is to stop leaving tools open.
    let exposure = declared_public_host.as_deref().map_or_else(
        || format!("the bind address {}", config.server.host),
        |h| format!("the declared public_url host {h}"),
    );
    let remedy = if declared_public_host.is_some() && config.auth.enabled {
        "Remove the tool paths from auth.public_paths: a gateway published by \
         name is reached by more than the client on this machine."
    } else if declared_public_host.is_some() {
        // With auth off, clearing public_paths changes nothing — every path is
        // open. Saying otherwise sends the operator to make an edit that leaves
        // them refused, with no idea why.
        "Set auth.enabled = true with a bearer token and keep auth.public_paths \
         to /health: with authentication off, every path is open regardless of \
         that list."
    } else if config.auth.enabled {
        "Remove the tool paths from auth.public_paths, or bind 127.0.0.1."
    } else {
        "Set auth.enabled = true and keep auth.public_paths to /health, or bind 127.0.0.1."
    };
    Some(format!(
        "refusing to serve HTTP, reachable at {exposure}: {cause}, so any caller \
         that reaches it can invoke every configured backend with this \
         gateway's credentials. {remedy} If authentication terminates in front \
         of this gateway (a sidecar, a service mesh, or a reverse proxy), set \
         server.allow_unauthenticated_network_bind = true."
    ))
}

/// The refusal a config reload must answer: [`network_bind_refusal`] applied to
/// the configuration that will be IN FORCE if this reload publishes.
///
/// `running` is what the process actually applied, fixed at startup; `wanted` is
/// the file. Only fields a reload applies live are taken from `wanted`, and
/// today that is `server.public_url` alone. Everything else — `auth`, the
/// override, `host` — comes from `running`, because a reload does not apply
/// them: the router snapshots `auth_config` at construction and `config_reload`
/// never touches it.
///
/// That distinction is the whole function. Judging the FILE instead lets an
/// operator who declares a `public_url` and enables authentication in one edit
/// — the remediation this project recommends everywhere — produce a config that
/// reads as safe while the request path is still running the old, permissive
/// auth. The same masking works with `allow_unauthenticated_network_bind`, and
/// with any restart-only input [`network_bind_refusal`] grows later. Overlaying
/// the live fields onto the running config removes the class: a field that is
/// not applied cannot influence a decision about what is in force.
///
/// Lives here, beside the refusal, because the two must agree about which
/// fields are live and the failure to agree is silent — the overlay would
/// simply judge the wrong config. `config_reload` calls this and not the
/// refusal directly.
///
/// Returns `None` when `running` would ALREADY have been refused, so a reload is
/// only refused for a state it would itself cause. Unreachable on the HTTP path,
/// where startup refused it; reachable off it, since `run_stdio` never runs the
/// check.
///
/// Design: `docs/design/unauthenticated-network-posture.md`, Decision C.
#[must_use]
pub fn reload_posture_refusal(running: &Config, wanted: &Config) -> Option<ReloadPostureRefusal> {
    if network_bind_refusal(running).is_some() {
        return None;
    }
    let mut effective = running.clone();
    effective
        .server
        .public_url
        .clone_from(&wanted.server.public_url);
    network_bind_refusal(&effective).map(|reason| ReloadPostureRefusal {
        reason,
        restart_would_also_refuse: network_bind_refusal(wanted).is_some(),
    })
}

/// Why a reload was refused, and what a restart on the same file would do.
///
/// The second answer is not cosmetic. A file that declares a `public_url` AND
/// enables authentication cannot be applied by a reload — the authentication
/// half needs a restart, so applying it would open the origin gate over a
/// request path still running without a credential — and yet it is exactly
/// right on a restart. Telling that operator to revert would be telling them to
/// undo the fix. Telling the one who declared only a `public_url` that a
/// restart applies it would be worse: their next start would refuse to serve.
pub struct ReloadPostureRefusal {
    /// What is wrong with the configuration that would be in force.
    pub reason: String,
    /// `true` when starting fresh on this same file would refuse to serve.
    pub restart_would_also_refuse: bool,
}

#[cfg(test)]
mod network_bind_tests {
    use super::network_bind_refusal;
    use crate::config::Config;

    fn config(host: &str, auth: bool, override_set: bool) -> Config {
        let mut c = Config::default();
        c.server.host = host.to_string();
        c.auth.enabled = auth;
        c.server.allow_unauthenticated_network_bind = override_set;
        c
    }

    /// The deployment templates this repository ships must start.
    ///
    /// Every one of them binds `0.0.0.0`, because a container or a pod that
    /// binds loopback receives nothing. That is half the refusal condition, so
    /// each template has to answer the other half — and until this case existed,
    /// three of them did not: the Helm chart and the Kubernetes base carried no
    /// `auth` section at all, which is `enabled: false`, which is refused. An
    /// unmodified `helm install` produced a pod that exited.
    ///
    /// The shapes below are the ones those files now hold. Reading the files
    /// themselves from a unit test would tie this crate to the repository
    /// layout, so they are mirrored here and named, which is the trade this
    /// makes deliberately: it catches a REGRESSION in what the refusal accepts,
    /// not an edit to the templates.
    #[test]
    fn the_shipped_deployment_shapes_are_allowed_to_serve() {
        // Helm values.yaml and the Kubernetes base ConfigMap: a credential is
        // required, and only /health is open so probes work without one.
        let mut cluster = config("0.0.0.0", true, false);
        cluster.auth.bearer_token = Some("env:MCP_GATEWAY_TOKEN".to_string());
        cluster.auth.public_paths = vec!["/health".to_string()];
        assert!(
            network_bind_refusal(&cluster).is_none(),
            "the shipped cluster templates would not start"
        );

        // docker-compose.yaml: binds 0.0.0.0 inside the container and keeps the
        // init config's public /mcp, so it sets the escape hatch — the host
        // publish is 127.0.0.1 only, and the gateway cannot see that.
        let mut compose = config("0.0.0.0", true, true);
        compose.auth.public_paths = vec!["/health".to_string(), "/mcp".to_string()];
        assert!(
            network_bind_refusal(&compose).is_none(),
            "the shipped compose template would not start"
        );

        // And the same compose shape WITHOUT the hatch is refused, so the line
        // is load-bearing rather than decorative.
        let mut without = compose.clone();
        without.server.allow_unauthenticated_network_bind = false;
        assert!(
            network_bind_refusal(&without).is_some(),
            "the compose template's escape hatch is not what makes it start"
        );
    }

    /// Every native credential gate counts, not only `auth`.
    ///
    /// Each of these rejects a caller that presents nothing, so a gateway
    /// carrying one does not have tools "reachable without a credential" — the
    /// question this refusal actually asks. Refusing them stops the most
    /// carefully secured deployments from starting, which is a denial of
    /// service dressed as a security control.
    ///
    /// Enumerated one gate per case rather than asserted in a lump, because the
    /// failure this guards against is a gate being FORGOTTEN: mTLS and
    /// `agent_auth` both were.
    #[test]
    fn a_native_credential_gate_means_the_tools_are_not_open() {
        // mTLS that requires a client certificate: rejected during the TLS
        // handshake, before any HTTP exists.
        let mut mtls = config("0.0.0.0", false, false);
        mtls.mtls.enabled = true;
        mtls.mtls.require_client_cert = true;
        assert!(
            network_bind_refusal(&mtls).is_none(),
            "an mTLS gateway requiring client certificates was refused"
        );

        // ...but mTLS WITHOUT that requirement and with no policy is
        // encryption, not authentication, and its own doc comment says so. It
        // must still refuse.
        let mut encryption_only = mtls.clone();
        encryption_only.mtls.require_client_cert = false;
        encryption_only.mtls.policies = Vec::new();
        assert!(
            network_bind_refusal(&encryption_only).is_some(),
            "TLS without client certificates authenticates nobody"
        );

        // Optional certificates PLUS a policy does gate: the policy denies
        // every call that arrives without a verified identity.
        let mut policy_gated = encryption_only.clone();
        policy_gated.mtls.policies = vec![crate::mtls::config::PolicyRuleConfig::default()];
        assert!(
            network_bind_refusal(&policy_gated).is_none(),
            "an mTLS policy denies uncredentialed calls, so the tools are not open"
        );

        // Agent JWT auth: the middleware wraps every route and answers 401 to a
        // request with no valid token. `enabled` is sufficient here because
        // `Config::validate` refuses a config whose agent keys could not reject
        // anybody, so this state cannot reach a running gateway — see
        // `config::Config::validate_agent_key_material` and its tests.
        let mut agent = config("0.0.0.0", false, false);
        agent.agent_auth.enabled = true;
        assert!(
            network_bind_refusal(&agent).is_none(),
            "a gateway requiring an agent JWT was refused"
        );

        // And with none of them, the same bind is still refused, so the cases
        // above pass on the gate rather than on the fixture.
        assert!(
            network_bind_refusal(&config("0.0.0.0", false, false)).is_some(),
            "the control case must refuse, or these prove nothing"
        );
    }

    #[test]
    fn a_public_path_counts_when_it_covers_the_tool_surface() {
        // Whether a configured prefix opens the tools is DERIVED here, not
        // asserted: it opens them exactly when some real tool request path
        // starts with it, which is what `ResolvedAuthConfig::is_public_path`
        // computes at request time. Writing the column by hand is how the
        // earlier spellings of this rule stayed green while being wrong.
        let real_tool_paths = ["/mcp", "/mcp/github"];
        let cases = [
            // Reach a tool route.
            "",
            "/",
            "/m",
            "/mc",
            "/mcp",
            "/mcp/",
            "/mcp/github",
            // Do NOT, and each of these once refused the gateway at startup:
            // the check asked whether an entry BEGAN with `/mcp` rather than
            // whether it reached a tool route, so an operator's own health
            // endpoint stopped the process from starting.
            "/mcp-status",
            "/mcpx",
            "/mcp.json",
            "/mcp%2Ffoo",
            "/mcp\u{FF0F}foo",
            "/health",
            "/metrics",
            "/MCP",
            "/.well-known/oauth-protected-resource",
        ];
        for path in cases {
            let opens_tools = real_tool_paths.iter().any(|real| real.starts_with(path));
            let mut c = config("0.0.0.0", true, false);
            c.auth.public_paths = vec!["/health".to_string(), path.to_string()];
            assert_eq!(
                network_bind_refusal(&c).is_some(),
                opens_tools,
                "public path {path:?} was judged wrongly: refusing a legitimate \
                 config stops a gateway starting, and missing one serves every \
                 backend without a credential"
            );
        }
    }

    #[test]
    fn a_blank_public_path_is_the_most_public_path_there_is() {
        // Public paths are matched by PREFIX (`ResolvedAuthConfig::is_public_path`,
        // `path.starts_with(p)`), so a blank entry is a prefix of every path and
        // opens the whole gateway — the MCP endpoint included. A YAML list with
        // a stray dash produces one.
        //
        // This case exists because the check used to skip empty entries, so the
        // single entry that opens everything was the single entry that did not
        // count: the config below read as secured and served every backend.
        let mut c = config("0.0.0.0", true, false);
        c.auth.public_paths = vec!["/health".to_string(), String::new()];
        assert!(
            network_bind_refusal(&c).is_some(),
            "a blank public path opens every route and must be refused"
        );
    }

    #[test]
    fn auth_enabled_is_not_enough_when_tools_are_public() {
        // Two changes that are each right and together are not: the starter
        // config enables auth AND lists /mcp as a public path so tools stay
        // open. `auth.enabled` alone then reads as safe, while every backend
        // stays reachable without a credential — on a network address.
        let mut c = config("0.0.0.0", true, false);
        c.auth.public_paths = vec!["/health".to_string(), "/mcp".to_string()];
        let refusal = network_bind_refusal(&c);
        assert!(
            refusal.is_some(),
            "tools open to the network with no credential must be refused"
        );
        let msg = refusal.unwrap();
        assert!(
            msg.contains("public_paths"),
            "the message must name the condition that fired, not a stale one: {msg}"
        );

        // Health alone is fine: it carries no authority.
        let mut probe_only = config("0.0.0.0", true, false);
        probe_only.auth.public_paths = vec!["/health".to_string()];
        assert!(network_bind_refusal(&probe_only).is_none());
    }

    #[test]
    fn a_published_loopback_gateway_still_refuses_open_tools() {
        // The interaction the three changes create together, which none of them
        // has alone. The bind is loopback, so the bind-address check passes.
        // `public_url` is declared, so the origin gate deliberately admits that
        // hostname — that is what it is for. The starter config leaves /mcp
        // public so the local client keeps working. Put together, a proxy or
        // tunnel in front reaches every backend with no credential, while the
        // operator's config says `auth.enabled: true` and reads as protected.
        let mut c = config("127.0.0.1", true, false);
        c.server.public_url = Some("https://gw.example.com".to_string());
        c.auth.public_paths = vec!["/health".to_string(), "/mcp".to_string()];

        let refusal = network_bind_refusal(&c);
        assert!(
            refusal.is_some(),
            "a gateway published by name must not leave tools open"
        );
        let msg = refusal.unwrap();
        assert!(
            msg.contains("gw.example.com"),
            "and must name the declared host as the exposure, since narrowing \
             the bind would not fix it: {msg}"
        );

        // A loopback public_url is not a publication, so nothing changes.
        let mut local = config("127.0.0.1", true, false);
        local.server.public_url = Some("http://127.0.0.1:39400".to_string());
        local.auth.public_paths = vec!["/health".to_string(), "/mcp".to_string()];
        assert!(
            network_bind_refusal(&local).is_none(),
            "the ordinary local install must still start"
        );

        // And health-only stays fine even when published.
        let mut published_probe = config("127.0.0.1", true, false);
        published_probe.server.public_url = Some("https://gw.example.com".to_string());
        published_probe.auth.public_paths = vec!["/health".to_string()];
        assert!(network_bind_refusal(&published_probe).is_none());
    }

    #[test]
    fn an_unauthenticated_network_bind_is_refused() {
        for host in ["0.0.0.0", "192.168.1.5", "::"] {
            let refusal = network_bind_refusal(&config(host, false, false));
            assert!(refusal.is_some(), "{host} with auth off must be refused");
            let msg = refusal.unwrap();
            assert!(msg.contains("auth.enabled"), "must name the remedy: {msg}");
            assert!(
                msg.contains("authentication is disabled"),
                "must name the condition that fired: {msg}"
            );
            assert!(
                msg.contains("127.0.0.1"),
                "must name the other remedy: {msg}"
            );
        }
    }

    #[test]
    fn a_loopback_bind_serves_without_authentication() {
        for host in ["127.0.0.1", "localhost", "::1"] {
            assert!(
                network_bind_refusal(&config(host, false, false)).is_none(),
                "{host} is the documented default and must keep working"
            );
        }
    }

    #[test]
    fn authentication_or_the_override_permits_a_network_bind() {
        assert!(network_bind_refusal(&config("0.0.0.0", true, false)).is_none());
        assert!(network_bind_refusal(&config("0.0.0.0", false, true)).is_none());
    }
}
