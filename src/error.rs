// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Error types for MCP Gateway

use std::io;

use thiserror::Error;

/// Result type alias for MCP Gateway
pub type Result<T> = std::result::Result<T, Error>;

/// MCP Gateway errors
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Authorization refused this call.
    ///
    /// A distinct variant, not an opaque `JsonRpc`, so a consumer can ask "is
    /// this a denial?" without matching on message text. The playbook engine
    /// needs exactly that: a denial must not be retried, while a timeout must
    /// be, and the two are indistinguishable once flattened to a string.
    ///
    /// `code` is the code the router's own refusal envelope would carry, so a
    /// caller sees one classification whichever gate rejected.
    #[error("{message}")]
    Forbidden {
        /// JSON-RPC error code the refusal envelope carries.
        code: i32,
        /// HTTP status the refusal deserves.
        ///
        /// Carried rather than derived: the router gate already answers a
        /// refusal with 403, and a denial that only the chokepoint can see —
        /// a playbook step — must not come back 200 with an error buried in
        /// the body. One refusal, one status, whichever gate produced it.
        status: u16,
        /// Human-readable refusal reason, safe to return to the caller.
        message: String,
    },

    /// A response or bridge question was refused by the gateway's Firewall.
    /// This server-owned provenance must survive internal error propagation.
    #[error("Response blocked by security firewall")]
    ResponseFirewallRefused,

    /// The audit log could not record this call, so its result is withheld
    /// (4.0.0 item D1-f). HTTP 503, JSON-RPC `-32005`. The call may have run:
    /// a client must not blindly retry a side effect.
    #[error("audit log unavailable; the call may have run but its result is withheld")]
    AuditUnavailable,

    /// Configuration validation failure — semantically invalid config.
    ///
    /// Use this instead of `Internal` when a config value fails a semantic
    /// constraint (e.g. conflicting fields, invalid URL, missing required key).
    #[error("Configuration validation error: {0}")]
    ConfigValidation(String),

    /// Config watcher error — file watcher setup or event delivery failed.
    ///
    /// Use this instead of `Internal` for `notify`-crate failures in the
    /// hot-reload subsystem.
    #[error("Config watcher error: {0}")]
    ConfigWatcher(String),

    /// Capability file SHA-256 pin mismatch — potential rug-pull attack.
    ///
    /// Raised by the capability loader when a YAML's embedded `sha256:` pin
    /// does not match the on-disk file content. The capability is refused
    /// load. See `crate::capability::hash` for the hashing strategy.
    #[error(
        "Capability hash mismatch (rug-pull protection) in {file}: expected {expected}, actual {actual}"
    )]
    CapabilityHashMismatch {
        /// The hash embedded in the YAML `sha256:` field (trusted baseline).
        expected: String,
        /// The hash computed from the current file content.
        actual: String,
        /// The file path that failed verification.
        file: String,
    },

    /// Backend not found
    #[error("Backend not found: {0}")]
    BackendNotFound(String),

    /// The backend could not take the request: it would not start, its
    /// concurrency limit closed, its tools could not be read in time.
    ///
    /// Invariant: constructed only before the request is sent. That is what
    /// puts it on the [`Error::is_pre_dispatch`] allowlist, where a wrong
    /// `true` frees an idempotency key for work that may have run, so an
    /// after-send failure is `Transport` or `BackendTimeout`, never this
    /// (MIK-7979). The files that construct it are pinned by a scan test
    /// (`pre_send_scan_tests`); a new one needs its pre-send proof.
    #[error("Backend unavailable: {0}")]
    BackendUnavailable(String),

    /// Circuit breaker is open — request rejected without being dispatched.
    ///
    /// Carries the backend name and, once the breaker has tripped, the failure
    /// that tripped it.  Use [`rpc_codes::SERVER_ERROR_START`] (-32000) as the
    /// JSON-RPC code for this variant.
    #[error(
        "Circuit breaker open for backend '{backend}'{}",
        last_failure.as_ref().map(|r| format!("; last failure: {r}")).unwrap_or_default()
    )]
    CircuitOpen {
        /// Backend whose breaker refused the call.
        backend: String,
        /// Why the breaker last opened (`BreakerOpenEvent::reason`), if it has.
        last_failure: Option<String>,
    },

    /// The gateway's own per-backend rate limiter refused the request before
    /// dispatch. Not a breaker trip and not a backend failure: the backend was
    /// never asked, so this is never sampled into the error budgets (F23).
    ///
    /// Carries the backend name. JSON-RPC code -32000, as for `CircuitOpen`.
    #[error("Rate limit exceeded for backend '{0}'")]
    RateLimited(String),

    /// The backend refused a new per-caller slot: it holds its cap of caller
    /// slots, or this caller's principal holds its own (#2300). Refused
    /// before dispatch, like `RateLimited`; never served on the shared slot.
    #[error("Backend '{backend}' has no free caller slot ({limit} limit reached)")]
    IdentitySlotsExhausted {
        /// The backend that refused.
        backend: String,
        /// Which limit refused: `backend` or `principal`.
        limit: &'static str,
    },

    /// Tool not found in any connected backend.
    ///
    /// Carries the tool name that was requested.
    #[error("Tool not found: '{0}'")]
    ToolNotFound(String),

    /// Backend timeout
    #[error("Backend timeout: {0}")]
    BackendTimeout(String),

    /// Transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// A transport failure that waiting cannot fix.
    ///
    /// `Transport` means "failed, cause unknown, possibly transient", which is
    /// the honest answer at most of its ~59 construction sites. This variant is
    /// for the few that genuinely know better: a command path that does not
    /// exist, a file that is not executable, a request the server calls
    /// malformed.
    ///
    /// The distinction has a caller. Warm-start retries indefinitely while a
    /// backend's tool cache is empty, so before this a mistyped command path
    /// produced a respawn attempt once a minute for the whole process lifetime,
    /// with nothing in the logs saying the configuration was simply wrong.
    ///
    /// When in doubt, use `Transport`. An unknown failure retrying is a cost;
    /// a recoverable failure classified permanent needs a restart to notice.
    ///
    /// HTTP status codes are classified here only with the body in hand. A
    /// first pass marked every 4xx permanent; two existing tests refused it,
    /// because this protocol overloads BOTH 404 and 400 to mean "your MCP
    /// session expired, reinitialise and retry" (#247). So
    /// [`crate::security::safe_http_status_error`] builds this variant only for
    /// a 4xx outside {400, 401, 403, 404, 407, 408, 429} whose body carries no
    /// session-expiry marker: the server answered and refused the request
    /// (MIK-7979). Everything else stays `Transport`.
    #[error("Transport error (permanent): {0}")]
    TransportPermanent(String),

    /// A transport failure the gateway can prove happened *before* any byte of
    /// the request reached the backend.
    ///
    /// `Transport` conflates two failures ADR-012 must keep apart: "could not
    /// connect" and "the stream died after the request was written". The
    /// second may have executed a side effect, so consequence 1 settles it as
    /// terminal. The first provably did not, and settling it terminal denies a
    /// caller a retry of work that never ran.
    ///
    /// Constructed at exactly four sites. The first is
    /// [`crate::security::safe_request_error_for`], and only when reqwest
    /// reports `is_connect()` AND the caller supplies
    /// [`crate::security::RedirectEvidence::NoRedirectFollowed`], which the
    /// transport derives from a redirect counter sampled either side of the
    /// send. A request that followed a redirect stays `Transport`: a 307
    /// re-submits the body, so the side effect may already have run at the
    /// origin that redirected. The second is the stdio transport's send with
    /// no stdin writer (MIK-7979): the writer is absent, so no write was
    /// attempted. The third and fourth are a stdio request that ends before
    /// its frame was admitted to the writer (MIK-7871): refused because stdout
    /// had already closed, or timed out or overtaken by stdout closing while
    /// still waiting for stdin (`stdio_write.rs`, `unsent_or`). A frame admitted
    /// to the writer goes out whole (#3453), so after that it stays `Transport`
    /// or `BackendTimeout`.
    ///
    /// The counter, not `reqwest::Error::url()`, is what carries this. An
    /// earlier revision compared the error's URL against the posted URL; that
    /// comparison is equal whether or not a hop was taken, because reqwest
    /// back-fills the original URL on the error path and only advances it on
    /// the success path. Do not reintroduce it.
    ///
    /// The narrow construction is the point. This variant is on the
    /// `is_pre_dispatch` allowlist, where a wrong `true` licenses a second
    /// execution of a side effect, so it must not grow a free-form
    /// construction surface.
    ///
    /// Its `Display` is byte-identical to [`Error::Transport`]'s, deliberately:
    /// this is an internal classification and the wire contract must not
    /// change. The cost is that no log line and no assertion message can tell
    /// the two apart -- only the variant can. That is how an earlier revision
    /// shipped the classifier with no production caller and a green suite
    /// underneath it, so a behavioural row, not a unit test that inspects the
    /// variant, is what pins this distinction.
    #[error("Transport error: {0}")]
    TransportConnect(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// A backend refused the proposed protocol version at the HTTP layer.
    ///
    /// A distinct variant rather than a flattened `Transport` string, for the
    /// reason `Forbidden` is one: `initialize` has to ask "was this a version
    /// rejection?" without matching on backend-controlled message text. Only
    /// the version tokens parsed out of the body travel here — never the body,
    /// which is backend-controlled and routinely quotes credentials back.
    #[error("Backend rejected the proposed protocol version; it supports: {}", supported.join(", "))]
    ProtocolVersionRejected {
        /// Versions the backend said it speaks.
        supported: Vec<String>,
    },

    /// OAuth client error — token acquisition, refresh, or callback failure.
    ///
    /// Use this instead of `Internal` for all errors originating in the
    /// `oauth/client`, `oauth/metadata`, `oauth/callback`, and `oauth/storage`
    /// modules.
    #[error("OAuth error: {0}")]
    OAuth(String),

    /// An interactive login nobody completed within the authorization window
    /// (MIK-7982). Every start that waited on that login ends with it.
    #[error(
        "authorization for backend '{backend}' was not completed within {window_secs}s; \
         retry to open a new login, then complete it in the browser"
    )]
    AuthorizationIncomplete {
        /// The backend whose login it was.
        backend: String,
        /// The authorization window that passed.
        window_secs: u64,
    },

    /// A login ended by a restart or shutdown of its backend before it
    /// completed (MIK-7982).
    #[error("authorization for backend '{backend}' was cancelled by a restart or shutdown; retry")]
    AuthorizationCancelled {
        /// The backend whose login it was.
        backend: String,
    },

    /// A caller that never begins or waits on an interactive login (the
    /// health probe) found a start in flight, which may be a login, and did
    /// not wait on it (MIK-7982).
    #[error(
        "backend '{backend}' is starting (possibly waiting on an interactive login); not waited on"
    )]
    AuthorizationRequired {
        /// The backend that needs the login.
        backend: String,
    },

    /// A caller's own deadline passed while it waited on a login still in
    /// progress: the person has not finished, the backend did not fail
    /// (MIK-7982).
    #[error(
        "authorization for backend '{backend}' is still in progress; \
         complete the login in the browser and retry"
    )]
    AuthorizationPending {
        /// The backend whose login is in progress.
        backend: String,
    },

    /// TLS error: certificate loading, TLS acceptor setup, or handshake
    /// failure on the mTLS listener.
    ///
    /// Use this instead of `Internal` for `rustls` and TLS-acceptor errors.
    /// A socket or listener error that is not about TLS is `Io`, on either
    /// listener.
    #[error("TLS error: {0}")]
    Tls(String),

    /// JSON-RPC error
    #[error("JSON-RPC error {code}: {message}")]
    JsonRpc {
        /// Error code
        code: i32,
        /// Error message
        message: String,
        /// Optional data
        data: Option<serde_json::Value>,
    },

    /// A JSON-RPC error the peer carried on a status that invites a retry.
    ///
    /// Two independent facts, and a caller breaks if either is dropped. The
    /// code is the peer's own answer, so the health probe must score it as an
    /// unserved answer rather than as a transport fault and tear down a
    /// backend that is up and merely declining. The status says the peer has
    /// not finished answering, so the retry classifiers must keep retrying it
    /// rather than hand an overloaded peer's "ask again" to a client as its
    /// considered reply. Flattening this to `Transport` loses the code;
    /// filing it as `JsonRpc` loses the retry.
    #[error("JSON-RPC error {code} carried on retryable status {status}: {message}")]
    JsonRpcRetryable {
        /// Error code the peer sent
        code: i32,
        /// Error message the peer sent
        message: String,
        /// The HTTP status that carried it
        status: u16,
        /// Additional error data the peer sent, kept at parity with
        /// [`Error::JsonRpc`]: a refusal that exhausts its retries must
        /// surface the same payload its in-band twin would have carried.
        data: Option<serde_json::Value>,
    },

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Server shutdown
    #[error("Server shutdown")]
    Shutdown,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    /// The refusal an open breaker returns, carrying the failure that tripped it.
    pub(crate) fn circuit_open(backend: &str, breaker: &crate::failsafe::CircuitBreaker) -> Self {
        Self::CircuitOpen {
            backend: backend.to_string(),
            last_failure: breaker.last_open_event().map(|event| event.reason),
        }
    }

    /// Create a JSON-RPC error
    pub fn json_rpc(code: i32, message: impl Into<String>) -> Self {
        Self::JsonRpc {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// True only for failures the gateway can prove it raised *before* the
    /// request reached the backend.
    ///
    /// ADR-012 consequence 1 settles a dispatched failure as terminal, because
    /// a transport failure after the backend acted is indistinguishable from
    /// one before it. That reasoning does not extend to a request that never
    /// left: caching it would deny the caller a retry of work that provably
    /// never ran.
    ///
    /// The allowlist is deliberately tight and the default is "dispatched".
    /// Misjudging a pre-dispatch failure as dispatched costs a retry;
    /// misjudging the reverse admits a second execution of a side effect.
    ///
    /// `TransportConnect` earns its place by construction, not by variant: it
    /// exists only where reqwest proved the connection was never established
    /// on an unredirected request. See its doc comment for why a redirected
    /// request is excluded. `BackendUnavailable` earns it by its construction
    /// invariant (raised only before the request is sent), which a scan test
    /// holds to a reviewed list of files.
    #[must_use]
    pub fn is_pre_dispatch(&self) -> bool {
        matches!(
            self,
            Self::CircuitOpen { .. }
                | Self::RateLimited(_)
                | Self::IdentitySlotsExhausted { .. }
                | Self::BackendNotFound(_)
                | Self::ToolNotFound(_)
                | Self::TransportConnect(_)
                | Self::BackendUnavailable(_)
                // A login wait: the start never finished, so nothing was sent
                // and the same-key retry after the login must run (MIK-7982).
                | Self::AuthorizationIncomplete { .. }
                | Self::AuthorizationCancelled { .. }
                | Self::AuthorizationRequired { .. }
                | Self::AuthorizationPending { .. }
        )
    }

    /// The request may have left the gateway and no answer came back: the
    /// stream died (`Transport`) or the wait ran out (`BackendTimeout`). The
    /// effect is undetermined, so a same-key retry is told so rather than
    /// served this error as if the work had failed (MIK-7979). Conservative by
    /// design: where the send cannot be proven either way the notice says
    /// "may have", and the work still never runs twice.
    #[must_use]
    pub(crate) fn is_lost_round(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::BackendTimeout(_))
    }

    /// The gateway's own limiter or slot admission refused: the backend was
    /// never asked, so this is not a backend failure. Matched on the variant,
    /// never on the message (F23, #2300).
    #[must_use]
    pub(crate) fn is_gateway_throttle(&self) -> bool {
        matches!(
            self,
            Self::RateLimited(_) | Self::IdentitySlotsExhausted { .. }
        )
    }

    /// The backend is waiting on a person to log in, not failing: an
    /// unfinished, cancelled, required or pending authorization. The one
    /// predicate every breaker and cooldown site excludes (MIK-7982).
    #[must_use]
    pub(crate) fn is_authorization_wait(&self) -> bool {
        matches!(
            self,
            Self::AuthorizationIncomplete { .. }
                | Self::AuthorizationCancelled { .. }
                | Self::AuthorizationRequired { .. }
                | Self::AuthorizationPending { .. }
        )
    }

    /// Convert to JSON-RPC error code
    #[must_use]
    pub fn to_rpc_code(&self) -> i32 {
        match self {
            Self::JsonRpc { code, .. }
            | Self::JsonRpcRetryable { code, .. }
            | Self::Forbidden { code, .. } => *code,
            Self::Json(_) => -32700, // Parse error
            Self::Protocol(_) | Self::ResponseFirewallRefused => -32600, // Invalid request
            Self::BackendNotFound(_) | Self::ToolNotFound(_) => -32001,
            Self::AuditUnavailable => -32005,
            Self::BackendUnavailable(_)
            | Self::CircuitOpen { .. }
            | Self::RateLimited(_)
            | Self::IdentitySlotsExhausted { .. }
            | Self::BackendTimeout(_)
            | Self::Transport(_)
            // A connect failure is the same class on the wire; the variant
            // exists for settlement, not for the caller.
            | Self::TransportConnect(_)
            // Same class as `Transport` to a JSON-RPC caller: a backend-side
            // failure, not a gateway fault. Omitting it reported a missing
            // backend command as an internal error.
            | Self::TransportPermanent(_) => -32000,
            // A 429 is the same class: the backend refused, the gateway is
            // healthy. Only 429 is lifted -- every other `Http` status keeps
            // the internal-error code it has always reported, so the arm is
            // guarded rather than moved wholesale.
            Self::Http(e) if e.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS) => -32000,
            // A11-b: a typed credential refusal (401, 403) was `Transport`
            // (-32000) until it was typed; it keeps that code, since the backend
            // refused and the gateway is healthy.
            Self::Http(e)
                if e.status()
                    .is_some_and(crate::security::http_diagnostics::is_deterministic_refusal) =>
            {
                -32000
            }
            _ => -32603, // Internal error
        }
    }
}

/// Standard JSON-RPC error codes
pub mod rpc_codes {
    /// Parse error - Invalid JSON
    pub const PARSE_ERROR: i32 = -32700;
    /// Invalid Request - Not a valid Request object
    pub const INVALID_REQUEST: i32 = -32600;
    /// Method not found
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid params
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal error
    pub const INTERNAL_ERROR: i32 = -32603;
    /// Server error range start
    pub const SERVER_ERROR_START: i32 = -32000;
    /// Server error range end
    pub const SERVER_ERROR_END: i32 = -32099;
}

#[cfg(test)]
#[path = "error_pre_send_scan_tests.rs"]
mod pre_send_scan_tests;

#[cfg(test)]
mod rpc_code_tests {
    use super::Error;

    /// MIK-7979: every `BackendUnavailable` is raised before the request is
    /// sent, so it frees an idempotency key; a lost round does not.
    #[test]
    fn backend_unavailable_is_pre_dispatch_and_a_lost_round_is_not() {
        assert!(Error::BackendUnavailable("svc".to_string()).is_pre_dispatch());
        assert!(!Error::Transport("reset".to_string()).is_pre_dispatch());
        assert!(!Error::BackendTimeout("slow".to_string()).is_pre_dispatch());
    }

    #[test]
    fn a_permanent_transport_failure_reports_as_a_backend_error() {
        // Omitting the variant here reported a missing backend command as an
        // INTERNAL error, blaming the gateway for the operator's typo.
        assert_eq!(
            Error::TransportPermanent("Failed to spawn: no such file".to_string()).to_rpc_code(),
            -32000,
        );
        assert_eq!(
            Error::Transport("connection refused".to_string()).to_rpc_code(),
            -32000,
            "the two transport variants must look the same to a JSON-RPC caller"
        );
    }

    #[test]
    fn a_refusal_keeps_the_peers_code_whichever_carriage_brings_it() {
        // A peer code recovered from a 429/503 body is the peer's answer, not a
        // gateway fault: omitting the retryable variant here reported an
        // exhausted backend refusal as INTERNAL and sent operators after the
        // wrong process.
        assert_eq!(
            Error::JsonRpcRetryable {
                code: -32601,
                message: "method not found".to_string(),
                status: 503,
                data: None,
            }
            .to_rpc_code(),
            -32601,
        );
    }
}
