// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Per-request protocol metadata (MCP 2026-07-28), and telling the eras apart.
//!
//! The revision deleted the `initialize` handshake, so a request has to say for
//! itself what it is. It does that in `params._meta`, under reverse-DNS keys:
//!
//! ```json
//! "_meta": {
//!   "io.modelcontextprotocol/protocolVersion": "2026-07-28",
//!   "io.modelcontextprotocol/clientCapabilities": {},
//!   "io.modelcontextprotocol/clientInfo": { "name": "…", "version": "…" }
//! }
//! ```
//!
//! Version and capabilities are **required**; a request missing either is
//! malformed and gets `-32602`, with HTTP `400` on the HTTP path.
//!
//! ## Why absence cannot simply mean "malformed"
//!
//! A 2025 client sends none of these fields. So does a 2026 client that forgot
//! one. Under a rule of "no protocol fields means malformed", every legacy
//! client this gateway serves would start receiving `-32602`.
//!
//! So the rule is about **declaration**, not presence: a request that carries at
//! least one protocol field has declared itself modern, and is then held to all
//! of them. A request carrying none has declared nothing and is served as
//! legacy. The cost of that choice is bounded and named: a 2026 client that
//! omits *both* required fields is treated as a 2025 client rather than told its
//! request was malformed. Breaking every existing client to improve one error
//! message is the worse trade.
//!
//! `_meta` is a general-purpose extension field — tracing and vendor extensions
//! live there too — so only the `io.modelcontextprotocol/*` protocol keys count
//! as a declaration. A 2025 client that sends a trace context has not thereby
//! become a broken 2026 client.

use serde_json::Value;
use tracing::info;

/// `_meta` key: the protocol version a request is written against. Required.
pub const KEY_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// `_meta` key: the capabilities the client declares for this request. Required.
pub const KEY_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
/// `_meta` key: who the client says it is. Optional, and **self-asserted**.
pub const KEY_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
/// `_meta` key: the minimum log level to emit for this request. Optional.
pub const KEY_LOG_LEVEL: &str = "io.modelcontextprotocol/logLevel";
/// `_meta` key: who the server says it is, on every result.
pub const KEY_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// The protocol fields a modern request carries.
#[derive(Debug, Clone)]
pub struct RequestFields {
    /// The revision this request is written against.
    pub protocol_version: String,
    /// What the client declared it can receive. A server **MUST NOT** rely on a
    /// capability absent from here.
    ///
    /// Names rather than the subtree they came from. Every consumer asks the
    /// same question — was this capability declared — and keeping the whole
    /// `clientCapabilities` value to answer it copied an attacker-sized,
    /// arbitrarily deep object out of every request, on a path that runs before
    /// anything has decided the request is even wanted.
    ///
    /// A null value is not a declaration: the specification's rule is that a
    /// server may not rely on what was not declared, and explicitly-absent is
    /// still absent.
    pub declared_capabilities: Declared,
    /// The client's self-reported name, for logs and displays.
    ///
    /// **Never an authorization input.** The specification says clients *SHOULD
    /// identify themselves*, which is identification, not authentication: any
    /// caller can write any name here. Authorization stays with the
    /// authenticated credential.
    pub client_info_name: Option<String>,
    /// The minimum level to emit `notifications/message` at for this request.
    /// `None` means emit none at all.
    pub log_level: Option<String>,
}

/// What a request declared itself to be.
#[derive(Debug)]
pub enum RequestShape {
    /// Carries the protocol fields, and all the required ones.
    Modern(Box<RequestFields>),
    /// Declares no protocol fields. A 2025 client.
    Legacy,
    /// Declared itself modern and then omitted a required field.
    Malformed {
        /// The required keys that were absent, named so the error can say which.
        missing: Vec<&'static str>,
    },
}

/// Decide what a request declared itself to be.
///
/// Reads the body **and** the `MCP-Protocol-Version` header, because a request
/// that declares itself modern in one and says nothing in the other is the
/// exact split this revision's mirrored headers exist to close. Classifying on
/// the body alone let a caller put `2026-07-28` in a header an upstream
/// intermediary routes on, omit the body metadata, and take the legacy path
/// past the feature gate and every mirrored-header check behind it.
///
/// Only a header naming the **modern era** counts as a declaration. 2025
/// defines `MCP-Protocol-Version` too, so treating mere presence as modern
/// would refuse every conforming 2025 client — the likelier mistake, and the
/// more damaging one.
///
/// The era, not the served list: [`declares_modern_era`], the same predicate
/// the router uses to decide a request gets no session. One question, one
/// owner. When these were two predicates, a `2026-` revision this build does
/// not serve was skipped for session minting and classified `Legacy`, so it
/// took the legacy destructive-confirmation policy with an empty session id and
/// never reached the unsupported-version refusal.
#[must_use]
pub fn classify_request(params: Option<&Value>, header_version: Option<&str>) -> RequestShape {
    let header_declares_modern = header_version.is_some_and(declares_modern_era);

    let meta = params
        .and_then(|p| p.get("_meta"))
        .and_then(Value::as_object);

    let Some(meta) = meta else {
        return if header_declares_modern {
            // Declared modern where an intermediary can see it, and carried
            // none of what that declaration requires.
            RequestShape::Malformed {
                missing: vec![KEY_PROTOCOL_VERSION, KEY_CLIENT_CAPABILITIES],
            }
        } else {
            RequestShape::Legacy
        };
    };

    let version = meta.get(KEY_PROTOCOL_VERSION);
    let capabilities = meta.get(KEY_CLIENT_CAPABILITIES);

    // Declaration, not presence: only the protocol keys count. `_meta` also
    // carries tracing and vendor extensions, and a 2025 client that sends a
    // trace context has not declared an era.
    //
    // All four defined keys declare it, not just the required pair. `clientInfo`
    // and `logLevel` are this revision's own keys, so a request carrying one and
    // omitting the required pair has begun a declaration and failed to finish
    // it — malformed, rather than quietly legacy.
    let declared = version.is_some()
        || capabilities.is_some()
        || meta.contains_key(KEY_CLIENT_INFO)
        || meta.contains_key(KEY_LOG_LEVEL);
    if !declared && !header_declares_modern {
        return RequestShape::Legacy;
    }

    let mut missing = Vec::new();
    if version.is_none() {
        missing.push(KEY_PROTOCOL_VERSION);
    }
    if capabilities.is_none() {
        missing.push(KEY_CLIENT_CAPABILITIES);
    }
    if !missing.is_empty() {
        return RequestShape::Malformed { missing };
    }

    // A version that is present but not a string is as unusable as an absent
    // one, and saying "missing" of a field that is there would misdirect
    // whoever reads the error.
    let Some(protocol_version) = version.and_then(Value::as_str) else {
        return RequestShape::Malformed {
            missing: vec![KEY_PROTOCOL_VERSION],
        };
    };

    // Present but unusable is not satisfied. The required-field check above
    // asks only whether the key exists; a null, a number or an array would
    // reach dispatch as a capability declaration nothing can read.
    let Some(capabilities) = capabilities.and_then(Value::as_object) else {
        return RequestShape::Malformed {
            missing: vec![KEY_CLIENT_CAPABILITIES],
        };
    };

    RequestShape::Modern(Box::new(RequestFields {
        protocol_version: protocol_version.to_string(),
        declared_capabilities: Declared::parse(capabilities),
        client_info_name: meta
            .get(KEY_CLIENT_INFO)
            .and_then(|i| i.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string),
        log_level: meta
            .get(KEY_LOG_LEVEL)
            .and_then(Value::as_str)
            .map(str::to_string),
    }))
}

/// Whether a protocol-version value declares the stateless era at all.
///
/// Broader than [`MODERN_VERSIONS`] on purpose: a client naming a 2026 revision
/// this build does not serve has still declared itself stateless, and treating
/// it as legacy would hand it a session its own revision deleted.
#[must_use]
pub fn declares_modern_era(version: &str) -> bool {
    MODERN_VERSIONS.contains(&version) || version.starts_with("2026-")
}

/// Revisions the **stateless** path can serve.
///
/// Deliberately separate from `SUPPORTED_VERSIONS`, which is the list a legacy
/// `initialize` negotiates over. The two sets are not the same thing and only
/// coincide by accident: a 2025 revision cannot be served statelessly, and
/// 2026-07-28 cannot be reached through a handshake that revision deleted.
pub const MODERN_VERSIONS: &[&str] = &["2026-07-28"];

/// Methods this revision removed. Refused on the modern path, served on the
/// legacy one — the gateway's own backend health probe is a `ping`, and every
/// 2025 client has one too.
pub const REMOVED_IN_2026_07_28: &[&str] = &[
    "ping",
    "logging/setLevel",
    "notifications/roots/list_changed",
    // Replaced by `subscriptions/listen`, not merely deprecated. A client that
    // can still reach the old methods has no reason to move to the new one.
    "resources/subscribe",
    "resources/unsubscribe",
];

/// Methods this revision *added*, which a legacy peer must not reach.
///
/// The mirror of the list above, and needed for the same reason: serving a
/// 2026 method to a 2025 client tells it the gateway speaks a revision that
/// client cannot hold up its end of.
///
/// `tasks/get` and `tasks/update` are listed because the revision adds them, not
/// because this gateway serves them: neither is implemented. `tasks/get`
/// previously answered every handle with a `not_found` **success**, which is
/// not in the protocol's task model and told a client its handle had been
/// looked up and missed. Both now reach the ordinary method-not-found answer,
/// which is true. The specification page for the tasks extension returns 404 at
/// the path its own index links, so there is no shape to implement against yet.
pub const ADDED_IN_2026_07_28: &[&str] = &["subscriptions/listen", "tasks/get", "tasks/update"];

/// The client capability a method needs, if it needs one.
///
/// A server **MUST NOT** rely on a capability the client has not declared, so
/// this is consulted before dispatch rather than discovered inside it — a
/// handler that finds out halfway through has already had an effect.
#[must_use]
pub fn required_capability(method: &str) -> Option<&'static str> {
    match method {
        "sampling/createMessage" => Some("sampling"),
        "elicitation/create" => Some("elicitation"),
        "roots/list" => Some("roots"),
        _ => None,
    }
}

/// The elicitation modes this gateway can service, as its own closed set.
///
/// A mode is not a caller string. The specification names the modes, the
/// gateway implements the ones it can relay, and anything outside that set is
/// refused rather than carried — which is what keeps a declaration bounded by
/// the gateway's vocabulary instead of the caller's input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitationMode {
    /// The default: a structured form the client renders.
    Form,
    /// A URL the client opens out of band.
    Url,
}

impl ElicitationMode {
    /// How the gateway renders this mode, for a refusal payload.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Form => "form",
            Self::Url => "url",
        }
    }

    /// The mode an `elicitation/create` request asks in, or `None` when the
    /// value is one this gateway cannot service.
    ///
    /// An omitted `mode` is form because the specification's request table says
    /// so — the entry reads *"Optional for form mode (defaults to `"form"` if
    /// omitted)"*. An explicit `null` resolves the same way: `Option` cannot
    /// distinguish the two, the specification draws no distinction between
    /// them, and so neither does the gateway.
    #[must_use]
    pub fn from_params(params: Option<&Value>) -> Option<Self> {
        match params.and_then(|p| p.get("mode")) {
            None | Some(Value::Null) => Some(Self::Form),
            Some(Value::String(mode)) => match mode.as_str() {
                "form" => Some(Self::Form),
                "url" => Some(Self::Url),
                _ => None,
            },
            Some(_) => None,
        }
    }
}

/// What a client declared, as a fixed set of flags this gateway owns.
///
/// Heapless and `Copy` on purpose. The declaration arrives inside `_meta` on a
/// path that runs before anything has decided the request is wanted, so the
/// parse must not retain a caller-sized allocation — a declaration of ten
/// thousand keys reduces to these five bits and the rest is dropped where it
/// was read. Every consumer asks a closed question, and a closed question does
/// not need the caller's strings to answer it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Declared {
    sampling: bool,
    elicitation: bool,
    roots: bool,
    elicitation_form: bool,
    elicitation_url: bool,
}

impl Declared {
    /// A client that declared nothing — the answer for every legacy and
    /// malformed shape, which carry no declaration to read.
    pub const NONE: Self = Self {
        sampling: false,
        elicitation: false,
        roots: false,
        elicitation_form: false,
        elicitation_url: false,
    };

    /// Whether a capability was declared by name.
    ///
    /// Names outside the gateway's set answer `false` rather than looking the
    /// caller's key up: a capability this build cannot service was not
    /// declared to it, whatever the client wrote.
    #[must_use]
    pub fn has(self, capability: &str) -> bool {
        match capability {
            "sampling" => self.sampling,
            "elicitation" => self.elicitation,
            "roots" => self.roots,
            _ => false,
        }
    }

    /// Whether an elicitation mode was declared.
    #[must_use]
    pub fn has_elicitation_mode(self, mode: ElicitationMode) -> bool {
        match mode {
            ElicitationMode::Form => self.elicitation_form,
            ElicitationMode::Url => self.elicitation_url,
        }
    }

    /// Read a declaration out of a `clientCapabilities` object.
    ///
    /// Only an object-valued key declares. The specification writes a declared
    /// capability as an object, an explicitly-null one is still absent, and a
    /// string or a number names no mode at all — so none of them may reach a
    /// consumer as a declaration of something the client can be sent.
    fn parse(capabilities: &serde_json::Map<String, Value>) -> Self {
        let elicitation = capabilities.get("elicitation").and_then(Value::as_object);
        // An empty object is the specification's own way of declaring a
        // capability with no options, and elicitation's option-less shape is
        // the form mode. Applied here, before unrecognised keys are dropped, so
        // that a declaration of nothing but unrecognised modes stays a
        // declaration of no mode rather than picking this default up on the
        // way out.
        let (declares_form, declares_url) = match elicitation {
            Some(modes) if modes.is_empty() => (true, false),
            Some(modes) => (
                modes.get("form").is_some_and(Value::is_object),
                modes.get("url").is_some_and(Value::is_object),
            ),
            None => (false, false),
        };
        Self {
            sampling: capabilities.get("sampling").is_some_and(Value::is_object),
            elicitation: elicitation.is_some(),
            roots: capabilities.get("roots").is_some_and(Value::is_object),
            elicitation_form: declares_form,
            elicitation_url: declares_url,
        }
    }
}

impl RequestShape {
    /// The capabilities this request declared, in declaration order.
    ///
    /// Empty for legacy and malformed shapes: neither carries a declaration to
    /// read, and a capability the client did not mention was not declared.
    ///
    /// The names travel rather than a single "may be asked for input" bit
    /// because MRTR.9 refuses **per requested method** — a client that declared
    /// `elicitation` and not `sampling` may be sent one and not the other, and
    /// a boolean cannot tell those apart.
    #[must_use]
    pub fn declared_capabilities(&self) -> Declared {
        match self {
            RequestShape::Modern(f) => f.declared_capabilities,
            _ => Declared::NONE,
        }
    }
}

impl RequestFields {
    /// Whether the client declared a capability by name.
    ///
    /// Absent and explicitly-absent are the same answer: the specification's
    /// rule is that the server may not rely on what was not declared, and a
    /// capability the client did not mention was not declared.
    #[must_use]
    pub fn declares_capability(&self, name: &str) -> bool {
        self.declared_capabilities.has(name)
    }
}

/// The longest protocol revision this gateway will repeat into its own log.
/// `2026-07-28` is ten characters; the bound is generous enough that no real
/// revision reaches it and small enough that a hostile one cannot fill a disk.
const MAX_LOGGED_FIELD_LEN: usize = 64;

/// Bounds a request-sourced string before it reaches an observation record.
///
/// Every field on the NFR.OBS.1 record arrives from the request and the body
/// limit is megabytes, so writing any of them verbatim lets one caller choose
/// how much operator disk a single request consumes. Applied per field rather
/// than per value so a field added later inherits the bound instead of
/// reintroducing the hole beside the fields that carry it.
fn bounded_for_log(value: &str) -> &str {
    if value.len() > MAX_LOGGED_FIELD_LEN {
        "oversized"
    } else {
        value
    }
}

/// Classifies a request and records what revision it declared, in one place.
///
/// NFR.OBS.1. The revision this request is written against, and which of the
/// places carried it. A record naming only the revision cannot tell a stateless
/// `_meta` declaration from a session's handshake, and the two are served by
/// different code paths -- which is the whole reason to record it.
///
/// Classification and the record live together because they are one fact read
/// once. Kept apart, the record sat inside the HTTP handler while the stdio
/// dispatcher classified nothing, so a stdio session was observed by nothing at
/// all; a second copy beside the stdio dispatcher would have restored the
/// symptom's shape and left the two free to disagree. Callers that need the
/// shape take it from the return value rather than re-deriving it.
///
/// `header_version` is the transport's own declaration where a transport has
/// one. Stdio has no headers, so it passes `None` and a modern request there
/// can only be sourced to `_meta`.
///
/// Emitted above any early return the caller makes, so every request that
/// reaches a dispatcher is recorded and not only the well-formed ones.
pub fn classify_and_observe(
    method: &str,
    params: Option<&Value>,
    header_version: Option<&str>,
) -> RequestShape {
    let shape = classify_request(params, header_version);
    let (protocol_revision, revision_source) = match &shape {
        RequestShape::Modern(fields) => (fields.protocol_version.as_str(), "_meta"),
        // Declared itself modern and then omitted a required field. The
        // revision may still be readable, and it may be readable from either
        // place, so both are consulted and the record names the one that
        // carried it. Reading only the header attributed a body-declared
        // caller to `absent`, and labelled a header-only declaration `_meta`;
        // each is a wrong answer about a request that was refused, which is
        // exactly the population this record exists to explain.
        RequestShape::Malformed { .. } => match params
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get(KEY_PROTOCOL_VERSION))
            .and_then(Value::as_str)
        {
            Some(version) => (version, "_meta"),
            None => match header_version {
                Some(version) => (version, "header"),
                None => ("absent", "none"),
            },
        },
        // A legacy revision is settled once at `initialize` and echoed on every
        // later request in the header, so both readings below report the same
        // handshake rather than a second source.
        RequestShape::Legacy => match header_version.or_else(|| {
            params
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str)
        }) {
            Some(version) => (version, "handshake"),
            None => ("absent", "none"),
        },
    };
    // Both request-sourced fields are bounded before they are written. A
    // revision is a short dated token and a method is a short name; anything
    // longer is neither, and the record says so rather than repeating it.
    info!(
        target: "mcp_gateway::observed",
        method = bounded_for_log(method),
        protocol_revision = bounded_for_log(protocol_revision),
        revision_source,
        "protocol revision observed"
    );
    shape
}

#[cfg(test)]
mod declared_capabilities_tests {
    use super::{Declared, RequestShape, classify_request};
    use serde_json::json;

    fn modern_params(caps: &serde_json::Value) -> serde_json::Value {
        json!({"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": caps
        }})
    }

    #[test]
    fn a_modern_request_carries_the_names_it_declared() {
        let shape = classify_request(
            Some(&modern_params(&json!({"elicitation": {}}))),
            Some("2026-07-28"),
        );
        assert!(
            matches!(shape, RequestShape::Modern(_)),
            "fixture must be modern"
        );
        assert!(shape.declared_capabilities().has("elicitation"));
    }

    #[test]
    fn declaring_nothing_carries_no_names() {
        let shape = classify_request(Some(&modern_params(&json!({}))), Some("2026-07-28"));
        assert!(
            matches!(shape, RequestShape::Modern(_)),
            "fixture must be modern"
        );
        assert_eq!(shape.declared_capabilities(), Declared::NONE);
    }

    #[test]
    fn a_neighbouring_capability_is_carried_under_its_own_name() {
        // The names must stay distinguishable: collapsing them to one bit is
        // what MRTR.9's per-method refusal cannot be built on.
        for cap in ["sampling", "roots"] {
            let shape =
                classify_request(Some(&modern_params(&json!({cap: {}}))), Some("2026-07-28"));
            assert!(shape.declared_capabilities().has(cap), "{cap}");
        }
    }

    #[test]
    fn a_shape_that_failed_to_classify_declares_nothing() {
        // The doc comment names this an empty case, so something has to hold it
        // there. Production does not reach it today -- the handler returns on a
        // failed classification before the field is read -- which is exactly why
        // a mutant returning a non-empty slice would otherwise go unnoticed.
        let shape = RequestShape::Malformed {
            missing: vec!["protocolVersion"],
        };
        assert_eq!(shape.declared_capabilities(), Declared::NONE);
    }

    #[test]
    fn a_legacy_request_declares_nothing() {
        let shape = classify_request(Some(&json!({})), Some("2025-11-25"));
        assert!(
            matches!(shape, RequestShape::Legacy),
            "fixture must be legacy"
        );
        assert_eq!(shape.declared_capabilities(), Declared::NONE);
    }
}

/// MIK-7212.MRTR.9a — the parse boundary.
///
/// These are unit tests rather than component tests because the property lives
/// here: a component test cannot distinguish "dropped at parse" from "ignored
/// at comparison", and those two implementations differ exactly where the
/// security argument is.
#[cfg(test)]
mod declared_parse_boundary_tests {
    use super::{Declared, ElicitationMode, classify_request};
    use serde_json::{Value, json};

    fn declaring(capabilities: Value) -> Declared {
        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": capabilities
            }
        });
        classify_request(Some(&params), Some("2026-07-28")).declared_capabilities()
    }

    /// Case 3. A declaration of arbitrary size reduces to a fixed set of flags.
    ///
    /// Three assertions, because no one of them suffices. The contents check
    /// cannot observe a retained allocation; `size_of` catches an owning field
    /// only through the width it happens to add, and a same-sized substitution
    /// would slip past it; the `Copy` bound rejects an owning field by kind
    /// rather than by width. The last two fail the *build*, which is the case a
    /// contents assertion cannot reach.
    #[test]
    fn a_declaration_of_any_size_parses_to_a_fixed_heapless_value() {
        const fn assert_copy<T: Copy>() {}
        assert_copy::<Declared>();
        assert!(
            size_of::<Declared>() <= 8,
            "Declared must stay a handful of flags; a growth here is a caller-sized field \
             arriving by the back door"
        );

        let mut modes = serde_json::Map::new();
        let mut capabilities = serde_json::Map::new();
        for index in 0..10_000 {
            modes.insert(format!("mode_{index}"), json!({}));
            capabilities.insert(format!("capability_{index}"), json!({}));
        }
        modes.insert("form".to_string(), json!({}));
        capabilities.insert("elicitation".to_string(), Value::Object(modes));

        let declared = declaring(Value::Object(capabilities));
        assert_eq!(
            declared,
            Declared {
                sampling: false,
                elicitation: true,
                roots: false,
                elicitation_form: true,
                elicitation_url: false,
            },
            "twenty thousand caller keys must reduce to the one recognised capability and the \
             one recognised mode, and to nothing else"
        );
    }

    /// Case 4. Only an object declares — on both levels.
    #[test]
    fn a_non_object_value_declares_neither_a_capability_nor_a_mode() {
        for value in [json!(null), json!("form"), json!(7), json!([])] {
            let declared = declaring(json!({ "elicitation": value }));
            assert_eq!(
                declared,
                Declared::NONE,
                "elicitation set to {value} names no mode, so it declares nothing"
            );

            let declared = declaring(json!({ "elicitation": { "form": value } }));
            assert!(
                !declared.has_elicitation_mode(ElicitationMode::Form),
                "a form key set to {value} is not a declaration of form mode"
            );
        }
    }

    /// Case 4, the other half: a *populated* object is still a declaration, so
    /// the rule cannot be implemented as "empty objects only".
    #[test]
    fn a_populated_mode_object_still_declares_that_mode() {
        let declared = declaring(json!({ "elicitation": { "form": { "maxLength": 40 } } }));
        assert!(declared.has_elicitation_mode(ElicitationMode::Form));
        assert!(!declared.has_elicitation_mode(ElicitationMode::Url));
    }

    /// Case 5. The request side takes strings, and only the two this gateway
    /// services.
    #[test]
    fn an_unreadable_requested_mode_is_no_mode_at_all() {
        for value in [json!(7), json!([]), json!({}), json!("Form")] {
            assert_eq!(
                ElicitationMode::from_params(Some(&json!({ "mode": value }))),
                None,
                "mode {value} is not one this gateway can service, and must not be honoured as one"
            );
        }
    }

    /// Case 5, the boundary the plan pins deliberately: an explicit `null`
    /// resolves through the same default as an omitted field. `Option` cannot
    /// tell the two apart, the specification draws no distinction between them,
    /// and so neither does the gateway.
    #[test]
    fn an_explicit_null_mode_resolves_the_same_way_as_an_absent_one() {
        let absent = ElicitationMode::from_params(Some(&json!({ "message": "Which one?" })));
        let null = ElicitationMode::from_params(Some(&json!({ "mode": Value::Null })));
        assert_eq!(absent, Some(ElicitationMode::Form));
        assert_eq!(null, absent, "an explicit null is not a fifth thing");
        assert_eq!(ElicitationMode::from_params(None), absent);
    }
}
