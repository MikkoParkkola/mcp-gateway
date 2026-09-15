// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Open `WebUI` assertion adapter: a signed header, verified with adapter-owned
//! HMAC material, turned into a namespaced [`VerifiedIdentity`].
//!
//! WHAT THIS IS NOT. It is not an authentication path. It runs strictly AFTER
//! the standard auth middleware and adds nothing to what the caller may do: a
//! request arrives here already authenticated, and the adapter only answers
//! "which end user is this authenticated caller acting for". That ordering is
//! the whole security story, so it is enforced by where the layer is applied in
//! `router::create_router_with` and re-checked here — a request with no
//! [`NamedApiKey`] in its extensions is refused rather than trusted.
//!
//! WHY AN API KEY AND NOTHING ELSE. The assertion is a bearer-equivalent
//! statement about a third party, so the presenter must be a credential an
//! operator explicitly listed in `allowed_api_key_names`. The gateway bearer is
//! deliberately NOT eligible even if an operator names an API key "bearer"
//! (see [`NamedApiKey`], which is minted only where a key is actually matched),
//! and neither is a key-server temporary token or a delegated OIDC bearer:
//! those already carry their own verified identity, and letting them also
//! assert one would be an identity-substitution path.
//!
//! WHY THE MATERIAL IS RESOLVED HERE AND NOT READ FROM THE LOAD. Configuration
//! validation runs the structural half of the adapter rules for a DISABLED
//! account store and stops before any adapter secret is read. The adapter list
//! is a gateway identity path and is not gated on custody being open, so this
//! module calls [`resolve_adapter_runtime`], which runs the material half for
//! enabled and disabled blocks alike. A failure is a REFUSAL, never a
//! downgrade: the configured headers are still recognised and rejected, so a
//! misconfigured deployment fails closed instead of passing the assertion
//! through to a handler that might read it.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use tracing::warn;

use crate::config::Config;
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::config::{
    AdapterRuntime, GatewayCredential, SecretOverlay, adapter_header_names, resolve_adapter_runtime,
};

use super::auth::NamedApiKey;

/// One adapter, keyed by the header it is configured to read.
struct Trusted {
    runtime: AdapterRuntime,
    decoding_key: DecodingKey,
}

/// The adapter layer's state: either trusted material per header, or a refusal
/// set of headers whose material could not be established.
///
/// Cloneable because axum's `from_fn_with_state` takes the state by value per
/// request; everything expensive (and every secret) sits behind one `Arc`.
#[derive(Clone)]
pub(crate) struct OpenWebUiAdapterState {
    inner: Arc<AdapterInner>,
}

struct AdapterInner {
    /// Header name -> every trusted installation configured to read it.
    ///
    /// A `Vec` and not one entry: configuration deliberately permits several
    /// installations to share a header (a fleet behind one proxy), so keying by
    /// header alone would silently drop all but the last one and make the
    /// surviving installation the only identity anyone could assert.
    /// Empty when refusing.
    trusted: HashMap<HeaderName, Vec<Trusted>>,
    /// Every configured header, trusted or not, so a refusing runtime still
    /// recognises what it must reject. DEDUPLICATED: this list drives the
    /// "how many assertion headers did the request present" count, and a header
    /// named by two installations would otherwise count one request header
    /// twice and refuse every legitimate caller as a duplicate.
    configured: Vec<HeaderName>,
}

impl OpenWebUiAdapterState {
    /// Build the adapter state for a config, or `None` when no adapter is
    /// configured.
    ///
    /// `None` is the load-bearing case: the overwhelming majority of
    /// deployments configure no adapter, and they must keep EXACTLY the
    /// behaviour they had — no layer, no header inspection, no environment
    /// lookup. The caller therefore skips wiring the middleware entirely rather
    /// than installing a pass-through, so "no adapter" cannot regress into "an
    /// adapter that happens to allow everything".
    pub(crate) fn from_config(config: &Config, overlay: &dyn SecretOverlay) -> Option<Self> {
        let accounts = config.accounts.as_ref();
        let mut configured: Vec<HeaderName> = Vec::new();
        for name in adapter_header_names(accounts)
            .iter()
            .filter_map(|name| header_name(name))
        {
            if !configured.contains(&name) {
                configured.push(name);
            }
        }
        if configured.is_empty() {
            return None;
        }

        // Built here rather than borrowed from the loader: `Config` keeps its
        // credential list private to the config module, and the adapter must be
        // compared against the credentials AS CONFIGURED (borrowed text), never
        // against a resolved `auto` bearer that differs per call.
        let credentials = gateway_credentials(config);

        let trusted = match resolve_adapter_runtime(accounts, overlay, &credentials) {
            Ok(runtimes) => {
                let mut trusted: HashMap<HeaderName, Vec<Trusted>> = HashMap::new();
                for runtime in runtimes {
                    let Some(name) = header_name(&runtime.header) else {
                        continue;
                    };
                    let decoding_key = DecodingKey::from_secret(&runtime.secret);
                    // Appended, never inserted over: every installation that
                    // named this header stays a candidate.
                    trusted.entry(name).or_default().push(Trusted {
                        runtime,
                        decoding_key,
                    });
                }
                trusted
            }
            Err(error) => {
                // The error is logged WITHOUT the offending value: these
                // failures are about secret material, and the diagnostic must
                // not become the leak. `AdapterRuntime` has no `Debug` for the
                // same reason.
                warn!(
                    %error,
                    "Open WebUI adapter material could not be established; \
                     assertion headers will be refused"
                );
                HashMap::new()
            }
        };

        Some(Self {
            inner: Arc::new(AdapterInner {
                trusted,
                configured,
            }),
        })
    }
}

#[cfg(test)]
impl OpenWebUiAdapterState {
    /// Test-only view of the identity half of the middleware: which principal,
    /// if any, this state resolves an assertion to once the caller checks (a
    /// named API key, no conflicting identity) have already passed.
    ///
    /// It calls the SAME [`resolve_identity`] the middleware calls, so a test
    /// asserting that two installations sharing a header keep distinct
    /// principals is asserting about the production path and not a
    /// reimplementation of it.
    pub(crate) fn resolved_identity_for_test(
        &self,
        header: &str,
        api_key_name: &str,
        token: &str,
    ) -> Option<VerifiedIdentity> {
        let name = header_name(header)?;
        let candidates = self.inner.trusted.get(&name)?;
        resolve_identity(candidates, api_key_name, token).ok()
    }
}

/// The gateway authentication credentials as configured, for the no-reuse rule.
fn gateway_credentials(config: &Config) -> Vec<GatewayCredential<'_>> {
    let mut credentials: Vec<GatewayCredential<'_>> = Vec::new();
    if let Some(token) = config.auth.bearer_token.as_deref() {
        credentials.push(GatewayCredential::BearerToken(token));
    }
    for (index, api_key) in config.auth.api_keys.iter().enumerate() {
        credentials.push(GatewayCredential::ApiKey {
            index,
            name: api_key.name.as_str(),
            spec: api_key.key.as_str(),
        });
    }
    credentials
}

fn header_name(raw: &str) -> Option<HeaderName> {
    HeaderName::try_from(raw.to_ascii_lowercase()).ok()
}

/// The assertion claims this gateway is willing to read.
///
/// Everything else the upstream puts in the token — `roles`, `email`, `name`,
/// group lists — is DISCARDED by not being a field here. An adapter proves who
/// the end user is, not what they may do; authorisation stays with the
/// presented API key. Deserialising roles would mean an upstream could grant
/// itself privileges by editing a token it signs.
#[derive(Deserialize)]
struct AssertionClaims {
    sub: String,
    iat: i64,
    exp: i64,
}

/// Reasons an assertion is refused. Rendered as one opaque status to the
/// caller; the detail exists for the operator's log.
enum Refusal {
    DuplicateHeader,
    MalformedHeader,
    NoTrustedMaterial,
    NotApiKeyAuthenticated,
    KeyNotAllowed,
    ConflictingIdentity,
    AmbiguousIdentity,
    Invalid(&'static str),
}

impl Refusal {
    fn reason(&self) -> &'static str {
        match self {
            Self::DuplicateHeader => "duplicate assertion headers",
            Self::MalformedHeader => "malformed assertion header",
            Self::NoTrustedMaterial => "adapter material not established",
            Self::NotApiKeyAuthenticated => "caller did not authenticate with an API key",
            Self::KeyNotAllowed => "API key not permitted to assert for this adapter",
            Self::ConflictingIdentity => "request already carries a verified identity",
            Self::AmbiguousIdentity => "assertion verified for more than one installation",
            Self::Invalid(detail) => detail,
        }
    }
}

/// Verify an Open `WebUI` assertion header, when one is present.
///
/// Pass-through is the default: a request carrying no configured assertion
/// header is untouched, so wiring this layer changes nothing for callers that
/// do not use the adapter.
pub(crate) async fn openwebui_adapter_middleware(
    State(state): State<OpenWebUiAdapterState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let inner = &state.inner;

    // Which configured headers did this request actually present? Counting
    // ACROSS adapters and counting REPEATS of one header are the same check:
    // two assertions on one request have no defensible winner, and picking
    // either would let a caller who can append a header override the one an
    // upstream proxy set.
    //
    // Values are copied out before anything else so the header map is no longer
    // borrowed when the accepted request has its assertion header removed.
    let presented: Vec<(HeaderName, Option<String>)> = inner
        .configured
        .iter()
        .flat_map(|name| {
            request
                .headers()
                .get_all(name)
                .iter()
                .map(|value| (name.clone(), value.to_str().ok().map(str::to_owned)))
        })
        .collect();
    let (header, value) = match presented.len() {
        0 => return next.run(request).await,
        1 => presented
            .into_iter()
            .next()
            .unwrap_or_else(|| unreachable!()),
        _ => return refuse(&Refusal::DuplicateHeader),
    };

    let Some(token) = value else {
        return refuse(&Refusal::MalformedHeader);
    };
    let token = token.trim();

    let candidates = match inner.trusted.get(&header) {
        Some(candidates) if !candidates.is_empty() => candidates,
        _ => return refuse(&Refusal::NoTrustedMaterial),
    };

    // The presenter must be a named API key. Checked once, before any adapter
    // is consulted: it is a property of the caller, not of an installation.
    let Some(api_key) = request.extensions().get::<NamedApiKey>() else {
        return refuse(&Refusal::NotApiKeyAuthenticated);
    };
    let api_key_name = api_key.name().to_owned();

    // A request that already carries a verified identity (key-server temporary
    // token, delegated OIDC bearer) is refused rather than overwritten: two
    // answers to "who is this" is a substitution attempt, and silently
    // preferring either one would be a way to launder an identity.
    if request.extensions().get::<VerifiedIdentity>().is_some() {
        return refuse(&Refusal::ConflictingIdentity);
    }

    let identity = match resolve_identity(candidates, &api_key_name, token) {
        Ok(identity) => identity,
        Err(refusal) => return refuse(&refusal),
    };

    // The header is consumed. A handler must not be able to re-read the raw
    // assertion and reach its own, weaker conclusion about it.
    request.headers_mut().remove(&header);
    request.extensions_mut().insert(identity);
    next.run(request).await
}

/// Resolve one assertion against every installation configured to read the
/// header it arrived on.
///
/// Several installations may share a header, so the assertion is offered to
/// each of them and the SIGNATURE decides which one minted it. Every candidate
/// is tried — no early return on the first failure — because a failure only
/// means "not this installation's token", and stopping there would make
/// acceptance depend on configuration order.
///
/// EXACTLY ONE must succeed. Zero is a plain refusal, reported as the first
/// reason seen so the operator log names a real cause. Two or more means two
/// installations hold material that verifies the same assertion: the subject is
/// then ambiguous and is refused rather than resolved by preferring one, since
/// preferring one would silently pick which installation's user a caller is
/// acting for.
fn resolve_identity(
    candidates: &[Trusted],
    api_key_name: &str,
    token: &str,
) -> Result<VerifiedIdentity, Refusal> {
    let mut accepted: Option<VerifiedIdentity> = None;
    let mut first_refusal: Option<Refusal> = None;
    for candidate in candidates {
        // Per-installation: the allow-list belongs to the installation being
        // asserted for, not to the header they happen to share.
        if !candidate
            .runtime
            .allowed_api_key_names
            .iter()
            .any(|allowed| allowed == api_key_name)
        {
            first_refusal.get_or_insert(Refusal::KeyNotAllowed);
            continue;
        }
        match verify(&candidate.runtime, &candidate.decoding_key, token) {
            Ok(identity) => {
                if accepted.is_some() {
                    return Err(Refusal::AmbiguousIdentity);
                }
                accepted = Some(identity);
            }
            Err(refusal) => {
                first_refusal.get_or_insert(refusal);
            }
        }
    }
    accepted.ok_or(first_refusal.unwrap_or(Refusal::NoTrustedMaterial))
}

/// Verify one assertion against one adapter's material and rules.
fn verify(
    runtime: &AdapterRuntime,
    key: &DecodingKey,
    token: &str,
) -> Result<VerifiedIdentity, Refusal> {
    // HS256 only, fixed by the algorithm this `Validation` is constructed with:
    // the token's own `alg` header cannot select a different verification, so
    // `none` and an RS/HS confusion are both rejected before any signature
    // check.
    let mut validation = Validation::new(Algorithm::HS256);
    // Presence is required, not merely "checked if present": a token missing
    // `exp` would otherwise be an eternal one.
    validation.set_required_spec_claims(&["sub", "iat", "exp", "iss"]);
    validation.set_issuer(&[runtime.issuer.as_str()]);
    validation.validate_exp = true;
    // No audience is configured for these assertions, and leaving `aud`
    // validation on with an empty expected set rejects everything.
    validation.validate_aud = false;
    validation.leeway = runtime.clock_skew_seconds;

    let claims = decode::<AssertionClaims>(token, key, &validation)
        .map_err(|_| Refusal::Invalid("signature or claim validation failed"))?
        .claims;

    if claims.sub.is_empty() {
        return Err(Refusal::Invalid("empty subject"));
    }

    // Lifetime is bounded from the token's OWN claims, so an upstream cannot
    // mint a year-long assertion that stays valid if it leaks. `exp <= iat` is
    // rejected as incoherent rather than treated as an already-expired token.
    let lifetime = claims
        .exp
        .checked_sub(claims.iat)
        .ok_or(Refusal::Invalid("incoherent lifetime"))?;
    if lifetime <= 0 {
        return Err(Refusal::Invalid("expiry not after issuance"));
    }
    let max = i64::try_from(runtime.max_lifetime_seconds)
        .map_err(|_| Refusal::Invalid("configured max lifetime out of range"))?;
    if lifetime > max {
        return Err(Refusal::Invalid("lifetime exceeds configured maximum"));
    }

    // Future-dated issuance, beyond the configured skew, is refused: it is how
    // a token's effective lifetime gets extended past the bound just checked.
    let now = now_seconds();
    let skew = i64::try_from(runtime.clock_skew_seconds)
        .map_err(|_| Refusal::Invalid("configured clock skew out of range"))?;
    if claims.iat > now.saturating_add(skew) {
        return Err(Refusal::Invalid("issued in the future"));
    }

    Ok(VerifiedIdentity {
        subject: claims.sub,
        // Not carried: an adapter asserts a subject, and an email or group list
        // taken from it would flow into role mapping as if an IdP had verified
        // it.
        email: String::new(),
        name: None,
        groups: Vec::new(),
        issuer: namespaced_issuer(&runtime.installation_id),
    })
}

/// The issuer this identity is recorded under.
///
/// NOT the adapter's configured `issuer`: that value is an upstream's own
/// string, and recording it verbatim would let an adapter claim to be a real
/// OIDC provider — `VerifiedIdentity::stable_actor_id` is issuer+subject, so a
/// matching issuer plus a chosen subject IS another provider's user. The
/// installation id is length-prefixed for the same collision reason
/// `stable_actor_id` length-prefixes its parts.
fn namespaced_issuer(installation_id: &str) -> String {
    format!(
        "openwebui-adapter:{}:{}",
        installation_id.len(),
        installation_id
    )
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// One status and one body for every refusal.
///
/// The caller learns that the assertion was not accepted and nothing about
/// which rule caught it: the detail goes to the operator's log, because a
/// distinguishable response is an oracle for probing an adapter's issuer,
/// lifetime bound, and allow-list.
fn refuse(refusal: &Refusal) -> Response {
    warn!(reason = refusal.reason(), "Open WebUI assertion refused");
    (StatusCode::FORBIDDEN, "Invalid identity assertion").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::{Value, json};

    const SECRET: &[u8] = b"fixture-adapter-signing-secret-123456789";

    fn runtime(installation: &str) -> AdapterRuntime {
        AdapterRuntime {
            installation_id: installation.to_string(),
            header: "x-openwebui-assertion".to_string(),
            issuer: "open-webui".to_string(),
            allowed_api_key_names: vec!["owui".to_string()],
            max_lifetime_seconds: 300,
            clock_skew_seconds: 30,
            secret: SECRET.to_vec(),
        }
    }

    fn claims(subject: &str) -> Value {
        let now = now_seconds();
        json!({"iss":"open-webui", "sub":subject, "iat":now, "exp":now+120,
            "email":"untrusted@example.invalid", "roles":["admin"], "groups":["admin"]})
    }

    fn token(claims: &Value, algorithm: Algorithm, secret: &[u8]) -> String {
        encode(
            &Header::new(algorithm),
            claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    #[test]
    fn identities_are_namespaced_and_profile_claims_are_discarded() {
        let key = DecodingKey::from_secret(SECRET);
        let alice = token(&claims("alice"), Algorithm::HS256, SECRET);
        let bob = token(&claims("bob"), Algorithm::HS256, SECRET);
        let a = verify(&runtime("desk"), &key, &alice).unwrap_or_else(|_| panic!("valid Alice"));
        let b = verify(&runtime("desk"), &key, &bob).unwrap_or_else(|_| panic!("valid Bob"));
        let other = verify(&runtime("laptop"), &key, &alice)
            .unwrap_or_else(|_| panic!("valid installation"));
        assert_ne!(a.stable_actor_id(), b.stable_actor_id());
        assert_ne!(a.stable_actor_id(), other.stable_actor_id());
        assert_eq!(a.subject, "alice");
        assert!(a.email.is_empty());
        assert!(a.name.is_none());
        assert!(a.groups.is_empty());
        assert_ne!(a.issuer, "open-webui");
    }

    fn trusted(installation: &str, secret: &[u8]) -> Trusted {
        let mut runtime = runtime(installation);
        runtime.secret = secret.to_vec();
        Trusted {
            decoding_key: DecodingKey::from_secret(secret),
            runtime,
        }
    }

    /// Installations sharing a header are resolved by SIGNATURE, and exactly
    /// one of them must succeed.
    #[test]
    fn shared_header_resolves_to_exactly_one_installation() {
        const OTHER: &[u8] = b"fixture-second-installation-secret-987654321";
        let candidates = vec![trusted("desk", SECRET), trusted("laptop", OTHER)];
        let desk = token(&claims("alice"), Algorithm::HS256, SECRET);
        let laptop = token(&claims("alice"), Algorithm::HS256, OTHER);

        let first = resolve_identity(&candidates, "owui", &desk)
            .unwrap_or_else(|_| panic!("desk assertion"));
        let second = resolve_identity(&candidates, "owui", &laptop)
            .unwrap_or_else(|_| panic!("laptop assertion"));
        // Order-independent: the second installation is reachable even though
        // it is not the first candidate tried.
        assert_ne!(first.stable_actor_id(), second.stable_actor_id());
        assert_eq!(first.subject, second.subject);

        // Signed by neither, and presented by an API key neither installation
        // lists: both are refusals, not a fallback to some other installation.
        assert!(
            resolve_identity(
                &candidates,
                "owui",
                &token(&claims("alice"), Algorithm::HS256, b"unconfigured-secret")
            )
            .is_err()
        );
        assert!(resolve_identity(&candidates, "unlisted", &desk).is_err());

        // Two installations that both verify the same assertion give two
        // answers to "who is this", so the assertion is refused outright.
        let ambiguous = vec![trusted("desk", SECRET), trusted("laptop", SECRET)];
        assert!(resolve_identity(&ambiguous, "owui", &desk).is_err());
    }

    #[test]
    fn invalid_signatures_algorithms_and_claims_are_refused() {
        let runtime = runtime("desk");
        let key = DecodingKey::from_secret(SECRET);
        assert!(
            verify(
                &runtime,
                &key,
                &token(&claims("alice"), Algorithm::HS256, b"wrong-key")
            )
            .is_err()
        );
        assert!(
            verify(
                &runtime,
                &key,
                &token(&claims("alice"), Algorithm::HS384, SECRET)
            )
            .is_err()
        );
        for field in ["sub", "iat", "exp", "iss"] {
            let mut value = claims("alice");
            value.as_object_mut().unwrap().remove(field);
            assert!(
                verify(&runtime, &key, &token(&value, Algorithm::HS256, SECRET)).is_err(),
                "missing {field}"
            );
        }
        let now = now_seconds();
        for (field, value) in [
            ("sub", json!("")),
            ("iss", json!("attacker")),
            ("exp", json!(now - 60)),
            ("exp", json!(now + 3600)),
            ("iat", json!(now + 60)),
            ("iat", json!(i64::MIN)),
        ] {
            let mut invalid = claims("alice");
            invalid[field] = value;
            assert!(
                verify(&runtime, &key, &token(&invalid, Algorithm::HS256, SECRET)).is_err(),
                "invalid {field}"
            );
        }
    }
}
