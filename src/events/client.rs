// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one outbound client for callbacks (design §3.5): every name resolved
//! once and pinned against the deny list, IP literals checked before use, no
//! environment proxy, no redirects, bounded time and bounded reads. The
//! verification POST and every delivery go through it.

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::types::CallbackFailure;
use crate::security::ssrf::{PinningResolver, SystemResolver, in_allowed, ssrf_denial};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
/// The verification echo is the only body the gateway reads.
const MAX_READ: usize = 4096;

/// Whether a POST reads the answer's body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadBody {
    /// Read a 2xx body up to `MAX_READ` (the verification echo).
    Echo,
    /// Read nothing: a delivery needs only the status.
    Discard,
}

/// What the endpoint answered. Only the status and `Retry-After` are kept;
/// headers and the body of a delivery answer are never read.
#[derive(Debug)]
pub(crate) struct Answer {
    pub status: u16,
    pub retry_after: Option<Duration>,
    pub body: Vec<u8>,
}

/// The hardened callback client.
pub(crate) struct CallbackClient {
    http: reqwest::Client,
    allowed: Vec<(IpAddr, u8)>,
}

impl CallbackClient {
    /// Build the client; `allowed` is `events.callback_allow_private`.
    ///
    /// # Errors
    /// The TLS backend failed to initialise.
    pub(crate) fn new(allowed: Vec<(IpAddr, u8)>) -> crate::Result<Self> {
        Self::build(allowed, None)
    }

    /// As [`Self::new`], also trusting `root`: a test receiver's own CA, so a
    /// row can deliver over TLS without a process-wide trust file.
    #[cfg(test)]
    pub(crate) fn trusting(
        allowed: Vec<(IpAddr, u8)>,
        root: reqwest::Certificate,
    ) -> crate::Result<Self> {
        Self::build(allowed, Some(root))
    }

    fn build(
        allowed: Vec<(IpAddr, u8)>,
        root: Option<reqwest::Certificate>,
    ) -> crate::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(PinningResolver::new(SystemResolver).with_allowed(allowed.clone()))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT);
        if let Some(root) = root {
            builder = builder.add_root_certificate(root);
        }
        let http = crate::debug_trust_roots::extra_roots(builder)
            .build()
            .map_err(|e| crate::Error::Config(format!("events callback client: {e}")))?;
        Ok(Self { http, allowed })
    }

    /// Refuse an IP-literal host the deny list covers: a literal never
    /// reaches the pinning resolver, so it is checked here, before each use.
    pub(crate) fn check_literal(&self, url: &url::Url) -> Result<(), CallbackFailure> {
        let literal = match url.host() {
            Some(url::Host::Ipv4(v4)) => IpAddr::V4(v4),
            Some(url::Host::Ipv6(v6)) => IpAddr::V6(v6),
            _ => return Ok(()),
        };
        if crate::security::ssrf::is_private_or_reserved(literal)
            && !in_allowed(&self.allowed, literal)
        {
            return Err(CallbackFailure::ConnectionRefused);
        }
        Ok(())
    }

    /// POST the verification envelope and require the challenge echoed back.
    pub(crate) async fn verify(
        &self,
        url: &url::Url,
        subscription_id: &str,
        key: &[u8],
    ) -> Result<(), CallbackFailure> {
        let challenge =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let body = serde_json::to_vec(&serde_json::json!({
            "type": "verification",
            "challenge": challenge,
        }))
        .unwrap_or_default();
        let id = format!(
            "msg_verification_{}",
            hex::encode(rand::random::<[u8; 16]>())
        );
        let answer = self
            .post(url, subscription_id, &id, &[key], body, ReadBody::Echo)
            .await?;
        match answer.status {
            400..=499 => return Err(CallbackFailure::Http4xx),
            500..=599 => return Err(CallbackFailure::Http5xx),
            200..=299 => {}
            _ => return Err(CallbackFailure::ChallengeFailed),
        }
        let answer: serde_json::Value =
            serde_json::from_slice(&answer.body).map_err(|_| CallbackFailure::ChallengeFailed)?;
        let got = answer
            .get("challenge")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if bool::from(got.as_bytes().ct_eq(challenge.as_bytes())) {
            Ok(())
        } else {
            Err(CallbackFailure::ChallengeFailed)
        }
    }

    /// One signed POST, signed with a fresh timestamp: the only function
    /// that puts callback bytes on the wire. A transport failure is its
    /// category; any HTTP answer is returned for the caller to judge.
    pub(crate) async fn post(
        &self,
        url: &url::Url,
        subscription_id: &str,
        webhook_id: &str,
        keys: &[&[u8]],
        body: Vec<u8>,
        read: ReadBody,
    ) -> Result<Answer, CallbackFailure> {
        self.post_tracked(url, subscription_id, webhook_id, keys, body, read)
            .await
            .map_err(|(failure, _)| failure)
    }

    /// [`Self::post`], and with a failure whether it came before any byte of
    /// the request could be written (a refused literal, DNS, connect or TLS
    /// failure), so a caller can tell a body that never left the process.
    pub(crate) async fn post_tracked(
        &self,
        url: &url::Url,
        subscription_id: &str,
        webhook_id: &str,
        keys: &[&[u8]],
        body: Vec<u8>,
        read: ReadBody,
    ) -> Result<Answer, (CallbackFailure, bool)> {
        self.check_literal(url).map_err(|failure| (failure, true))?;
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let signature = sign(keys, webhook_id, &timestamp, &body);
        let mut response = self
            .http
            .post(url.clone())
            .header("content-type", "application/json")
            .header("webhook-id", webhook_id)
            .header("webhook-timestamp", &timestamp)
            .header("webhook-signature", signature)
            .header("x-mcp-subscription-id", subscription_id)
            .body(body)
            .send()
            .await
            .map_err(|e| (classify(&e), e.is_connect()))?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| retry_after(v, chrono::Utc::now()));
        let mut answer = Answer {
            status: status.as_u16(),
            retry_after,
            body: Vec::new(),
        };
        if read == ReadBody::Discard || !status.is_success() {
            return Ok(answer);
        }
        while let Some(chunk) = response.chunk().await.map_err(|e| (classify(&e), false))? {
            if answer.body.len() + chunk.len() > MAX_READ {
                return Err((CallbackFailure::ChallengeFailed, false));
            }
            answer.body.extend_from_slice(&chunk);
        }
        Ok(answer)
    }
}

/// The failure category of a transport error. Only the category leaves.
fn classify(error: &reqwest::Error) -> CallbackFailure {
    if error.is_timeout() {
        return CallbackFailure::Timeout;
    }
    if ssrf_denial(error).is_some() {
        return CallbackFailure::ConnectionRefused;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        let tls = current.downcast_ref::<rustls::Error>().is_some()
            || current
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::get_ref)
                .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some());
        if tls {
            return CallbackFailure::TlsError;
        }
        source = current.source();
    }
    CallbackFailure::ConnectionRefused
}

/// Standard Webhooks `webhook-signature`: one `v1,<base64 HMAC-SHA256>` per
/// key over `id.timestamp.body`, space-separated, newest key first.
pub(crate) fn sign(keys: &[&[u8]], id: &str, timestamp: &str, body: &[u8]) -> String {
    keys.iter()
        .map(|key| {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(id.as_bytes());
            mac.update(b".");
            mac.update(timestamp.as_bytes());
            mac.update(b".");
            mac.update(body);
            format!(
                "v1,{}",
                base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The key bytes of a `whsec_` secret of 24..=64 decoded bytes, else `None`.
pub(crate) fn decode_whsec(secret: &str) -> Option<Vec<u8>> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(secret.strip_prefix("whsec_")?)
        .ok()?;
    (24..=64).contains(&raw.len()).then_some(raw)
}

/// A `Retry-After` value: delta-seconds, or an HTTP-date (RFC 9110
/// section 10.2.3), as the wait from `now`. A date in the past waits zero.
fn retry_after(value: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let at = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    Some(
        (at.with_timezone(&chrono::Utc) - now)
            .to_std()
            .unwrap_or_default(),
    )
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
