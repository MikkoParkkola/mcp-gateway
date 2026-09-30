// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Raw-receipt verification of an upstream gateway's signature chain (ASI07
//! increment 3, design D2/D3/R1/R4/R7).
//!
//! Runs on the value a chained backend returned, before output-schema
//! processing, task-handle capture, continuations or the input bridge read
//! it, and binds the chain to the challenge this dispatch sent.

use std::sync::Arc;

use serde_json::Value;

use super::ChainIdentity;
use crate::config::ChainMode;
use crate::protocol::mrtr::CHAIN_NONCE_META;
use crate::protocol::{UpstreamChain, UpstreamState};
use crate::security::signature_chain::{
    CHAIN_META, ChainPolicy, ChainPurpose, content_digest, strip_chain, verify_chain,
};

/// What one dispatch learned about its upstream chain. Owned by that dispatch.
#[derive(Default)]
pub(crate) enum ChainReceipt {
    /// Not a chained backend, or not dispatched.
    #[default]
    Unchecked,
    /// A chained backend answered: the outcome to carry, if any.
    Checked(Option<Arc<UpstreamChain>>),
    /// Refused at raw receipt: the dispatch error is the caller's answer.
    Refused,
}

/// The per-dispatch slot a chained dispatch writes its receipt into.
pub(crate) type ChainSlot = parking_lot::Mutex<ChainReceipt>;

/// A fresh per-dispatch challenge: 16 bytes from the system CSPRNG, as hex.
/// Never stored, reused or shared with the client.
pub(crate) fn mint_nonce() -> crate::Result<String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0_u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| crate::Error::json_rpc(-32603, "no randomness for the chain challenge"))?;
    Ok(hex::encode(bytes))
}

/// Write this gateway's challenge into `params._meta`, keeping every other
/// member (design D2/R7). The only writer of the outbound chain nonce.
pub(crate) fn inject_nonce(params: &mut Value, nonce: &str) {
    let Some(members) = params.as_object_mut() else {
        return;
    };
    let meta = members
        .entry("_meta")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(meta) = meta.as_object_mut() {
        meta.insert(CHAIN_NONCE_META.to_owned(), Value::String(nonce.to_owned()));
    }
}

fn refusal(rule: &str) -> crate::Error {
    crate::Error::json_rpc(
        -32001,
        format!("upstream signature chain did not verify: {rule}"),
    )
}

/// Whether a reply is not a complete result: an interim round or a task handle.
fn is_interim(result: &Value) -> bool {
    matches!(
        result.get("resultType").and_then(Value::as_str),
        Some("input_required" | "task")
    )
}

/// Check `result`, the raw reply of a backend in `mode`, against `nonce`.
///
/// - `Ok(None)`: nothing to carry (mode off, or an interim reply under
///   `verify`, which then travels unchained).
/// - `Ok(Some(_))`: the verified links, or an `Unverified` outcome under
///   `verify`.
/// - `Err(-32001)`: under `require`, an interim reply or a chain that is
///   absent or fails a rule, named in the message, never the data.
///
/// The chain is always removed from `result`; only this gateway re-emits it.
pub(crate) fn receive(
    identity: &ChainIdentity,
    policy: (ChainMode, &[String], Option<&str>),
    result: &mut Value,
    nonce: &str,
    now: u64,
) -> crate::Result<Option<Arc<UpstreamChain>>> {
    let (mode, origins, signer) = policy;
    if mode == ChainMode::Off {
        return Ok(None);
    }
    if is_interim(result) {
        strip_chain(result);
        return match mode {
            ChainMode::Require => Err(refusal("interim")),
            _ => Ok(None),
        };
    }
    let received = content_digest(result).map_err(|_| refusal("Unhashable"))?;
    let chain = result
        .get("_meta")
        .and_then(|meta| meta.get(CHAIN_META))
        .cloned();
    strip_chain(result);
    let checked = match (&chain, signer) {
        (None, _) => Err("absent".to_owned()),
        (Some(_), None) => Err("signer".to_owned()),
        (Some(chain), Some(signer)) => {
            let policy = ChainPolicy {
                trusted_keys: &identity.trusted_keys,
                origins,
                signer,
                replay_window: identity.replay_window,
                max_links: identity.max_links,
                purpose: ChainPurpose::Forward,
            };
            verify_chain(chain, &policy, &received, nonce, now)
                .map(|_| ())
                .map_err(|rule| format!("{rule:?}"))
        }
    };
    let (links, state) = match (checked, mode) {
        (Ok(()), _) => (
            chain
                .and_then(|c| c.as_array().cloned())
                .unwrap_or_default(),
            UpstreamState::Verified,
        ),
        // No room to append is a capacity refusal in either mode (D5).
        (Err(rule), _) if rule == "Size" => return Err(refusal(&rule)),
        (Err(rule), ChainMode::Require) => return Err(refusal(&rule)),
        (Err(_), _) => (Vec::new(), UpstreamState::Unverified),
    };
    Ok(Some(Arc::new(UpstreamChain {
        links,
        received,
        state,
    })))
}

/// Seconds since the epoch, for freshness checks.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl super::super::MetaMcp {
    /// Mint and write this dispatch's challenge for a chained backend.
    /// `None` for an `off` backend or a gateway with no chain identity, whose
    /// params are left untouched.
    pub(crate) fn chain_challenge(
        &self,
        mode: ChainMode,
        params: &mut Value,
    ) -> crate::Result<Option<String>> {
        if mode == ChainMode::Off || self.chain_signer.is_none() {
            return Ok(None);
        }
        let nonce = mint_nonce()?;
        inject_nonce(params, &nonce);
        Ok(Some(nonce))
    }

    /// Verify a chained backend's raw reply against `challenge` and record the
    /// outcome in `slot`. A refusal is recorded too, so the caller answers
    /// with this error instead of wrapping it as a tool failure.
    pub(crate) fn chain_receive(
        &self,
        policy: (ChainMode, &[String], Option<&str>),
        result: &mut Value,
        challenge: Option<&str>,
        slot: &ChainSlot,
    ) -> crate::Result<()> {
        let (Some(identity), Some(challenge)) = (self.chain_signer.as_deref(), challenge) else {
            return Ok(());
        };
        match receive(identity, policy, result, challenge, now()) {
            Ok(outcome) => {
                *slot.lock() = ChainReceipt::Checked(outcome);
                Ok(())
            }
            Err(error) => {
                *slot.lock() = ChainReceipt::Refused;
                Err(error)
            }
        }
    }
}

impl super::super::MetaMcp {
    /// [`Self::chain_receive`] for the backend registered as `server`; the
    /// direct route's entry point. `challenge` is the nonce this gateway wrote.
    pub(crate) fn chain_receive_for(
        &self,
        server: &str,
        result: &mut Value,
        challenge: Option<&str>,
        slot: &ChainSlot,
    ) -> crate::Result<()> {
        let Some(backend) = self.backends.get(server) else {
            return Ok(());
        };
        self.chain_receive(backend.chain_policy(), result, challenge, slot)
    }

    /// The chain mode of `server`: `Off` for a name not registered, a
    /// capability backend, or a gateway with no chain identity of its own.
    pub(crate) fn chain_mode_of(&self, server: &str) -> ChainMode {
        if self.chain_signer.is_none() {
            return ChainMode::Off;
        }
        self.backends
            .get(server)
            .map_or(ChainMode::Off, |backend| backend.chain_policy().0)
    }
}

impl ChainReceipt {
    /// The chain source this receipt allows: a chained backend is eligible
    /// only with a checked outcome; an unchained dispatch keeps `Backend`.
    pub(crate) fn eligibility(&self) -> crate::protocol::ChainSource {
        match self {
            Self::Unchecked | Self::Checked(Some(_)) => crate::protocol::ChainSource::Backend,
            Self::Checked(None) | Self::Refused => crate::protocol::ChainSource::NotEligible,
        }
    }

    /// The upstream outcome to carry, if any.
    pub(crate) fn into_upstream(self) -> Option<Arc<UpstreamChain>> {
        match self {
            Self::Checked(outcome) => outcome,
            Self::Unchecked | Self::Refused => None,
        }
    }
}

impl super::super::MetaMcp {
    /// Refuse a task-augmented call to a `require` backend at admission (inc3
    /// R2): a task's answer arrives outside this dispatch's challenge, so it
    /// could never carry a checked chain. Nothing is dispatched.
    pub(crate) fn refuse_chained_task(
        &self,
        tool_name: &str,
        arguments: &Value,
    ) -> crate::Result<()> {
        let server = match tool_name {
            "gateway_invoke" => arguments.get("server").and_then(Value::as_str),
            _ => self.surfaced_tools_map.get(tool_name).map(String::as_str),
        };
        match server.map(|server| self.chain_mode_of(server)) {
            Some(ChainMode::Require) => Err(crate::Error::json_rpc(
                -32001,
                "task execution is not available for a backend that requires a signature chain",
            )),
            _ => Ok(()),
        }
    }
}
