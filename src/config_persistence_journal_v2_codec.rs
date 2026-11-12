// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Private wire DTOs: persisted claims never construct an A proof.

use serde_json::Value;

#[cfg(test)]
use crate::security::transparency_log::settle::role_fields;

use super::{
    Action, Attribution, Deserialize, Fact, FileRevision, JournalError, JournalV2, LogId, Pending,
    Phase, Role, Serialize, TokenState,
};

#[cfg(test)]
use super::{Decision, FrozenRecord, MAX_JOURNAL_BYTES, Reason, ResultClass};

#[cfg(test)]
pub(super) fn terminal_matches(
    record: &FrozenRecord,
    decision: &Decision,
    owner: &TokenState,
    attempts: &[TokenState],
) -> bool {
    let Ok(Value::Object(mut payload)) = serde_json::from_slice(&record.payload_json) else {
        return false;
    };
    let Some(counter) = owner.intent_counter else {
        return false;
    };
    // Settle adds the journal-owned token before checking these same role fields.
    payload.insert("token".into(), Value::String(owner.intent_id.0.clone()));
    if role_fields(record.role, &payload).is_err()
        || payload.get("intent_counter").and_then(Value::as_u64) != Some(counter)
    {
        return false;
    }
    let linkage_matches = match (payload.get("settled_by"), &decision.settled_by) {
        (None, None) => true,
        (Some(by), Some(token)) if record.role == Role::Outcome => {
            by["token"].as_str() == Some(token.0.as_str())
                && attempts.iter().any(|attempt| {
                    &attempt.intent_id == token
                        && attempt.intent.role == Role::RecoveryIntent
                        && attempt.intent_counter.is_some()
                        && by["intent_counter"].as_u64() == attempt.intent_counter
                })
        }
        _ => false,
    };
    if !linkage_matches {
        return false;
    }
    payload
        .remove("result")
        .and_then(|value| serde_json::from_value::<ResultClass>(value).ok())
        == Some(decision.result)
        && payload
            .remove("reason")
            .and_then(|value| serde_json::from_value::<Reason>(value).ok())
            == Some(decision.reason)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalWire {
    version: u32,
    binding: Option<String>,
    phase: Phase,
    original_revision: Option<String>,
    new_revision: Option<String>,
    pending: Option<PendingWire>,
    fact: Option<FactWire>,
    writer: Option<TokenState>,
    attempts: Vec<TokenState>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingWire {
    action: ActionWire,
    expected: String,
    tried: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ActionWire {
    Forward,
    Restore,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FactWire {
    Untouched,
    Committed(String),
    RolledBack(String),
}

pub(super) fn decode(bytes: &[u8]) -> Result<JournalV2, JournalError> {
    let wire: JournalWire = serde_json::from_slice(bytes).map_err(|_| JournalError::Unreadable)?;
    let mut state = JournalV2 {
        version: wire.version,
        binding: wire
            .binding
            .map(LogId::from_journal)
            .transpose()
            .map_err(|_| JournalError::InvalidState)?,
        phase: wire.phase,
        original_revision: wire
            .original_revision
            .as_deref()
            .map(FileRevision::parse_journal)
            .transpose()?,
        new_revision: wire
            .new_revision
            .as_deref()
            .map(FileRevision::parse_journal)
            .transpose()?,
        pending: None,
        fact: wire
            .fact
            .map(|fact| {
                Ok::<_, JournalError>(match fact {
                    FactWire::Untouched => Fact::Untouched,
                    FactWire::Committed(r) => Fact::Committed(FileRevision::parse_journal(&r)?),
                    FactWire::RolledBack(r) => Fact::RolledBack(FileRevision::parse_journal(&r)?),
                })
            })
            .transpose()?,
        writer: wire.writer,
        attempts: wire.attempts,
    };
    if let Some(pending) = wire.pending {
        let action = match pending.action {
            ActionWire::Forward => Action::Forward,
            ActionWire::Restore => Action::Restore,
        };
        state.pending = Some(Pending {
            action,
            expected: FileRevision::parse_journal(&pending.expected)?,
            pre_action: state.pre_action(action)?.clone(),
            tried: pending.tried,
        });
    }
    state.validate()?;
    Ok(state)
}

#[cfg(test)]
pub(super) fn encode(state: &JournalV2) -> Result<Vec<u8>, JournalError> {
    let wire = JournalWire {
        version: state.version,
        binding: state.binding.as_ref().map(|id| id.as_str().to_owned()),
        phase: state.phase,
        original_revision: state
            .original_revision
            .as_ref()
            .map(|r| r.as_str().to_owned()),
        new_revision: state.new_revision.as_ref().map(|r| r.as_str().to_owned()),
        pending: state.pending.as_ref().map(|p| PendingWire {
            action: match p.action {
                Action::Forward => ActionWire::Forward,
                Action::Restore => ActionWire::Restore,
            },
            expected: p.expected.as_str().to_owned(),
            tried: p.tried,
        }),
        fact: state.fact.as_ref().map(|fact| match fact {
            Fact::Untouched => FactWire::Untouched,
            Fact::Committed(r) => FactWire::Committed(r.as_str().to_owned()),
            Fact::RolledBack(r) => FactWire::RolledBack(r.as_str().to_owned()),
        }),
        writer: state.writer.clone(),
        attempts: state.attempts.clone(),
    };
    // Value's ordered maps preserve the canonical golden wire, including actors.
    let bytes = serde_json::to_value(wire)
        .and_then(|value| serde_json::to_vec(&value))
        .map_err(|_| JournalError::Persist)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::Persist);
    }
    Ok(bytes)
}

pub(super) mod role {
    use std::borrow::Borrow;

    use super::{Deserialize, Role};

    // Serde borrows fields; adapt that callback to the value-based serializer.
    pub(crate) fn serialize_ref<S: serde::Serializer>(
        role: impl Borrow<Role>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        serialize(*role.borrow(), s)
    }

    pub(crate) fn serialize<S: serde::Serializer>(role: Role, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(role.event())
    }

    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Role, D::Error> {
        let event = String::deserialize(d)?;
        Role::from_event(&event).ok_or_else(|| serde::de::Error::custom("unknown journal role"))
    }
}

pub(super) mod attribution {
    use std::borrow::Borrow;

    use super::{Attribution, Deserialize, Serialize, Value};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        actor: Value,
    }

    // Keep Serde's borrowed-field callback separate from the optional value.
    pub(crate) fn serialize_ref<S: serde::Serializer>(
        actor: impl Borrow<Option<Attribution>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        serialize(actor.borrow().as_ref(), s)
    }

    pub(crate) fn serialize<S: serde::Serializer>(
        actor: Option<&Attribution>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        actor.serialize(s)
    }

    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Attribution>, D::Error> {
        Option::<Wire>::deserialize(d)?
            .map(|wire| {
                let bytes = serde_json::to_vec(&wire.actor).map_err(serde::de::Error::custom)?;
                crate::security::audit::AuditWho::from_persisted(&bytes)
                    .map(|actor| Attribution { actor })
                    .map_err(|_| serde::de::Error::custom("invalid journal actor"))
            })
            .transpose()
    }
}
