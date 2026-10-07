// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A2A 1.0 wire types, JSON-RPC binding (specification tag v1.0.1).
//!
//! Only what the outbound bridge reads or writes. Unknown fields are ignored on
//! the way in, so an agent that adds fields stays readable.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The protocol version this bridge speaks, sent as the `A2A-Version` header.
pub(crate) const PROTOCOL_VERSION: &str = "1.0";
/// The A2A 1.0 well-known Agent Card path.
pub(crate) const DEFAULT_CARD_PATH: &str = "/.well-known/agent-card.json";

/// The Agent Card: who the agent is and where it answers.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentCard {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub supported_interfaces: Vec<AgentInterface>,
    #[serde(default)]
    pub skills: Vec<Skill>,
}

/// One `(url, binding, version)` the agent answers on.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentInterface {
    pub url: String,
    pub protocol_binding: String,
    pub protocol_version: String,
    #[serde(default)]
    pub tenant: Option<String>,
}

impl AgentInterface {
    /// Whether this bridge can speak this interface: JSON-RPC, major version 1.
    pub(crate) fn is_jsonrpc_v1(&self) -> bool {
        self.protocol_binding.eq_ignore_ascii_case("JSONRPC")
            && self.protocol_version.split('.').next() == Some("1")
    }
}

/// A capability the agent advertises. Discovery text only: `SendMessage`
/// cannot address a skill.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Skill {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub examples: Vec<String>,
}

/// A content part: exactly one of `text`, `raw`, `url`, `data`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Part {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Base64 bytes, kept as received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `Some(Value::Null)` for a present `"data": null`, which is a valid
    /// answer; `None` only when the field is absent.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

/// A present field, `null` included, as `Some`. With `default`, an absent
/// field stays `None`.
fn present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

impl Part {
    pub(crate) fn text(text: &str) -> Self {
        Self {
            text: Some(text.to_owned()),
            ..Self::default()
        }
    }
}

/// A message, either the one this bridge sends or an agent's reply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Message {
    #[serde(rename = "messageId")]
    pub id: String,
    pub role: String,
    pub parts: Vec<Part>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

impl Message {
    /// A user message with one text part and a fresh `messageId`.
    pub(crate) fn user_text(text: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            role: "ROLE_USER".to_owned(),
            parts: vec![Part::text(text)],
            context_id: None,
            task_id: None,
        }
    }
}

/// Task lifecycle state. Anything this build does not know reads as
/// `Unspecified`, never as success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum TaskState {
    #[serde(rename = "TASK_STATE_SUBMITTED")]
    Submitted,
    #[serde(rename = "TASK_STATE_WORKING")]
    Working,
    #[serde(rename = "TASK_STATE_COMPLETED")]
    Completed,
    #[serde(rename = "TASK_STATE_FAILED")]
    Failed,
    #[serde(rename = "TASK_STATE_CANCELED")]
    Canceled,
    #[serde(rename = "TASK_STATE_INPUT_REQUIRED")]
    InputRequired,
    #[serde(rename = "TASK_STATE_REJECTED")]
    Rejected,
    #[serde(rename = "TASK_STATE_AUTH_REQUIRED")]
    AuthRequired,
    #[serde(other)]
    Unspecified,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TaskStatus {
    pub state: TaskState,
    #[serde(default)]
    pub message: Option<Message>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Artifact {
    #[serde(default)]
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Task {
    pub id: String,
    pub status: TaskStatus,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
}

/// The `SendMessage` result: exactly one of a task and a message.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendMessageResponse {
    #[serde(default)]
    pub task: Option<Task>,
    #[serde(default)]
    pub message: Option<Message>,
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
