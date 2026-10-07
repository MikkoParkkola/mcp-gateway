// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A2A -> MCP translation. Pure functions, no I/O.
//!
//! ```text
//! Agent Card           -> one MCP tool (`send_message`); skills are its text
//! Task | Message reply -> MCP CallToolResult (content, structuredContent, isError)
//! ```

use std::fmt::Write as _;

use serde_json::{Map, Value, json};

use super::types::{AgentCard, Message, Part, SendMessageResponse, Task, TaskState};
use crate::protocol::{Tool, ToolAnnotations};

/// The one tool every A2A agent is exposed as. `SendMessage` cannot address a
/// skill, so a tool per skill would be interchangeable aliases.
pub(crate) const TOOL_NAME: &str = "send_message";

/// The agent as one MCP tool, its skills folded into the description so
/// discovery still finds it by what it can do.
pub(crate) fn card_to_tool(card: &AgentCard) -> Tool {
    let mut description = card
        .description
        .clone()
        .unwrap_or_else(|| format!("Delegate a task to the A2A agent {}.", card.name));
    if !card.skills.is_empty() {
        description.push_str("\n\nSkills:");
        // `write!` into a `String` cannot fail.
        for skill in &card.skills {
            let _ = write!(description, "\n- {}", skill.name);
            if let Some(about) = &skill.description {
                let _ = write!(description, ": {about}");
            }
            if !skill.tags.is_empty() {
                let _ = write!(description, " [{}]", skill.tags.join(", "));
            }
            for example in &skill.examples {
                let _ = write!(description, "\n  e.g. {example}");
            }
        }
    }
    Tool {
        name: TOOL_NAME.to_owned(),
        title: Some(card.name.clone()),
        description: Some(description),
        input_schema: json!({
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "What to ask the agent"}
            },
            "required": ["message"],
        }),
        output_schema: None,
        annotations: Some(ToolAnnotations {
            title: Some(card.name.clone()),
            read_only_hint: None,
            destructive_hint: None,
            idempotent_hint: None,
            open_world_hint: Some(true),
        }),
        role: None,
        projection: None,
    }
}

/// A `SendMessage` reply as an MCP `CallToolResult`.
pub(crate) fn reply_to_result(reply: &SendMessageResponse) -> Value {
    match (&reply.task, &reply.message) {
        (Some(task), _) => task_to_result(task),
        (None, Some(message)) => parts_to_result("message", &message.parts),
        (None, None) => error_result("the agent returned neither a task nor a message"),
    }
}

fn task_to_result(task: &Task) -> Value {
    let reason = status_text(task.status.message.as_ref());
    let state = task.status.state;
    match state {
        TaskState::Completed => {
            let parts: Vec<Part> = task
                .artifacts
                .iter()
                .flat_map(|artifact| artifact.parts.iter().cloned())
                .collect();
            parts_to_result(&task.id, &parts)
        }
        TaskState::Failed | TaskState::Rejected | TaskState::Canceled => error_result(&format!(
            "the A2A task ended {}: {reason}",
            state_name(state)
        )),
        TaskState::InputRequired | TaskState::AuthRequired => error_result(&format!(
            "the A2A agent stopped in state {} and asked: {reason}. This gateway cannot relay \
             that question yet; rephrase the request with the missing detail.",
            state_name(state)
        )),
        TaskState::Submitted | TaskState::Working | TaskState::Unspecified => {
            error_result(&format!(
                "the A2A agent returned before finishing (state {})",
                state_name(state)
            ))
        }
    }
}

fn state_name(state: TaskState) -> &'static str {
    match state {
        TaskState::Submitted => "submitted",
        TaskState::Working => "working",
        TaskState::Completed => "completed",
        TaskState::Failed => "failed",
        TaskState::Canceled => "canceled",
        TaskState::InputRequired => "input-required",
        TaskState::Rejected => "rejected",
        TaskState::AuthRequired => "auth-required",
        TaskState::Unspecified => "unspecified",
    }
}

fn status_text(message: Option<&Message>) -> String {
    let text: Vec<&str> = message
        .map(|message| {
            message
                .parts
                .iter()
                .filter_map(|part| part.text.as_deref())
                .collect()
        })
        .unwrap_or_default();
    if text.is_empty() {
        "no details".to_owned()
    } else {
        text.join(" ")
    }
}

fn error_result(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": true})
}

/// Parts as MCP content without loss: inline bytes stay as received.
fn parts_to_result(owner: &str, parts: &[Part]) -> Value {
    let mut content = Vec::with_capacity(parts.len());
    let mut objects = Vec::new();
    let mut data_parts = 0;
    for (index, part) in parts.iter().enumerate() {
        if let Some(text) = &part.text {
            content.push(json!({"type": "text", "text": text}));
        } else if let Some(data) = &part.data {
            data_parts += 1;
            if let Value::Object(object) = data {
                objects.push(object.clone());
            }
            content.push(json!({"type": "text", "text": data.to_string()}));
        } else if let Some(raw) = &part.raw {
            let mut resource = Map::new();
            resource.insert("uri".into(), json!(format!("a2a://{owner}/part/{index}")));
            resource.insert(
                "mimeType".into(),
                json!(
                    part.media_type
                        .as_deref()
                        .unwrap_or("application/octet-stream")
                ),
            );
            resource.insert("blob".into(), json!(raw));
            content.push(json!({"type": "resource", "resource": resource}));
        } else if let Some(url) = &part.url {
            let mut link = Map::new();
            link.insert("type".into(), json!("resource_link"));
            link.insert("uri".into(), json!(url));
            link.insert(
                "name".into(),
                json!(part.filename.as_deref().unwrap_or(url)),
            );
            if let Some(media_type) = &part.media_type {
                link.insert("mimeType".into(), json!(media_type));
            }
            content.push(Value::Object(link));
        }
    }
    if content.is_empty() {
        content.push(json!({"type": "text", "text": "The agent returned no content."}));
    }
    let mut result = json!({"content": content, "isError": false});
    // MCP `structuredContent` is an object: promoted only when the reply's one
    // data part is one.
    if data_parts == 1
        && let [object] = objects.as_slice()
    {
        result["structuredContent"] = Value::Object(object.clone());
    }
    result
}

#[cfg(test)]
#[path = "translator_tests.rs"]
mod tests;
