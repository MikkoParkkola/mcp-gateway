//! MCP ↔ A2A translation layer.
//!
//! This module is the semantic bridge between the two protocols.  All
//! conversions are pure functions with no I/O, making them trivially
//! testable and free of side effects.
//!
//! # Mapping summary
//!
//! ```text
//! A2A Skill   → MCP Tool         (via skill_to_tool)
//! MCP args    → A2A message text  (via tool_args_to_message)
//! A2A Task    → MCP tool result   (via task_to_mcp_result)
//! ```

use serde_json::{Value, json};

use crate::protocol::{Tool, ToolAnnotations};
use crate::{Error, Result};

use super::types::{A2aTask, Artifact, Part, Skill, TaskState};

// ── Schema constant ───────────────────────────────────────────────────────────

/// Standard input schema for all synthesized A2A tools.
///
/// A2A agents accept opaque natural-language messages, not structured
/// arguments.  The `context_id` enables multi-turn conversations.
fn a2a_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "message": {
                "type": "string",
                "description": "Message to send to the agent"
            },
            "context_id": {
                "type": "string",
                "description": "Optional context ID for multi-turn conversations"
            }
        },
        "required": ["message"]
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Convert an A2A [`Skill`] into an MCP [`Tool`].
///
/// The `namespace` prefix is prepended to the skill ID so that tools from
/// different A2A backends remain unique when surfaced via the gateway's
/// Meta-MCP aggregation.
///
/// # Example
///
/// ```rust
/// use mcp_gateway::a2a::types::Skill;
/// use mcp_gateway::a2a::translator::skill_to_tool;
///
/// let skill = Skill {
///     id: "web_search".to_string(),
///     name: "Web Search".to_string(),
///     description: Some("Search the web".to_string()),
///     tags: vec!["search".to_string()],
///     input_modes: vec![],
///     output_modes: vec![],
///     examples: vec![],
/// };
/// let tool = skill_to_tool(&skill, "travel-agent");
/// assert_eq!(tool.name, "travel-agent__web_search");
/// ```
#[must_use]
pub fn skill_to_tool(skill: &Skill, namespace: &str) -> Tool {
    let name = format!("{namespace}__{}", skill.id);

    let annotations = build_annotations(skill);

    Tool {
        name,
        title: Some(skill.name.clone()),
        description: skill.description.clone(),
        input_schema: a2a_input_schema(),
        output_schema: None,
        annotations: Some(annotations),
    }
}

/// Convert an entire Agent Card's skill list to MCP tools.
///
/// Namespaces each tool as `{namespace}__{skill_id}`.
///
/// # Example
///
/// ```rust
/// use mcp_gateway::a2a::types::{AgentCard, Skill};
/// use mcp_gateway::a2a::translator::agent_card_to_mcp_tools;
///
/// let card = AgentCard {
///     name: "MyAgent".to_string(),
///     description: None,
///     url: "https://agent.example.com".to_string(),
///     capabilities: None,
///     security_schemes: Default::default(),
///     skills: vec![
///         Skill { id: "s1".to_string(), name: "Skill One".to_string(),
///                 description: None, tags: vec![], input_modes: vec![],
///                 output_modes: vec![], examples: vec![] },
///     ],
/// };
/// let tools = agent_card_to_mcp_tools(&card, "my-backend");
/// assert_eq!(tools.len(), 1);
/// assert_eq!(tools[0].name, "my-backend__s1");
/// ```
#[must_use]
pub fn agent_card_to_mcp_tools(card: &super::types::AgentCard, namespace: &str) -> Vec<Tool> {
    card.skills
        .iter()
        .map(|s| skill_to_tool(s, namespace))
        .collect()
}

/// Extract the `"message"` field from MCP tool call arguments.
///
/// A2A tools synthesized by the gateway always have a single required
/// `message` argument (natural-language text) plus an optional `context_id`.
///
/// # Errors
///
/// Returns [`Error::Protocol`] if `args["message"]` is absent or not a string.
pub fn tool_args_to_message(args: &Value) -> Result<(&str, Option<&str>)> {
    let message = args.get("message").and_then(Value::as_str).ok_or_else(|| {
        Error::Protocol("A2A tool invocation requires a 'message' string argument".to_string())
    })?;

    let context_id = args.get("context_id").and_then(Value::as_str);

    Ok((message, context_id))
}

/// Convert a completed (or failed) A2A task into an MCP tool-call result `Value`.
///
/// Mapping:
/// - `Completed` → extracts all artifact text parts; data/file parts are JSON-serialized
/// - `Failed` → returns `Err(Error::Protocol(...))`
/// - `InputRequired` → returns a structured prompt so the caller can continue the conversation
/// - Other terminal states (`Canceled`) → `Err`
/// - Non-terminal (`Submitted`, `Working`) → `Err` (caller should not call this on in-progress tasks)
///
/// # Errors
///
/// Returns [`Error::Protocol`] for failed, canceled, or non-terminal tasks.
pub fn task_to_mcp_result(task: &A2aTask) -> Result<Value> {
    match task.status.state {
        TaskState::Completed => Ok(artifacts_to_value(&task.artifacts)),
        TaskState::Failed => Err(Error::Protocol(format!(
            "A2A task '{}' failed: {}",
            task.id,
            task.status
                .message
                .as_ref()
                .and_then(|m| m.parts.first())
                .and_then(|p| match p {
                    Part::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .unwrap_or("no details")
        ))),
        TaskState::Canceled => Err(Error::Protocol(format!(
            "A2A task '{}' was canceled",
            task.id
        ))),
        TaskState::InputRequired => Ok(build_input_required_response(task)),
        TaskState::Submitted | TaskState::Working => Err(Error::Protocol(format!(
            "A2A task '{}' is still in progress (state: {:?})",
            task.id, task.status.state
        ))),
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Build `ToolAnnotations` from skill metadata (tags, examples).
fn build_annotations(skill: &Skill) -> ToolAnnotations {
    // Store tags + examples as custom metadata via the open_world_hint field.
    // The annotations type has limited fields; we use read_only_hint to mark
    // A2A agent tools as likely non-destructive by default.
    ToolAnnotations {
        title: Some(skill.name.clone()),
        read_only_hint: None,
        destructive_hint: None,
        idempotent_hint: None,
        open_world_hint: Some(true), // A2A agents interact with external entities
    }
}

/// Convert a list of artifacts into a `Value` appropriate for MCP tool results.
fn artifacts_to_value(artifacts: &[Artifact]) -> Value {
    if artifacts.is_empty() {
        return Value::Null;
    }

    let parts: Vec<Value> = artifacts
        .iter()
        .flat_map(|a| a.parts.iter().map(part_to_value))
        .collect();

    match parts.len() {
        0 => Value::Null,
        1 => parts.into_iter().next().unwrap_or(Value::Null),
        _ => Value::Array(parts),
    }
}

/// Convert a single A2A [`Part`] to a JSON `Value` for MCP content.
fn part_to_value(part: &Part) -> Value {
    match part {
        Part::Text { text, .. } => {
            // Attempt to parse as JSON first; fall back to plain string.
            serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.clone()))
        }
        Part::File { file } => {
            json!({
                "type": "file",
                "uri": file.uri,
                "name": file.name,
                "mimeType": file.mime_type,
            })
        }
        Part::Data { data, .. } => data.clone(),
    }
}

/// Build the structured response for `input-required` task state.
fn build_input_required_response(task: &A2aTask) -> Value {
    let prompt = task
        .status
        .message
        .as_ref()
        .and_then(|m| m.parts.first())
        .and_then(|p| match p {
            Part::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .unwrap_or("Agent requires additional input to proceed.");

    json!({
        "state": "input-required",
        "prompt": prompt,
        "context_id": task.context_id,
        "task_id": task.id,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;
    use crate::a2a::types::{
        A2aMessage, A2aTask, Artifact, MessageRole, Part, Skill, TaskState, TaskStatus,
    };

    fn make_skill(id: &str) -> Skill {
        Skill {
            id: id.to_string(),
            name: format!("{id} Name"),
            description: Some(format!("Does {id}")),
            tags: vec!["tag1".to_string()],
            input_modes: vec!["text/plain".to_string()],
            output_modes: vec!["application/json".to_string()],
            examples: vec!["example".to_string()],
        }
    }

    fn make_task(state: TaskState, artifacts: Vec<Artifact>) -> A2aTask {
        A2aTask {
            id: "task-42".to_string(),
            context_id: Some("ctx-1".to_string()),
            status: TaskStatus {
                state,
                message: None,
                timestamp: None,
            },
            artifacts,
            metadata: None,
        }
    }

    // ── skill_to_tool ────────────────────────────────────────────────────────

    #[test]
    fn skill_to_tool_namespaces_correctly() {
        // GIVEN: skill with id "search"
        // WHEN: converting with namespace "backend"
        // THEN: tool name is "backend__search"
        let skill = make_skill("search");
        let tool = skill_to_tool(&skill, "backend");
        assert_eq!(tool.name, "backend__search");
    }

    #[test]
    fn skill_to_tool_sets_title_and_description() {
        // GIVEN: skill with name and description
        // WHEN: converting
        // THEN: tool title and description match
        let skill = make_skill("query");
        let tool = skill_to_tool(&skill, "ns");
        assert_eq!(tool.title.as_deref(), Some("query Name"));
        assert_eq!(tool.description.as_deref(), Some("Does query"));
    }

    #[test]
    fn skill_to_tool_produces_valid_input_schema() {
        // GIVEN: any skill
        // WHEN: converting
        // THEN: schema has required "message" field
        let tool = skill_to_tool(&make_skill("x"), "ns");
        let required = &tool.input_schema["required"];
        assert_eq!(required[0], "message");
        assert!(tool.input_schema["properties"]["message"].is_object());
    }

    #[test]
    fn skill_to_tool_sets_open_world_hint() {
        // GIVEN: any skill
        // WHEN: converting
        // THEN: open_world_hint is Some(true)
        let tool = skill_to_tool(&make_skill("x"), "ns");
        assert_eq!(tool.annotations.unwrap().open_world_hint, Some(true));
    }

    // ── agent_card_to_mcp_tools ───────────────────────────────────────────────

    #[test]
    fn agent_card_to_mcp_tools_maps_all_skills() {
        // GIVEN: card with 3 skills
        use crate::a2a::types::AgentCard;
        let card = AgentCard {
            name: "Bot".to_string(),
            description: None,
            url: "https://bot.example.com".to_string(),
            capabilities: None,
            security_schemes: HashMap::new(),
            skills: vec![make_skill("a"), make_skill("b"), make_skill("c")],
        };
        // WHEN: converting
        // THEN: 3 tools are produced with correct names
        let tools = agent_card_to_mcp_tools(&card, "my-bot");
        assert_eq!(tools.len(), 3);
        assert_eq!(tools[0].name, "my-bot__a");
        assert_eq!(tools[2].name, "my-bot__c");
    }

    #[test]
    fn agent_card_to_mcp_tools_returns_empty_for_no_skills() {
        use crate::a2a::types::AgentCard;
        let card = AgentCard {
            name: "Empty".to_string(),
            description: None,
            url: "https://empty.example.com".to_string(),
            capabilities: None,
            security_schemes: HashMap::new(),
            skills: vec![],
        };
        assert!(agent_card_to_mcp_tools(&card, "empty").is_empty());
    }

    // ── tool_args_to_message ─────────────────────────────────────────────────

    #[test]
    fn tool_args_to_message_extracts_message_and_context_id() {
        // GIVEN: args with both message and context_id
        let args = json!({"message": "hello", "context_id": "ctx-99"});
        // WHEN: extracting
        // THEN: both fields returned
        let (msg, ctx) = tool_args_to_message(&args).unwrap();
        assert_eq!(msg, "hello");
        assert_eq!(ctx, Some("ctx-99"));
    }

    #[test]
    fn tool_args_to_message_extracts_message_without_context_id() {
        // GIVEN: args with only message
        let args = json!({"message": "hello"});
        // WHEN: extracting
        // THEN: context_id is None
        let (msg, ctx) = tool_args_to_message(&args).unwrap();
        assert_eq!(msg, "hello");
        assert!(ctx.is_none());
    }

    #[test]
    fn tool_args_to_message_errors_when_message_absent() {
        // GIVEN: args without message
        let args = json!({"something_else": "value"});
        // WHEN: extracting
        // THEN: Err
        let err = tool_args_to_message(&args).unwrap_err();
        assert!(matches!(err, Error::Protocol(ref msg) if msg.contains("'message'")));
    }

    #[test]
    fn tool_args_to_message_errors_when_message_not_string() {
        // GIVEN: args where message is a number
        let args = json!({"message": 42});
        // WHEN: extracting
        // THEN: Err
        assert!(tool_args_to_message(&args).is_err());
    }

    // ── task_to_mcp_result ───────────────────────────────────────────────────

    #[test]
    fn task_to_mcp_result_completed_text_artifact_returns_string() {
        // GIVEN: completed task with text artifact
        let task = make_task(
            TaskState::Completed,
            vec![Artifact {
                artifact_id: None,
                name: None,
                description: None,
                parts: vec![Part::Text {
                    text: "Paris is beautiful".to_string(),
                    mime_type: None,
                }],
                last_chunk: None,
                metadata: None,
            }],
        );
        // WHEN: converting
        // THEN: returns string value
        let val = task_to_mcp_result(&task).unwrap();
        assert_eq!(val, Value::String("Paris is beautiful".to_string()));
    }

    #[test]
    fn task_to_mcp_result_completed_json_text_artifact_is_parsed() {
        // GIVEN: completed task with JSON text artifact
        let task = make_task(
            TaskState::Completed,
            vec![Artifact {
                artifact_id: None,
                name: None,
                description: None,
                parts: vec![Part::Text {
                    text: r#"{"flights": 3}"#.to_string(),
                    mime_type: None,
                }],
                last_chunk: None,
                metadata: None,
            }],
        );
        // WHEN: converting
        // THEN: returns parsed JSON
        let val = task_to_mcp_result(&task).unwrap();
        assert_eq!(val["flights"], 3);
    }

    #[test]
    fn task_to_mcp_result_completed_no_artifacts_returns_null() {
        // GIVEN: completed task with no artifacts
        let task = make_task(TaskState::Completed, vec![]);
        // WHEN: converting
        // THEN: null
        let val = task_to_mcp_result(&task).unwrap();
        assert_eq!(val, Value::Null);
    }

    #[test]
    fn task_to_mcp_result_failed_returns_err() {
        // GIVEN: failed task
        let task = make_task(TaskState::Failed, vec![]);
        // WHEN: converting
        // THEN: Err
        assert!(task_to_mcp_result(&task).is_err());
    }

    #[test]
    fn task_to_mcp_result_canceled_returns_err() {
        // GIVEN: canceled task
        let task = make_task(TaskState::Canceled, vec![]);
        // WHEN: converting
        // THEN: Err
        assert!(task_to_mcp_result(&task).is_err());
    }

    #[test]
    fn task_to_mcp_result_input_required_returns_structured_prompt() {
        // GIVEN: input-required task with message
        let mut task = make_task(TaskState::InputRequired, vec![]);
        task.status.message = Some(A2aMessage {
            role: MessageRole::Agent,
            parts: vec![Part::Text {
                text: "Which city?".to_string(),
                mime_type: None,
            }],
            context_id: None,
            metadata: None,
        });
        // WHEN: converting
        // THEN: structured object with state, prompt, context_id, task_id
        let val = task_to_mcp_result(&task).unwrap();
        assert_eq!(val["state"], "input-required");
        assert_eq!(val["prompt"], "Which city?");
        assert_eq!(val["context_id"], "ctx-1");
        assert_eq!(val["task_id"], "task-42");
    }

    #[test]
    fn task_to_mcp_result_working_returns_err() {
        // GIVEN: still-working task
        let task = make_task(TaskState::Working, vec![]);
        // WHEN: converting
        // THEN: Err (non-terminal state not expected here)
        assert!(task_to_mcp_result(&task).is_err());
    }

    #[test]
    fn task_to_mcp_result_data_part_returned_directly() {
        // GIVEN: completed task with data artifact
        let task = make_task(
            TaskState::Completed,
            vec![Artifact {
                artifact_id: None,
                name: None,
                description: None,
                parts: vec![Part::Data {
                    data: json!({"price": 199}),
                    mime_type: None,
                }],
                last_chunk: None,
                metadata: None,
            }],
        );
        // WHEN: converting
        // THEN: data value returned directly
        let val = task_to_mcp_result(&task).unwrap();
        assert_eq!(val["price"], 199);
    }

    #[test]
    fn task_to_mcp_result_multiple_parts_returns_array() {
        // GIVEN: completed task with two artifact parts
        let task = make_task(
            TaskState::Completed,
            vec![Artifact {
                artifact_id: None,
                name: None,
                description: None,
                parts: vec![
                    Part::Text {
                        text: "Part one".to_string(),
                        mime_type: None,
                    },
                    Part::Text {
                        text: "Part two".to_string(),
                        mime_type: None,
                    },
                ],
                last_chunk: None,
                metadata: None,
            }],
        );
        // WHEN: converting
        // THEN: array
        let val = task_to_mcp_result(&task).unwrap();
        assert!(val.is_array());
        assert_eq!(val.as_array().unwrap().len(), 2);
    }
}
