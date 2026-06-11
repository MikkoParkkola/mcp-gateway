//! Agent dispatch and reply (SLACKCTL.EXEC.5).
//!
//! Authorized instructions are dispatched to the agent runtime and the result
//! is posted back to the originating Slack thread via the existing
//! `slack_post_message` capability.

use serde::{Deserialize, Serialize};

/// Result of an agent dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchResult {
    /// The attribution ID for this dispatch.
    pub attribution_id: String,
    /// Whether the dispatch succeeded.
    pub success: bool,
    /// The agent's response text (or error message).
    pub response: String,
}

/// A pending reply to post to Slack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackReply {
    /// Channel to post to.
    pub channel: String,
    /// Message text.
    pub text: String,
    /// Thread timestamp to reply in-thread.
    pub thread_ts: String,
}

/// Dispatch an instruction to the agent runtime.
///
/// In production this routes through the gateway's MetaMcp/backend system.
/// For the control plane, the dispatch produces a `DispatchResult` that is
/// then formatted as a `SlackReply` for posting via `slack_post_message`.
pub fn format_agent_reply(channel: &str, thread_ts: &str, response: &str) -> SlackReply {
    SlackReply {
        channel: channel.to_string(),
        text: response.to_string(),
        thread_ts: thread_ts.to_string(),
    }
}

/// Format a confirmation request for destructive instructions.
pub fn format_confirmation_request(
    channel: &str,
    thread_ts: &str,
    instruction: &str,
    reason: &str,
) -> SlackReply {
    SlackReply {
        channel: channel.to_string(),
        text: format!(
            "⚠️ **Confirmation required**\n\n\
             Instruction: `{instruction}`\n\
             Reason: {reason}\n\n\
             Reply with `confirm` to proceed or `cancel` to abort."
        ),
        thread_ts: thread_ts.to_string(),
    }
}

/// Format a denial message for unauthorized users.
pub fn format_denial(channel: &str, thread_ts: &str, user_id: &str) -> SlackReply {
    SlackReply {
        channel: channel.to_string(),
        text: format!(
            "🚫 User <@{user_id}> is not authorized to issue commands."
        ),
        thread_ts: thread_ts.to_string(),
    }
}

/// Build the `slack_post_message` capability invocation arguments from a `SlackReply`.
pub fn reply_to_capability_args(reply: &SlackReply) -> serde_json::Value {
    serde_json::json!({
        "channel": reply.channel,
        "text": reply.text,
        "thread_ts": reply.thread_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_reply_has_correct_fields() {
        let reply = format_agent_reply("C123", "1234.5678", "4");
        assert_eq!(reply.channel, "C123");
        assert_eq!(reply.thread_ts, "1234.5678");
        assert_eq!(reply.text, "4");
    }

    #[test]
    fn confirmation_request_mentions_instruction() {
        let reply = format_confirmation_request(
            "C123",
            "1234.5678",
            "delete all issues",
            "matches destructive pattern",
        );
        assert!(reply.text.contains("delete all issues"));
        assert!(reply.text.contains("Confirmation required"));
    }

    #[test]
    fn denial_mentions_user() {
        let reply = format_denial("C123", "1234.5678", "UEVIL");
        assert!(reply.text.contains("UEVIL"));
        assert!(reply.text.contains("not authorized"));
    }

    #[test]
    fn capability_args_contain_required_fields() {
        let reply = format_agent_reply("C123", "1234.5678", "hello");
        let args = reply_to_capability_args(&reply);
        assert_eq!(args["channel"], "C123");
        assert_eq!(args["text"], "hello");
        assert_eq!(args["thread_ts"], "1234.5678");
    }
}
