//! Slack Socket Mode listener (SLACKCTL.LISTEN.2).
//!
//! A persistent listener subscribes to `message` and `app_mention` events via
//! Socket Mode, filters to an allowlisted channel set, and survives restart
//! (launchd KeepAlive verified via service plist).
//!
//! # Socket Mode protocol
//!
//! 1. POST to `https://slack.com/api/apps.connections.open` with the app-level
//!    token to receive a WebSocket URL.
//! 2. Connect to the WSS endpoint.
//! 3. Receive envelope messages with `type: "events_api"`.
//! 4. Acknowledge each envelope via `envelope_id`.
//! 5. Process the inner event payload.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Slack Socket Mode envelope received from the WSS connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackEnvelope {
    /// Unique envelope ID for acknowledgement.
    pub envelope_id: String,
    /// Envelope type (e.g. "events_api", "hello", "disconnect").
    #[serde(rename = "type")]
    pub envelope_type: String,
    /// The inner event payload (present for events_api envelopes).
    #[serde(default)]
    pub payload: Option<SlackEventPayload>,
}

/// Inner event payload within a Socket Mode envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackEventPayload {
    /// Event type (e.g. "message", "app_mention").
    #[serde(default)]
    pub event: Option<SlackEvent>,
}

/// A Slack event (message or app_mention).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackEvent {
    /// Event type.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The user who sent the message.
    #[serde(default)]
    pub user: Option<String>,
    /// The channel where the message was sent.
    #[serde(default)]
    pub channel: Option<String>,
    /// The message text.
    #[serde(default)]
    pub text: Option<String>,
    /// The message timestamp.
    #[serde(default)]
    pub ts: Option<String>,
    /// The thread timestamp (if this is a threaded message).
    #[serde(default)]
    pub thread_ts: Option<String>,
}

/// Envelope acknowledgement message sent back to Slack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeAck {
    /// The envelope_id being acknowledged.
    pub envelope_id: String,
}

/// Parsed and validated Slack event ready for processing.
#[derive(Debug, Clone)]
pub struct ProcessedEvent {
    /// Slack user ID of the message sender.
    pub user_id: String,
    /// Channel ID.
    pub channel: String,
    /// Message timestamp.
    pub ts: String,
    /// Thread timestamp (for replies).
    pub thread_ts: String,
    /// Message text (instruction).
    pub text: String,
}

/// Filter events to an allowlisted channel set.
///
/// Returns `None` if the event should be ignored (not from an allowed channel,
/// missing required fields, or from a bot).
pub fn filter_event(event: &SlackEvent, allowed_channels: &HashSet<String>) -> Option<ProcessedEvent> {
    let channel = event.channel.as_deref()?;
    let user_id = event.user.as_deref()?;
    let text = event.text.as_deref()?;
    let ts = event.ts.as_deref()?;

    // Filter to allowed channels
    if !allowed_channels.is_empty() && !allowed_channels.contains(channel) {
        tracing::debug!(
            channel = channel,
            "Ignoring event from non-allowlisted channel"
        );
        return None;
    }

    // Ignore bot messages (bots have user IDs starting with "B")
    if user_id.starts_with('B') {
        tracing::debug!(user_id = user_id, "Ignoring bot message");
        return None;
    }

    // Determine thread_ts: use thread_ts if present, otherwise use ts
    let thread_ts = event
        .thread_ts
        .as_deref()
        .unwrap_or(ts);

    Some(ProcessedEvent {
        user_id: user_id.to_string(),
        channel: channel.to_string(),
        ts: ts.to_string(),
        thread_ts: thread_ts.to_string(),
        text: text.to_string(),
    })
}

/// Build an envelope acknowledgement JSON message.
pub fn build_ack(envelope_id: &str) -> serde_json::Value {
    serde_json::json!({
        "envelope_id": envelope_id
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed_channels() -> HashSet<String> {
        let mut set = HashSet::new();
        set.insert("C0B54FR20SU".to_string());
        set
    }

    #[test]
    fn event_from_allowed_channel_is_processed() {
        let event = SlackEvent {
            event_type: "message".to_string(),
            user: Some("U12345".to_string()),
            channel: Some("C0B54FR20SU".to_string()),
            text: Some("what is 2+2".to_string()),
            ts: Some("1234567890.123456".to_string()),
            thread_ts: None,
        };
        let result = filter_event(&event, &allowed_channels());
        assert!(result.is_some());
        let processed = result.unwrap();
        assert_eq!(processed.user_id, "U12345");
        assert_eq!(processed.text, "what is 2+2");
        // thread_ts falls back to ts when not present
        assert_eq!(processed.thread_ts, "1234567890.123456");
    }

    #[test]
    fn event_from_non_allowed_channel_is_ignored() {
        let event = SlackEvent {
            event_type: "message".to_string(),
            user: Some("U12345".to_string()),
            channel: Some("CEVIL_CHANNEL".to_string()),
            text: Some("do something".to_string()),
            ts: Some("1234567890.123456".to_string()),
            thread_ts: None,
        };
        let result = filter_event(&event, &allowed_channels());
        assert!(result.is_none());
    }

    #[test]
    fn bot_messages_are_ignored() {
        let event = SlackEvent {
            event_type: "message".to_string(),
            user: Some("BOTUSER123".to_string()),
            channel: Some("C0B54FR20SU".to_string()),
            text: Some("bot message".to_string()),
            ts: Some("1234567890.123456".to_string()),
            thread_ts: None,
        };
        let result = filter_event(&event, &allowed_channels());
        assert!(result.is_none());
    }

    #[test]
    fn threaded_event_preserve_thread_ts() {
        let event = SlackEvent {
            event_type: "message".to_string(),
            user: Some("U12345".to_string()),
            channel: Some("C0B54FR20SU".to_string()),
            text: Some("follow-up".to_string()),
            ts: Some("1234567890.222222".to_string()),
            thread_ts: Some("1234567890.111111".to_string()),
        };
        let result = filter_event(&event, &allowed_channels());
        let processed = result.unwrap();
        assert_eq!(processed.thread_ts, "1234567890.111111");
    }

    #[test]
    fn empty_channel_is_ignored() {
        let event = SlackEvent {
            event_type: "message".to_string(),
            user: Some("U12345".to_string()),
            channel: None,
            text: Some("no channel".to_string()),
            ts: Some("1234567890.123456".to_string()),
            thread_ts: None,
        };
        let result = filter_event(&event, &allowed_channels());
        assert!(result.is_none());
    }

    #[test]
    fn ack_contains_envelope_id() {
        let ack = build_ack("abc123");
        assert_eq!(ack["envelope_id"], "abc123");
    }

    #[test]
    fn empty_allowlist_accepts_all_channels() {
        let event = SlackEvent {
            event_type: "message".to_string(),
            user: Some("U12345".to_string()),
            channel: Some("C_ANYTHING".to_string()),
            text: Some("hello".to_string()),
            ts: Some("1234567890.123456".to_string()),
            thread_ts: None,
        };
        let result = filter_event(&event, &HashSet::new());
        assert!(result.is_some());
    }
}
