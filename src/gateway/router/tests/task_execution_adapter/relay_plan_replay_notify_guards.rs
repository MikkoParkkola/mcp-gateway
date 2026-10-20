// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8408 stage 4: G27, a replay's receipts commit only with a
//! delivered notify frame. Split from `relay_plan_replay_content_guards`
//! for the file-size ceiling. The rig is `relay_plan_replay`'s.
use super::super::*;
use super::relay_plan_replay::{
    ALPHA, OTHER_PROSE, PROSE, Rig, Sensitivity, answering, chain, rig_with_mocks, task_call, text,
};
use super::relay_plan_replay_guards::delist;
use super::support::*;
use pretty_assertions::assert_eq;

/// An open listen stream's frames, read one SSE block at a time
/// (`notifications_helpers` is private to `notifications`, so the
/// minimal reader is local; the request is support's own).
struct Frames {
    body: axum::body::BodyDataStream,
    buffer: Vec<u8>,
    ended: bool,
}

impl Frames {
    fn take_frame(&mut self) -> Option<Value> {
        loop {
            let end = self.buffer.windows(2).position(|pair| pair == b"\n\n")?;
            let block: Vec<u8> = self.buffer.drain(..end + 2).collect();
            let text = String::from_utf8(block).expect("a subscription frame is UTF-8: fixture");
            let data: Vec<&str> = text
                .lines()
                .filter_map(|l| l.strip_prefix("data: "))
                .collect();
            if data.is_empty() {
                continue;
            }
            let payload = data.join("\n");
            return Some(
                serde_json::from_str(&payload).expect("a subscription frame is JSON: fixture"),
            );
        }
    }

    async fn next_frame(&mut self, what: &str) -> Value {
        use futures::StreamExt as _;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(frame) = self.take_frame() {
                return frame;
            }
            assert!(!self.ended, "the listen stream ended before {what} arrived");
            match tokio::time::timeout_at(deadline, self.body.next()).await {
                Err(elapsed) => panic!("{what} never arrived on the listen stream: {elapsed}"),
                Ok(None) => self.ended = true,
                Ok(Some(Ok(chunk))) => self.buffer.extend_from_slice(&chunk),
                Ok(Some(Err(error))) => panic!("the listen body failed mid-stream: {error}"),
            }
        }
    }

    /// Frames until one reports `task` completed; that frame.
    async fn completed_frame(&mut self, task: &str) -> Value {
        for _ in 0..8 {
            let frame = self.next_frame("the completed task frame").await;
            if frame["params"]["taskId"] == task && frame["params"]["status"] == "completed" {
                return frame;
            }
        }
        panic!("no completed frame for {task} arrived on the listen stream");
    }
}

/// Open alice's listen stream over `task`, consuming its acknowledgement.
async fn open_listen(state: &Arc<AppState>, id: i64, task: &str) -> Frames {
    let body = task_method(id, "subscriptions/listen", json!({"taskIds": [task]}));
    let response = create_router(Arc::clone(state))
        .oneshot(http_request(Some("key-a"), &body))
        .await
        .expect("the router must answer: fixture");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "premise: the listen is admitted"
    );
    let mut frames = Frames {
        body: response.into_body().into_data_stream(),
        buffer: Vec::new(),
        ended: false,
    };
    let ack = frames.next_frame("the listen acknowledgement").await;
    assert_eq!(
        ack["method"], "notifications/subscriptions/acknowledged",
        "premise ack: {ack}"
    );
    frames
}

/// A chain task held at step B, its listen stream open, then released
/// and settled: the shared setup of G27a/G27b. The frame is left
/// unread, so it is built and committed only when the row pulls it.
async fn settled_with_listener(key: &str) -> (Rig, String, Frames) {
    let (beta, mut gate) = MockBackend::holding(Answer::Sequence(vec![text(OTHER_PROSE)]));
    let rig = rig_with_mocks(answering(PROSE), beta, None, Sensitivity::Rule).await;
    let created = post(
        &rig.state,
        "key-a",
        task_call(1, key, "gateway_execute", &chain()),
    )
    .await;
    let task = task_id(&created);
    gate.wait_for_dispatch().await;
    let frames = open_listen(&rig.state, 7001, &task).await;
    gate.release_all();
    let settled = poll_until_terminal(&rig.state, "key-a", &task).await;
    assert_eq!(status_of(&settled), "completed", "premise: {settled}");
    (rig, task, frames)
}

/// G27a (T): a notify subscriber's frame of the completed plan task
/// stages and commits the replayed receipts: past the lapse, bob is
/// refused only after the frame is delivered.
/// Mutant: commit on a withheld frame (its inverse, never committing
/// on a delivered frame, leaves bob unrefused here).
#[tokio::test]
async fn g27a_a_delivered_notify_frame_commits_the_replayed_receipts() {
    let (rig, task, mut frames) = settled_with_listener("g27a").await;
    rig.lapse().await;
    assert!(
        !rig.refused("key-b", 270, PROSE).await,
        "P1: lapsed before the frame"
    );
    let frame = frames.completed_frame(&task).await;
    assert!(
        frame.to_string().contains(PROSE),
        "premise: the frame carries the full task: {frame}"
    );
    assert!(
        rig.refused("key-b", 271, PROSE).await,
        "the delivered frame committed no receipt (step A)"
    );
    assert!(
        rig.refused("key-b", 272, OTHER_PROSE).await,
        "the delivered frame committed no receipt (step B)"
    );
}

/// G27b (T): a frame the stored-read gate withholds (alpha delisted
/// after settlement, so the frame goes out minimal) commits none.
/// Mutant: commit on a withheld frame.
#[tokio::test]
async fn g27b_a_withheld_notify_frame_commits_nothing() {
    let (rig, task, mut frames) = settled_with_listener("g27b").await;
    rig.lapse().await;
    assert!(
        !rig.refused("key-b", 280, PROSE).await,
        "P1: lapsed before the frame"
    );
    delist(&rig.state, ALPHA);
    let frame = frames.completed_frame(&task).await;
    assert!(
        !frame.to_string().contains(PROSE),
        "premise: the withheld frame carries no output: {frame}"
    );
    assert!(
        !rig.refused("key-b", 281, PROSE).await,
        "the withheld frame committed a receipt"
    );
}
