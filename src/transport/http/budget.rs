// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A byte budget for every body a transport reads, for the start-once preview.
//!
//! Counted while reading, before anything is parsed, so an over-budget peer
//! is refused without its whole body ever held in memory. Only the start-once
//! preview attaches one; a transport without a budget reads as before.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};

use crate::security::http_diagnostics::safe_request_error;
use crate::{Error, Result};

/// One response's limit, and the limit on everything this transport reads.
#[derive(Debug)]
pub(crate) struct ByteBudget {
    per_response: usize,
    total: usize,
    used: AtomicUsize,
    /// The first refusal, kept: once over budget anywhere, every later read
    /// under this budget fails with it, so a peer cannot follow an oversized
    /// stream event with a small body answer and have the preview succeed.
    refused: std::sync::OnceLock<String>,
}

impl ByteBudget {
    // The preview is its only caller outside tests.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) const fn new(per_response: usize, total: usize) -> Self {
        Self {
            per_response,
            total,
            used: AtomicUsize::new(0),
            refused: std::sync::OnceLock::new(),
        }
    }

    /// Keep `message` as this budget's refusal (the first one wins) and
    /// return the refusal in force.
    fn refuse(&self, message: String) -> Error {
        Error::Transport(self.refused.get_or_init(|| message).clone())
    }

    /// The refusal already in force, if any.
    fn check(&self) -> Result<()> {
        match self.refused.get() {
            Some(message) => Err(Error::Transport(message.clone())),
            None => Ok(()),
        }
    }

    /// Count `len` more bytes of one response that has read `seen` so far.
    fn charge(&self, seen: &mut usize, len: usize) -> Result<()> {
        self.check()?;
        *seen = seen.saturating_add(len);
        if *seen > self.per_response {
            return Err(self.response_refusal());
        }
        self.charge_total(len)
    }

    /// The refusal of one response (or one stream event) past
    /// [`Self::per_response`], in the words [`is_budget_refusal`] knows.
    pub(crate) fn response_refusal(&self) -> Error {
        self.refuse(format!(
            "the response is over the preview's {} budget",
            mib(self.per_response)
        ))
    }

    /// The most one response (or one event on a retained stream) may carry.
    pub(crate) const fn per_response(&self) -> usize {
        self.per_response
    }

    /// Count `len` more bytes against the whole preview only: a retained
    /// session stream is no single response, so its events are bounded one
    /// by one by the decoder at [`Self::per_response`] instead.
    pub(crate) fn charge_total(&self, len: usize) -> Result<()> {
        self.check()?;
        let used = self
            .used
            .fetch_add(len, Ordering::Relaxed)
            .saturating_add(len);
        if used > self.total {
            return Err(self.refuse(format!(
                "the preview is over its {} budget",
                mib(self.total)
            )));
        }
        Ok(())
    }

    /// `stream`, counted chunk by chunk; the first chunk past a budget ends
    /// it with the error naming that budget.
    pub(crate) fn metered<S>(self: &Arc<Self>, stream: S) -> impl Stream<Item = Result<Bytes>>
    where
        S: Stream<Item = Result<Bytes>>,
    {
        let budget = Arc::clone(self);
        let mut seen = 0;
        stream.map(move |chunk| {
            let chunk = chunk?;
            budget.charge(&mut seen, chunk.len())?;
            Ok(chunk)
        })
    }

    /// The whole of `response`'s body, refused past either budget.
    pub(crate) async fn read(self: &Arc<Self>, response: reqwest::Response) -> Result<Bytes> {
        // An empty body charges nothing, so the kept refusal is checked here too.
        self.check()?;
        let stream = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(|e| safe_request_error("Failed to read response", &e)));
        // Boxed, not `pin!`: the critical coverage grade reads a macro's
        // expansion line as unreached.
        let mut stream = Box::pin(self.metered(stream));
        let mut body = BytesMut::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk?);
        }
        Ok(body.freeze())
    }
}

/// `error` is a [`ByteBudget`] refusal, which a caller must report rather
/// than read as a peer's silence.
#[cfg(any(test, feature = "webui"))]
pub(crate) fn is_budget_refusal(error: &Error) -> bool {
    let text = error.to_string();
    text.contains("over the preview's") || text.contains("preview is over its")
}

fn mib(bytes: usize) -> String {
    format!("{} MiB", bytes / (1024 * 1024))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_past_its_limit_names_the_response_budget() {
        let budget = ByteBudget::new(4 * 1024 * 1024, 8 * 1024 * 1024);
        let mut seen = 0;
        assert!(budget.charge(&mut seen, 4 * 1024 * 1024).is_ok());
        let error = budget.charge(&mut seen, 1).unwrap_err().to_string();
        assert!(
            error.contains("response is over the preview's 4 MiB budget"),
            "{error}"
        );
    }

    /// Once refused, a later small read is refused too, with the first reason.
    #[test]
    fn a_refusal_is_kept_for_every_later_read() {
        let budget = ByteBudget::new(1024, 1 << 20);
        let first = budget.response_refusal().to_string();
        assert!(first.contains("over the preview's"), "{first}");
        let later = budget.charge(&mut 0, 1).unwrap_err().to_string();
        assert_eq!(later, first);
        assert_eq!(budget.charge_total(1).unwrap_err().to_string(), first);
    }

    fn response(body: &'static [u8]) -> reqwest::Response {
        reqwest::Response::from(axum::http::Response::new(body))
    }

    /// `read` returns a body within both budgets whole.
    #[tokio::test]
    async fn read_returns_a_body_within_budget() {
        let budget = Arc::new(ByteBudget::new(16, 32));
        let body = budget.read(response(b"tools list")).await.unwrap();
        assert_eq!(body.as_ref(), b"tools list");
    }

    /// `read` refuses a body past the per-response budget, and then refuses
    /// an empty one with the same reason before reading it.
    #[tokio::test]
    async fn read_refuses_a_body_past_its_budget_and_keeps_refusing() {
        let budget = Arc::new(ByteBudget::new(4, 32));
        let first = budget
            .read(response(b"too long"))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            is_budget_refusal(&Error::Transport(first.clone())),
            "{first}"
        );
        let later = budget.read(response(b"")).await.unwrap_err().to_string();
        assert_eq!(later, first);
    }

    #[test]
    fn responses_past_the_total_name_the_preview_budget() {
        let budget = ByteBudget::new(4 * 1024 * 1024, 8 * 1024 * 1024);
        for _ in 0..2 {
            let mut seen = 0;
            assert!(budget.charge(&mut seen, 4 * 1024 * 1024).is_ok());
        }
        let error = budget.charge(&mut 0, 1).unwrap_err().to_string();
        assert!(
            error.contains("preview is over its 8 MiB budget"),
            "{error}"
        );
    }
}
