// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A byte budget for every body a transport reads (MIK-8838, U6 preview).
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
}

impl ByteBudget {
    pub(crate) const fn new(per_response: usize, total: usize) -> Self {
        Self {
            per_response,
            total,
            used: AtomicUsize::new(0),
        }
    }

    /// Count `len` more bytes of one response that has read `seen` so far.
    fn charge(&self, seen: &mut usize, len: usize) -> Result<()> {
        *seen = seen.saturating_add(len);
        if *seen > self.per_response {
            return Err(Error::Transport(format!(
                "the response is over the preview's {} budget",
                mib(self.per_response)
            )));
        }
        let used = self
            .used
            .fetch_add(len, Ordering::Relaxed)
            .saturating_add(len);
        if used > self.total {
            return Err(Error::Transport(format!(
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
        let stream = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(|e| safe_request_error("Failed to read response", &e)));
        let mut stream = std::pin::pin!(self.metered(stream));
        let mut body = BytesMut::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk?);
        }
        Ok(body.freeze())
    }
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
