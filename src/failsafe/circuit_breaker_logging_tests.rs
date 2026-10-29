// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A state change writes its log line only after the state lock is released.
//! Status readers take that lock, and a log sink that stops reading would
//! otherwise stall them for as long as it stays stopped.

use std::io;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

use super::*;

/// A log writer that tells the test it was reached, then parks until released.
#[derive(Clone)]
struct Parked {
    entered: mpsc::Sender<()>,
    release: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl io::Write for Parked {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.entered.send(());
        // Returns at once when the test drops its sender.
        let _ = self.release.lock().expect("one writer at a time").recv();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for Parked {
    type Writer = Parked;

    fn make_writer(&self) -> Parked {
        self.clone()
    }
}

#[test]
fn a_transition_writes_its_log_line_after_releasing_the_state_lock() {
    crate::test_log_capture::keep_interest_open();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let writer = Parked {
        entered: entered_tx,
        release: Arc::new(Mutex::new(release_rx)),
    };
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        reset_timeout: Duration::from_secs(30),
    };
    let breaker = Arc::new(CircuitBreaker::new("probe", &config));
    let worker = {
        let breaker = Arc::clone(&breaker);
        std::thread::spawn(move || {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(writer)
                .with_max_level(tracing::Level::DEBUG)
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                breaker.transition_to(CircuitState::Open);
            });
        })
    };
    entered_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the transition reached the log writer");
    let free = breaker.state.try_read().is_some();
    drop(release_tx);
    worker.join().expect("the worker finished");
    assert!(
        free,
        "the state lock was held while the log line was written"
    );
}
