// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8857.API4.1: one case per state, and the precedence between them.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{ServerState, StateInputs, decide};
use crate::failsafe::CircuitState;
use crate::runtime::RuntimeDenyReason;

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

/// A backend that never started and has nothing wrong with it.
fn fresh() -> StateInputs {
    StateInputs {
        denied: false,
        denial_reasons: Vec::new(),
        auth_wait: false,
        breaker: CircuitState::Closed,
        retry_after: Duration::ZERO,
        healthy: true,
        consecutive_failures: 0,
        running: false,
        reaped: false,
        ever_started: false,
        start_failed: false,
        slow: None,
    }
}

fn state_of(inputs: &StateInputs) -> ServerState {
    decide(inputs, now()).state
}

#[test]
fn api4_1_running() {
    let view = decide(
        &StateInputs {
            running: true,
            ever_started: true,
            ..fresh()
        },
        now(),
    );
    assert_eq!(view.state, ServerState::Running);
    assert_eq!(view.next_retry_at, None);
    assert!(!view.reason.is_empty(), "every state says why");
}

#[test]
fn api4_1_paused_retries_when_the_breaker_admits_a_probe() {
    let view = decide(
        &StateInputs {
            breaker: CircuitState::Open,
            retry_after: Duration::from_millis(30_000),
            healthy: false,
            consecutive_failures: 5,
            ever_started: true,
            ..fresh()
        },
        now(),
    );
    assert_eq!(view.state, ServerState::Paused);
    assert_eq!(view.next_retry_at, Some(now() + Duration::from_secs(30)));
    assert!(
        view.reason.contains('5'),
        "names the failure count: {}",
        view.reason
    );
}

#[test]
fn api4_1_paused_half_open_retries_now() {
    let view = decide(
        &StateInputs {
            breaker: CircuitState::HalfOpen,
            ever_started: true,
            ..fresh()
        },
        now(),
    );
    assert_eq!(view.state, ServerState::Paused);
    assert_eq!(view.next_retry_at, Some(now()));
}

#[test]
fn api4_1_dormant_when_reaped() {
    let inputs = StateInputs {
        reaped: true,
        ever_started: true,
        ..fresh()
    };
    assert_eq!(state_of(&inputs), ServerState::Dormant);
}

#[test]
fn api4_1_dormant_when_never_started_and_nothing_failed() {
    let view = decide(&fresh(), now());
    assert_eq!(view.state, ServerState::Dormant);
    assert!(!view.reason.is_empty());
}

#[test]
fn api4_1_unhealthy_while_calls_still_go_through() {
    let inputs = StateInputs {
        healthy: false,
        consecutive_failures: 2,
        running: true,
        ever_started: true,
        ..fresh()
    };
    assert_eq!(state_of(&inputs), ServerState::Unhealthy);
}

#[test]
fn api4_1_unhealthy_when_a_started_transport_dropped() {
    let inputs = StateInputs {
        ever_started: true,
        ..fresh()
    };
    assert_eq!(
        state_of(&inputs),
        ServerState::Unhealthy,
        "a connection that dropped is not a nap"
    );
}

#[test]
fn api4_1_unhealthy_when_the_last_start_failed() {
    let inputs = StateInputs {
        start_failed: true,
        ..fresh()
    };
    assert_eq!(
        state_of(&inputs),
        ServerState::Unhealthy,
        "a failed start is not a nap"
    );
}

#[test]
fn api4_1_a_connected_server_whose_rebuild_failed_reads_running() {
    let inputs = StateInputs {
        running: true,
        ever_started: true,
        start_failed: true,
        ..fresh()
    };
    assert_eq!(state_of(&inputs), ServerState::Running);
}

#[test]
fn api4_1_an_unhealthy_server_that_is_not_running_does_not_claim_calls_go_through() {
    let view = decide(
        &StateInputs {
            healthy: false,
            consecutive_failures: 2,
            ..fresh()
        },
        now(),
    );
    assert_eq!(view.state, ServerState::Unhealthy);
    assert!(!view.reason.contains("go through"), "{}", view.reason);
}

#[test]
fn api4_1_refused_names_the_denial_reasons() {
    let view = decide(
        &StateInputs {
            denied: true,
            denial_reasons: vec![RuntimeDenyReason::ForbiddenMount],
            ..fresh()
        },
        now(),
    );
    assert_eq!(view.state, ServerState::Refused);
    assert!(
        view.reason.contains("forbidden_mount"),
        "names the reason code: {}",
        view.reason
    );
    assert_eq!(view.next_retry_at, None);
}

#[test]
fn api4_1_needs_sign_in() {
    let inputs = StateInputs {
        auth_wait: true,
        ..fresh()
    };
    assert_eq!(state_of(&inputs), ServerState::NeedsSignIn);
}

#[test]
fn api4_1_unmanaged_serialises_snake_case() {
    assert_eq!(
        serde_json::to_value(ServerState::Unmanaged).unwrap(),
        "unmanaged"
    );
    assert_eq!(
        serde_json::to_value(ServerState::NeedsSignIn).unwrap(),
        "needs_sign_in"
    );
}

#[test]
fn api4_1_precedence_worst_first() {
    let open = StateInputs {
        breaker: CircuitState::Open,
        retry_after: Duration::from_secs(1),
        healthy: false,
        ever_started: true,
        ..fresh()
    };
    // A tripped breaker on a failing backend is paused, not unhealthy.
    assert_eq!(state_of(&open), ServerState::Paused);
    // A runtime refusal outranks everything.
    assert_eq!(
        state_of(&StateInputs {
            denied: true,
            auth_wait: true,
            ..open.clone()
        }),
        ServerState::Refused
    );
    // Signing in is the fix even when an older failure tripped the breaker.
    assert_eq!(
        state_of(&StateInputs {
            auth_wait: true,
            ..open.clone()
        }),
        ServerState::NeedsSignIn
    );
    // A failure is never shown as dormant: reaped but unhealthy reads unhealthy.
    assert_eq!(
        state_of(&StateInputs {
            reaped: true,
            healthy: false,
            ever_started: true,
            ..fresh()
        }),
        ServerState::Unhealthy
    );
}

#[test]
fn api4_2_a_running_server_far_over_its_usual_reads_slow() {
    let view = decide(
        &StateInputs {
            running: true,
            ever_started: true,
            slow: Some(crate::failsafe::Slow {
                recent_ms: 400,
                usual_ms: 100,
            }),
            ..fresh()
        },
        now(),
    );
    assert_eq!(view.state, ServerState::Slow);
    assert_eq!(view.next_retry_at, None);
    assert!(
        view.reason.contains("400 ms") && view.reason.contains("100 ms"),
        "the reason names both: {}",
        view.reason
    );
}

#[test]
fn api4_2_worse_states_win_over_slow() {
    let slow = Some(crate::failsafe::Slow {
        recent_ms: 400,
        usual_ms: 100,
    });
    let paused = StateInputs {
        running: true,
        ever_started: true,
        breaker: CircuitState::Open,
        healthy: false,
        consecutive_failures: 5,
        slow,
        ..fresh()
    };
    assert_eq!(state_of(&paused), ServerState::Paused);
    let unhealthy = StateInputs {
        running: true,
        ever_started: true,
        healthy: false,
        consecutive_failures: 2,
        slow,
        ..fresh()
    };
    assert_eq!(state_of(&unhealthy), ServerState::Unhealthy);
    let reaped = StateInputs {
        reaped: true,
        ever_started: true,
        slow,
        ..fresh()
    };
    assert_eq!(
        state_of(&reaped),
        ServerState::Dormant,
        "a server that is not running cannot be slow"
    );
}

#[test]
fn api4_2_slow_is_serialised_as_slow() {
    assert_eq!(
        serde_json::to_value(ServerState::Slow).expect("serialises"),
        serde_json::json!("slow")
    );
}

// ── The signals, written by the real start, dispatch and fill paths ─────────

mod through_a_backend {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use serde_json::Value;

    use super::ServerState;
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
    use crate::protocol::{JsonRpcResponse, RequestId};
    use crate::transport::Transport;
    use crate::{Error, Result};

    /// Answers every request, or refuses it with a sign-in wait while `wait`
    /// is set.
    struct SignIn {
        wait: AtomicBool,
        error: fn() -> Error,
    }

    #[async_trait]
    impl Transport for SignIn {
        async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
            if self.wait.load(Ordering::SeqCst) {
                return Err((self.error)());
            }
            Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                serde_json::json!({}),
            ))
        }
        async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
            Ok(())
        }
        fn is_connected(&self) -> bool {
            true
        }
        async fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    fn state(backend: &Backend) -> ServerState {
        backend.server_state(super::now()).state
    }

    fn http(name: &str, url: String) -> Arc<Backend> {
        Arc::new(Backend::new(
            name,
            BackendConfig {
                transport: TransportConfig::Http {
                    http_url: url,
                    streamable_http: Some(true),
                    protocol_version: None,
                },
                timeout: Duration::from_secs(10),
                ..BackendConfig::default()
            },
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ))
    }

    #[tokio::test]
    async fn api4_1_every_sign_in_wait_reads_needs_sign_in_until_a_call_succeeds() {
        let waits: [fn() -> Error; 4] = [
            || Error::AuthorizationRequired {
                backend: "b".into(),
            },
            || Error::AuthorizationPending {
                backend: "b".into(),
            },
            || Error::AuthorizationCancelled {
                backend: "b".into(),
            },
            || Error::AuthorizationIncomplete {
                backend: "b".into(),
                window_secs: 1,
            },
        ];
        for error in waits {
            let backend = Backend::new(
                "b",
                BackendConfig::default(),
                &FailsafeConfig::default(),
                Duration::from_secs(60),
            );
            let transport = Arc::new(SignIn {
                wait: AtomicBool::new(true),
                error,
            });
            backend.set_transport_for_test(transport.clone());
            assert!(backend.request("tools/list", None).await.is_err());
            assert_eq!(state(&backend), ServerState::NeedsSignIn, "{}", error());
            assert!(
                !backend.is_circuit_tripped(),
                "a sign-in wait is not a failure"
            );

            transport.wait.store(false, Ordering::SeqCst);
            backend
                .request("tools/list", None)
                .await
                .expect("signed in");
            assert_eq!(state(&backend), ServerState::Running, "{}", error());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn api4_2_a_running_backend_far_over_its_usual_reads_slow() {
        let backend = http(
            "slowing",
            crate::backend::publish_order_tests::upstream().await,
        );
        backend.ensure_started().await.expect("starts");
        assert_eq!(state(&backend), ServerState::Running, "premise");
        let tracker = &backend.shared_entry().failsafe.health_tracker;
        for _ in 0..500 {
            tracker.record_success(Duration::from_millis(100));
        }
        assert_eq!(state(&backend), ServerState::Running, "a steady usual");
        for _ in 0..99 {
            tracker.record_success(Duration::from_millis(1000));
        }
        assert_eq!(state(&backend), ServerState::Slow);
    }

    #[tokio::test]
    async fn api4_1_a_fresh_backend_whose_revive_fails_reads_unhealthy() {
        // Nothing listens on the discard port.
        let backend = http("dead", "http://127.0.0.1:9/mcp".to_owned());
        assert_eq!(state(&backend), ServerState::Dormant, "premise");
        assert!(backend.force_restart().await.is_err());
        assert_eq!(state(&backend), ServerState::Unhealthy);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn api4_1_a_started_backend_whose_connection_drops_reads_unhealthy() {
        let backend = http(
            "drops",
            crate::backend::publish_order_tests::upstream().await,
        );
        backend.ensure_started().await.expect("starts");
        assert_eq!(state(&backend), ServerState::Running);
        let transport = backend
            .shared_entry()
            .transport
            .read()
            .clone()
            .expect("published");
        transport.close().await.expect("closes");
        assert_eq!(state(&backend), ServerState::Unhealthy);
    }
}
