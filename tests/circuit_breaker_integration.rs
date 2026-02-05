//! Circuit breaker integration tests - per-backend configuration

use std::time::Duration;
use mcp_gateway::config::CircuitBreakerConfig;
use mcp_gateway::failsafe::CircuitBreaker;

#[test]
fn test_circuit_breaker_with_custom_config() {
    // Stricter configuration
    let custom_config = CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 3,  // Lower than default 5
        success_threshold: 4,  // Higher than default 2
        reset_timeout: Duration::from_secs(60),
    };

    let cb = CircuitBreaker::new("custom-backend", &custom_config);

    // Should open after 3 failures (not default 5)
    for _ in 0..2 {
        cb.record_failure();
    }
    assert!(cb.can_proceed());

    cb.record_failure(); // Third failure
    assert!(!cb.can_proceed());
}

#[test]
fn test_circuit_breaker_with_lenient_config() {
    // More lenient configuration for flaky backends
    let lenient_config = CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 10,  // Higher than default 5
        success_threshold: 2,   // Same as default
        reset_timeout: Duration::from_secs(30),
    };

    let cb = CircuitBreaker::new("flaky-backend", &lenient_config);

    // Should still be closed after 5 failures (default would open)
    for _ in 0..5 {
        cb.record_failure();
    }
    assert!(cb.can_proceed());

    // Should open after 10 failures
    for _ in 0..5 {
        cb.record_failure();
    }
    assert!(!cb.can_proceed());
}

#[test]
fn test_status_message_format() {
    let config = CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 3,
        success_threshold: 2,
        reset_timeout: Duration::from_secs(30),
    };

    let cb = CircuitBreaker::new("test-backend", &config);

    // Closed state
    let message = cb.status_message();
    assert!(message.contains("test-backend"));
    assert!(message.contains("closed"));

    // Open state
    for _ in 0..3 {
        cb.record_failure();
    }
    let message = cb.status_message();
    assert!(message.contains("Backend 'test-backend'"));
    assert!(message.contains("circuit breaker is open"));
    assert!(message.contains("3 failures"));
    assert!(message.contains("seconds"));
    assert!(message.contains("retry in"));
}

#[test]
fn test_disabled_circuit_breaker_config() {
    let disabled_config = CircuitBreakerConfig {
        enabled: false,
        failure_threshold: 3,
        success_threshold: 2,
        reset_timeout: Duration::from_secs(30),
    };

    let cb = CircuitBreaker::new("disabled-backend", &disabled_config);

    // Should never open, even with many failures
    for _ in 0..100 {
        cb.record_failure();
    }
    assert!(cb.can_proceed());

    let message = cb.status_message();
    assert!(message.contains("closed")); // Should report as closed even with failures
}

#[test]
fn test_half_open_state_message() {
    let config = CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 2,
        success_threshold: 3,
        reset_timeout: Duration::from_millis(10),
    };

    let cb = CircuitBreaker::new("recovery-backend", &config);

    // Open the circuit
    cb.record_failure();
    cb.record_failure();
    assert!(!cb.can_proceed());

    // Wait for reset timeout
    std::thread::sleep(Duration::from_millis(15));

    // Should transition to half-open on next can_proceed check
    assert!(cb.can_proceed());

    let message = cb.status_message();
    assert!(message.contains("half-open"));
    assert!(message.contains("testing recovery"));
}

#[test]
fn test_multiple_backends_independent_state() {
    let config = CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 3,
        success_threshold: 2,
        reset_timeout: Duration::from_secs(30),
    };

    let cb1 = CircuitBreaker::new("backend-1", &config);
    let cb2 = CircuitBreaker::new("backend-2", &config);

    // Open circuit for backend-1
    for _ in 0..3 {
        cb1.record_failure();
    }

    // backend-1 should be open
    assert!(!cb1.can_proceed());
    assert!(cb1.status_message().contains("is open"));

    // backend-2 should still be closed
    assert!(cb2.can_proceed());
    assert!(cb2.status_message().contains("closed"));
}
