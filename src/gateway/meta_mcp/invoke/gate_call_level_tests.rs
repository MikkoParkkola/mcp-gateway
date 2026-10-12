// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 amendment A1: for a target the caller cannot see, signing skips
//! the policy and judges only what a missing name meets there. A malformed
//! name is one of those: it must be refused exactly as the authorizer refuses
//! it (-32600, the bare reason, 403) and audited the same way, so a hidden
//! name and a missing one cannot be told apart by it.

use std::sync::{Arc, Mutex};

use serde_json::json;
use tracing_subscriber::layer::SubscriberExt;

use crate::gateway::authz::ToolPolicyAuthorizer;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_hidden_malformed_name_is_refused_and_audited_as_the_authorizer_refuses_it() {
    let (registry, _) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let policy = crate::security::ToolPolicy::default();
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &policy,
    };
    let caller = ctx(&authorizer);
    let arguments = json!({"server": "alpha", "tool": "bad/tool", "arguments": {}});

    // The twin: what the policy this call skipped answers for the same name.
    let by_policy = meta
        .authorize_invocation(&arguments, &caller)
        .expect_err("the authorizer refuses a malformed name");

    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || writer.clone()),
    );
    // A callsite another thread cached as off would miss this capture (MIK-8254).
    crate::test_log_capture::keep_interest_open();
    let guard = tracing::subscriber::set_default(subscriber);
    let by_signing = meta
        .check_call_level_policy(&arguments, &caller)
        .expect_err("signing refuses a malformed hidden name");
    drop(guard);

    assert_eq!(
        format!("{by_signing:?}"),
        format!("{by_policy:?}"),
        "the same refusal, code, status and message"
    );
    let logged = String::from_utf8(buffer.0.lock().map(|b| b.clone()).unwrap_or_default())
        .unwrap_or_default();
    let line = logged
        .lines()
        .find(|l| l.contains("Tool invocation refused by authorization"))
        .unwrap_or_else(|| panic!("no authorization-refusal warning logged:\n{logged}"));
    assert!(line.contains("bad/tool"), "{line}");
}

/// The authorizers pass an empty tool name, so the skipped policy answers it
/// with its own name check: signing answers an empty hidden name the same way.
#[test]
fn an_empty_hidden_name_is_refused_as_the_policy_refuses_it() {
    let (registry, _) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let policy = crate::security::ToolPolicy::default();
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &policy,
    };
    let caller = ctx(&authorizer);
    let arguments = json!({"server": "alpha", "tool": "", "arguments": {}});

    let by_policy = meta
        .check_invocation_policy(&arguments, None, &caller)
        .expect_err("the policy refuses an empty name");
    let by_signing = meta
        .check_call_level_policy(&arguments, &caller)
        .expect_err("signing refuses an empty hidden name");
    assert_eq!(
        format!("{by_signing:?}"),
        format!("{by_policy:?}"),
        "the same refusal as the policy this call skipped"
    );
}
