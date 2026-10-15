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

/// H2 (MIK-8361 ORACLE.2 grant/admin x stdio, codex review): signing runs
/// before the stdio route stage, so a signed `gateway_invoke` of a capability
/// the caller may not reach (admin-only for a non-admin; personal with no
/// grant) must be judged as the undefined capability is, not refused for its
/// reason. Same caller, same valid fresh nonce, same arguments.
#[tokio::test]
async fn h2_signing_judges_an_unreachable_capability_as_the_undefined_one() {
    use crate::capability::{CapabilityBackend, CapabilityExecutor};
    use crate::gateway::authz::AllowAll;
    use crate::gateway::meta_mcp::signing::{NONCE_META, SigningInvocationContext, SigningScope};
    const CAPS: &str = "caps";
    const CAP: &str = "hook_or_day";
    let definition = |personal: bool| {
        let metadata = if personal {
            "  exposure: personal\n  read_only: true\n  identity_owner:\n    authority: api_key\n    subject: alice\n"
        } else {
            "  exposure: public\n  read_only: false\n  registers_external_callback: true\n"
        };
        format!(
            "name: {CAP}\ndescription: A fixture capability\nmetadata:\n{metadata}\
             providers:\n  primary:\n    service: rest\n    config:\n      \
             base_url: http://127.0.0.1:9\n      path: /x\n      method: POST\n"
        )
    };
    let judged = |defined: Option<bool>| {
        let caps = Arc::new(CapabilityBackend::new(
            CAPS,
            Arc::new(CapabilityExecutor::new()),
        ));
        if let Some(personal) = defined {
            let parsed = crate::capability::parse_capability(&definition(personal))
                .expect("the fixture capability parses");
            caps.register_capability(parsed)
                .expect("the fixture capability registers");
        }
        let (registry, _) = counted_backend("alpha");
        let mut meta = MetaMcp::new(registry).with_identity_grants(
            crate::identity_grants::LocalIdentityGrantStore::from_grants(Vec::new()),
        );
        meta.set_capabilities(caps);
        meta.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"h2-capability-key-0123456789abcde".to_vec(),
                None,
                "k1".into(),
            ),
            std::time::Duration::from_secs(300),
            true,
        );
        let caller = ctx(&AllowAll);
        let arguments = json!({"server": CAPS, "tool": CAP, "arguments": {}});
        let mut request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "gateway_invoke", "arguments": arguments,
                       "_meta": {(NONCE_META): "h2-fresh-nonce"}}});
        let mut signing =
            SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
        let arguments = request["params"]["arguments"].clone();
        let answer = meta.prepare_signing_for_call(
            &mut signing,
            "gateway_invoke",
            &arguments,
            None,
            &caller,
        );
        format!("{answer:?} admitted={}", !signing.awaits_admission())
    };
    let undefined = judged(None);
    let mut cells = Vec::new();
    for (label, personal) in [("admin-only", false), ("personal, no grant", true)] {
        let defined = judged(Some(personal));
        if defined != undefined {
            cells.push(format!(
                "{label}: defined {defined} vs undefined {undefined}"
            ));
        }
    }
    assert!(
        cells.is_empty(),
        "H2 capability signing:\n{}",
        cells.join("\n")
    );
}

/// H3 (MIK-8361 ORACLE.2 K2, codex review): on a killed backend a signed call
/// with a malformed nonce must be refused alike for a hidden tool and a
/// missing one. Signing runs before the stdio route stage, so its order is
/// the answer stdio gives: the kill switch is backend-wide, not
/// existence-sensitive, and a missing name meets it before the nonce.
#[tokio::test]
async fn h3_a_killed_backend_refuses_a_malformed_nonce_alike_for_hidden_and_missing() {
    use crate::gateway::meta_mcp::signing::{NONCE_META, SigningInvocationContext, SigningScope};
    let refusal = |tool: &str, deny: &[&str]| {
        let (registry, _) = counted_backend("alpha");
        let mut meta = MetaMcp::new(registry);
        meta.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"h3-kill-order-key-0123456789abcde".to_vec(),
                None,
                "k1".into(),
            ),
            std::time::Duration::from_secs(300),
            true,
        );
        meta.kill_switch().kill("alpha");
        let policy = crate::security::ToolPolicy::from_config(&crate::security::ToolPolicyConfig {
            deny: deny.iter().map(|t| (*t).to_owned()).collect(),
            use_default_deny: false,
            ..crate::security::ToolPolicyConfig::default()
        });
        let authorizer = ToolPolicyAuthorizer {
            tool_policy: &policy,
        };
        let caller = ctx(&authorizer);
        let arguments = json!({"server": "alpha", "tool": tool, "arguments": {}});
        let mut request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "gateway_invoke", "arguments": arguments,
                       "_meta": {(NONCE_META): 42}}});
        let mut signing =
            SigningInvocationContext::capture_scoped(&mut request, SigningScope::InvokeOnly);
        let arguments = request["params"]["arguments"].clone();
        let refused = meta
            .prepare_signing_for_call(&mut signing, "gateway_invoke", &arguments, None, &caller)
            .expect_err("a killed backend's signed call is refused");
        format!("{refused:?}").replace(tool, "<tool>")
    };
    let hidden = refusal("read", &["read"]);
    let missing = refusal("not_listed", &[]);
    assert_eq!(
        hidden, missing,
        "a hidden tool and a missing one are refused alike on a killed backend"
    );
}

/// A call whose arguments name no server or no tool is no withheld target:
/// signing's skip is for a named target only (#3872 coverage, gate.rs).
#[test]
fn an_unnamed_invoke_target_is_not_withheld() {
    use crate::gateway::authz::AllowAll;
    let (registry, _) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let caller = ctx(&AllowAll);
    for arguments in [json!({"server": "alpha"}), json!({"tool": "read"})] {
        assert!(
            !meta.withheld_invoke_target(&arguments, None, &caller),
            "an unnamed target is not withheld: {arguments}"
        );
    }
}

/// Under `input_schema_enforcement: Off` a name the held list does not hold
/// is unproven (the held list never reports a lacked name), so it is
/// forwarded, not the gate's: the route stage does not answer it as
/// invisible (#3872 coverage, gate.rs; S6's stated residual).
#[tokio::test]
async fn under_off_a_lacked_name_is_not_invisible_at_the_route() {
    use crate::gateway::authz::AllowAll;
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig {
            input_schema_enforcement: crate::config::InputSchemaEnforcement::Off,
            ..crate::config::BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    ));
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read", "inputSchema": {"type": "object"}
    }))
    .expect("a tool");
    backend.store_shared_tools_for_test(vec![tool]);
    assert!(registry.register(backend), "premise: alpha registers");
    let meta = MetaMcp::new(registry);
    let caller = ctx(&AllowAll);
    assert!(
        !meta
            .invisible_at_route(("alpha", "not_listed"), &caller, None)
            .await,
        "under off a lacked name is forwarded, not invisible"
    );
}
