// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8137 b1: the chokepoint's own rows, at the meta layer (gpt i1 on #3688).

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::gateway::authz::{
    AllowAll, AuthorizationError, Decision, QuotaPrincipal, ToolAuthorizer, ToolTarget, Transport,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx, invoke_args};

/// Allows the first `allowed` decisions, then refuses: a grant revoked after
/// the call was authorized and before it is sent.
struct RevokedAfter {
    allowed: usize,
    decided: AtomicUsize,
}

impl ToolAuthorizer for RevokedAfter {
    fn quota_principal(&self) -> Option<&QuotaPrincipal> {
        None
    }
    fn decide<'a>(&'a self, target: ToolTarget<'a>) -> Decision<'a> {
        if self.decided.fetch_add(1, Ordering::SeqCst) < self.allowed {
            return AllowAll.decide(target);
        }
        Decision::of(Err(AuthorizationError::forbidden(
            -32003,
            "grant revoked".to_owned(),
        )))
    }
    fn admits_backend(&self, _server: &str) -> bool {
        true
    }
    fn transport(&self) -> Transport {
        AllowAll.transport()
    }
    fn caller_name(&self) -> Option<&str> {
        None
    }
}

/// F5: a grant revoked between the call's authorization and its send is
/// refused at the chokepoint: the decision taken at admission is not reused,
/// and the backend is never reached. Control: the same call with the grant
/// kept is sent. Mutant: the chokepoint skipping `recheck_target`.
#[tokio::test]
async fn f5_a_grant_revoked_before_the_send_is_refused_at_dispatch() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let kept = RevokedAfter {
        allowed: usize::MAX,
        decided: AtomicUsize::new(0),
    };
    let sent = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&kept))
        .await;
    assert!(sent.is_ok(), "control: a kept grant is sent: {sent:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "control: the backend was reached"
    );

    let revoked = RevokedAfter {
        allowed: 1,
        decided: AtomicUsize::new(0),
    };
    let refused = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&revoked))
        .await;
    assert!(
        matches!(refused, Err(crate::Error::Forbidden { .. })),
        "refused at the chokepoint: {refused:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the revoked call reached its backend"
    );
    assert_eq!(
        revoked.decided.load(Ordering::SeqCst),
        2,
        "decided at admission and again at dispatch"
    );
}
