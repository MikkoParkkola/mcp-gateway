// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final), group 3, rows that need the caller-verdict
//! seam (`caller_verdict`, the carried dispatch): C12. Mutant-red (M04).

use serde_json::json;

use super::catalogue_per_caller_tests::identity;
use super::identified_caller;
use super::invoke::CallerVerdict;
use super::slot_verdict_fixture::{
    BACKEND, CallerSlot, Surfaced, TOOL, Warmth, per_user, per_user_backend, valid,
};
use super::visible::with_visibility_memo;
use crate::config::InputSchemaEnforcement;

const CLOSED: InputSchemaEnforcement = InputSchemaEnforcement::Closed;

/// C12: the registry is reloaded between the caller verdict and the dispatch.
/// The call goes to the backend instance the verdict judged (or is refused);
/// never to the replacement, which would receive the old credential.
#[tokio::test]
async fn g3_c12_reload_between_verdict_and_dispatch() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::Yes,
    );
    let (replacement, repl_caller, repl_shared) =
        per_user_backend(CallerSlot::Valid, &valid(), Warmth::Warm, CLOSED);
    let alpha = identity("alpha");
    let answer = with_visibility_memo(async {
        let verdict = fx
            .meta
            .caller_verdict(
                (BACKEND, TOOL),
                &identified_caller(&alpha),
                None,
                super::invoke::TargetNaming::SurfacedName,
            )
            .await
            .expect("the verdict resolves");
        assert!(
            matches!(verdict, CallerVerdict::Proceed),
            "premise: {verdict:?}"
        );
        assert!(fx.meta.backends.remove(BACKEND), "premise: reload removes");
        assert!(
            fx.meta.backends.register(replacement),
            "premise: reload registers"
        );
        let response = Box::pin(fx.meta.handle_tools_call(
            crate::protocol::RequestId::Number(1),
            TOOL,
            json!({"q": "x"}),
            None,
            identified_caller(&alpha),
        ))
        .await;
        serde_json::to_value(&response).expect("a response serialises")
    })
    .await;
    assert_eq!(
        repl_caller.calls() + repl_shared.calls(),
        0,
        "C12: the call reached the replacement backend: {answer}"
    );
    assert!(
        fx.caller.calls() + fx.shared.calls() == 1 || answer.get("error").is_some(),
        "C12: neither dispatched to the captured instance nor refused: {answer}"
    );
}
