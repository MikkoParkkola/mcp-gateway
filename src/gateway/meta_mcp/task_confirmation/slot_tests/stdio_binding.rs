// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X14 binding a stdio caller (route-check-parity P3; MIK-8160, MIK-8326):
//! grants bound to the process that asked, the stdio owner's replay, and a
//! name the caller may not invoke left unclassified. On the slot fixture.

use super::*;

/// Two stdio processes: each draws its own nonce (`StdioNonce::process`).
const PROCESS_A: [u8; 32] = [0xA1; 32];
const PROCESS_B: [u8; 32] = [0xB2; 32];

/// [`ask_principal`] as the stdio process holding `nonce`, admitting its tasks
/// under the local operator as `stdio_tasks::intent` does.
async fn ask_stdio(fx: &Fixture, retry: &RetryFields, nonce: &[u8; 32]) -> TaskConfirmation {
    let principal = crate::protocol::mrtr::PrincipalSource::Stdio { nonce };
    let actor = Some(crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL);
    ask_principal(fx, retry, elicitation(), (principal, actor)).await
}

/// The retry that answers `outcome`'s challenge with `accept`.
fn accepting(outcome: &TaskConfirmation) -> RetryFields {
    let (_, issued_key, state) = challenge(outcome);
    RetryFields {
        input_responses: Some(json!({ issued_key: { "action": "accept" } })),
        request_state: Some(state),
        ..fresh()
    }
}

/// MIK-8160.X14.1 (P3, lead ruling 1): a stdio caller is challenged, bound
/// to its own process. Another stdio process cannot answer the grant; the
/// process that asked can, once.
#[tokio::test]
async fn a_stdio_grant_answers_only_the_process_that_asked() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let retry = accepting(&ask_stdio(&fx, &fresh(), &PROCESS_A).await);
    assert!(
        !matches!(
            ask_stdio(&fx, &retry, &PROCESS_B).await,
            TaskConfirmation::Granted(_)
        ),
        "another stdio process answered this process's grant"
    );
    assert!(matches!(
        ask_stdio(&fx, &retry, &PROCESS_A).await,
        TaskConfirmation::Granted(_)
    ));
}

/// P3: a grant does not cross between stdio and HTTP in either direction;
/// each owner then redeems its own.
#[tokio::test]
async fn a_grant_does_not_cross_between_stdio_and_http() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let stdio_grant = accepting(&ask_stdio(&fx, &fresh(), &PROCESS_A).await);
    assert!(
        !matches!(
            ask(&fx, &stdio_grant, elicitation()).await,
            TaskConfirmation::Granted(_)
        ),
        "an HTTP caller answered a stdio grant"
    );
    let http_grant = accepting(&ask(&fx, &fresh(), elicitation()).await);
    assert!(
        !matches!(
            ask_stdio(&fx, &http_grant, &PROCESS_A).await,
            TaskConfirmation::Granted(_)
        ),
        "a stdio caller answered an HTTP grant"
    );
    assert!(matches!(
        ask(&fx, &http_grant, elicitation()).await,
        TaskConfirmation::Granted(_)
    ));
    assert!(matches!(
        ask_stdio(&fx, &stdio_grant, &PROCESS_A).await,
        TaskConfirmation::Granted(_)
    ));
}

/// P3 replay row: a stdio retry of a destructive task this gateway already
/// admitted, carrying no grant, is let through to admission (which returns the
/// task it owns), not challenged again. Pins `already_admitted` reading the
/// owner stdio admits under (`LOCAL_OPERATOR_PRINCIPAL`), never the nonce.
#[tokio::test]
async fn a_stdio_retry_of_an_admitted_task_is_not_asked_again() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let arguments = json!({ "id": 1 });
    let owned = super::super::task_admission_request(
        crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL.to_owned(),
        KEY.to_owned(),
        TOOL,
        &arguments,
    );
    let _held = fx.admission.admit_task(owned.borrow());
    assert!(
        matches!(
            ask_stdio(&fx, &fresh(), &PROCESS_A).await,
            TaskConfirmation::Granted(_)
        ),
        "an admitted stdio task was challenged again"
    );
}

/// MIK-8326.X14.4 (WH.4): X14 never classifies a surfaced name this caller may
/// not invoke, whoever calls it. Defence in depth behind the route stage's
/// withheld-name answer: a challenge would confirm the tool exists. Control:
/// the same call from a caller who may invoke it is challenged.
#[tokio::test]
async fn x14_does_not_classify_a_name_the_caller_may_not_invoke() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (arguments, task, retry) = (json!({ "id": 1 }), json!({ "ttl": 60_000 }), fresh());
    let alice = identity();
    let actor = alice.stable_actor_id();
    let denied = crate::gateway::meta_mcp::InvokeScope {
        authorizer: &crate::gateway::authz::DenyAll,
        ..open_scope()
    };
    let outcome = fx
        .meta
        .confirm_destructive_task(&TaskConfirmationRequest {
            id: RequestId::Number(7),
            tool_name: TOOL,
            arguments: &arguments,
            task: Some(&task),
            retry: &retry,
            principal: crate::protocol::mrtr::PrincipalSource::Credential(Some(&alice)),
            admission_actor: Some(&actor),
            scope: denied,
            session_id: None,
            input_capabilities: elicitation(),
            is_modern: true,
            admission: &fx.admission,
        })
        .await;
    assert!(
        matches!(outcome, TaskConfirmation::NotRequired),
        "X14 decided a withheld tool: {outcome:?}"
    );
    assert!(
        matches!(
            ask(&fx, &fresh(), elicitation()).await,
            TaskConfirmation::Answer(_)
        ),
        "control: a caller who may invoke it is challenged"
    );
}
