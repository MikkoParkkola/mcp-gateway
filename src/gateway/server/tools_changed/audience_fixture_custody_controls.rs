// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 custody controls: dropping a genuinely admitted legacy `Ear`
//! ends its view's custody without removing the session, and a non-bearer
//! Authorization beside a live cookie is a typed bearer refusal while the
//! cookie alone admits live. Read on the default current-thread runtime,
//! as the fixture's thread-local drain requires.

use super::{Ear, World};
use crate::gateway::streaming::{DeadReason, SessionFrame};
use crate::protocol::Tool;

const STD: &str = "k-std";

fn tool(name: &str, description: &str) -> Tool {
    serde_json::from_value(serde_json::json!({
        "name": name, "description": description, "inputSchema": { "type": "object" }
    }))
    .expect("a tool")
}

fn alpha_with(read: &str) -> Vec<Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

/// The borrowed admission is a genuine `Ok(Some(view))`; the borrow ends
/// here, before any told/drop in the caller. Nothing is removed or cloned.
fn require_admitted(ear: &Ear) {
    match ear {
        Ear::Legacy {
            _view_admission: view_admission,
            ..
        } => match view_admission {
            Ok(Some(_view)) => {}
            Ok(None) => panic!("premise: admission must be Ok(Some(view)), got Ok(None)"),
            Err(reason) => panic!("premise: admission must be Ok(Some(view)), got {reason:?}"),
        },
        _ => panic!("premise: a legacy ear"),
    }
}

/// The borrowed admission is the typed `Err(Bearer)` refusal.
fn require_bearer_refusal(ear: &Ear) {
    match ear {
        Ear::Legacy {
            _view_admission: view_admission,
            ..
        } => match view_admission {
            Err(DeadReason::Bearer) => {}
            Err(reason) => panic!("premise: refusal must be Err(Bearer), got {reason:?}"),
            Ok(Some(_view)) => panic!("premise: refusal must be Err(Bearer), got Ok(Some)"),
            Ok(None) => panic!("premise: refusal must be Err(Bearer), got Ok(None)"),
        },
        _ => panic!("premise: a legacy ear"),
    }
}

/// A resubscribed duplicate of the session's own receiver and the actual
/// session id: the only custody retained past the ear's drop, no lease.
fn retained(ear: &Ear) -> (tokio::sync::broadcast::Receiver<SessionFrame>, String) {
    match ear {
        Ear::Legacy { rx, session, .. } => (rx.resubscribe(), session.clone()),
        _ => panic!("premise: a legacy ear"),
    }
}

async fn custody_one(owned: bool, label: &str) {
    let world = World::start().await;
    let mut ear = if owned {
        world.legacy_owned(label, STD).await
    } else {
        world.legacy(label, STD).await
    };
    require_admitted(&ear);
    let (mut duplicate, session) = retained(&ear);
    assert!(
        world.served_names(STD).await.contains(&"read".to_string()),
        "premise: k-std is really served read"
    );
    world.store_shared("alpha", alpha_with("r2"));
    assert_eq!(ear.told(&world).await, 1, "one visible change before drop");
    while duplicate.try_recv().is_ok() {}
    drop(ear);
    assert!(
        world.state.multiplexer.has_session(&session),
        "the real registry still has the session after the ear drops"
    );
    world.store_shared("alpha", alpha_with("r3"));
    world.settle().await;
    assert!(
        matches!(
            duplicate.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ),
        "no visible change is delivered after custody ends"
    );
}

#[tokio::test]
async fn dropping_an_admitted_legacy_ear_ends_custody_not_the_session() {
    custody_one(false, "custody-legacy").await;
    custody_one(true, "custody-owned").await;
}

#[tokio::test]
async fn basic_beside_a_live_cookie_is_refused_and_the_cookie_alone_admits() {
    let world = World::start().await;
    let cookie = world.dashboard_cookie();
    let mut refused = world
        .legacy_with(
            "custody-basic",
            &[
                ("authorization", "Basic dXNlcjpwYXNz".to_string()),
                ("cookie", cookie.clone()),
            ],
        )
        .await;
    require_bearer_refusal(&refused);
    let mut admitted = world
        .legacy_with("custody-cookie", &[("cookie", cookie)])
        .await;
    require_admitted(&admitted);
    world.store_shared("alpha", alpha_with("r2"));
    assert_eq!(
        refused.told(&world).await,
        0,
        "a non-bearer Authorization beside a live cookie is dead"
    );
    assert_eq!(
        admitted.told(&world).await,
        1,
        "the cookie alone is a genuine live admission, told once"
    );
}
