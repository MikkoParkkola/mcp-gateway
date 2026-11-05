// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9309 R11, the stdio first list's two waits share one start: the own
//! view warm of a per-user backend (`warm_listing_views`) and the first
//! list's wait for a shared surfaced backend's first fill. Each is capped
//! from that start, so together they take one bound, never two. Uses the
//! parent's fixture, on a paused clock.
use super::*;

use std::time::Duration;

use crate::backend::Backend;
use crate::config::TransportConfig;
use crate::gateway::server::first_list_wait::FirstList;
use crate::gateway::server::signing_allocation_tests::stdio_first_list::held_backend;

const SHARED: &str = "held_shared";
const SHARED_TOOL: &str = "held_shared_tool";
/// The fill bound's grace over a backend's call timeout (`LIST_FILL_WAIT_GRACE`).
const GRACE: Duration = Duration::from_secs(1);

#[tokio::test(start_paused = true)]
async fn r11_the_first_lists_two_waits_share_one_deadline_stdio() {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), &Binding::Connected);
    let per_user = gateway.backends().get(BACKEND).expect("the backend");
    assert!(
        per_user.shared_slot_refused(),
        "premise: a per-user-sessions-only backend"
    );
    let bound = per_user.tools_fill_bound();
    // A shared backend that never answers its tools/list, with the same bound.
    let held = held_backend(&[SHARED_TOOL]).await;
    let shared = Arc::new(Backend::new(
        SHARED,
        crate::config::BackendConfig {
            transport: TransportConfig::Http {
                http_url: held.url.clone(),
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout: bound
                .checked_sub(GRACE)
                .expect("premise: a fill bound past its grace"),
            ..crate::config::BackendConfig::r2_off()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    assert!(
        gateway.backends().register(shared),
        "premise: the shared backend registers"
    );
    let meta = Arc::new(gateway.take_meta().with_surfaced_tools(vec![
        SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        },
        SurfacedToolConfig {
            server: SHARED.to_string(),
            tool: SHARED_TOOL.to_string(),
        },
    ]));
    // Armed and never released: the own-view warm waits out its deadline.
    let (_reached, _held_prepass) = per_user.before_listing_prepass.arm();
    let stdio = Stdio {
        gateway,
        meta,
        tasks: None,
    };
    let started = tokio::time::Instant::now();
    let answer = FirstList::default()
        .scope(stdio.rpc(
            1,
            "tools/list",
            json!({"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}),
        ))
        .await;
    let took = started.elapsed();
    assert!(answer.get("error").is_none(), "{answer}");
    assert!(
        took >= bound
            .checked_sub(GRACE)
            .expect("premise: a fill bound past its grace"),
        "premise: the list waited ({took:?} for a {bound:?} bound)"
    );
    assert!(
        took < bound + bound / 2,
        "the two waits added up: {took:?} for one {bound:?} bound"
    );
}
