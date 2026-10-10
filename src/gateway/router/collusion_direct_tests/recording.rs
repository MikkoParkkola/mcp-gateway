// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the relay check records: delivered results only, passthrough, sensitivity, errors and the over-cap head and tail.

use super::*;

/// A9: only what the caller was delivered is recorded. A result the response
/// firewall refuses after dispatch, and an error answer, record nothing; the
/// same fixture then records a delivered one. Both delivery arms.
#[tokio::test]
async fn only_a_delivered_result_is_recorded() {
    for passthrough in [false, true] {
        let setup = Setup {
            passthrough,
            rules: "[{match: read, action: block}]",
            ..Setup::default()
        };
        let fx = fixture(setup).await;
        for (sends, refused) in [(1, Read::Injected), (2, Read::Error)] {
            fx.answer_read(refused);
            fx.read_refused(Some("a")).await;
            assert_sent(&fx, &fx.send(Some("b"), PROSE).await, sends);
        }
        fx.answer_read(Read::Text(PROSE.to_string()));
        fx.read(Some("a")).await;
        assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 2);
    }
}

/// A10: a passthrough backend is relay-checked too.
#[tokio::test]
async fn a_passthrough_backend_is_checked() {
    let fx = fixture(Setup {
        passthrough: true,
        ..Setup::default()
    })
    .await;
    fx.read(Some("a")).await;
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 0);
}

/// A11: a delivery is sensitive when its context-integrity classes name
/// personal, financial or guarded material, or its source matches a
/// `sources` glob; a public class alone is not.
#[tokio::test]
async fn sensitivity_comes_from_the_class_or_the_sources_glob() {
    let cases = [
        ("personal_data", None, true),
        ("financial_data", None, true),
        ("guarded_material", None, true),
        ("public", None, false),
        ("public", Some("alpha:r*"), true),
        ("public", Some("alpha:rea"), false),
    ];
    for (class, source, refused) in cases {
        let setup = Setup {
            sources: source.map(str::to_string).into_iter().collect(),
            ..Setup::default()
        };
        let fx = fixture(setup).await;
        fx.answer_read(Read::Classified(class));
        fx.read(Some("a")).await;
        let sent = fx.send(Some("b"), PROSE).await;
        if refused {
            assert_refused(&fx, &sent, 0);
        } else {
            assert_sent(&fx, &sent, 1);
        }
    }
}

/// A12: a response carrying both a result and an error delivers both, so the
/// result is recorded.
#[tokio::test]
async fn a_result_beside_an_error_is_recorded() {
    let fx = fixture(Setup::default()).await;
    fx.answer_read(Read::Both);
    let answer = envelope(&fx.read(Some("a")).await);
    assert!(answer.get("error").is_some(), "{answer}");
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 0);
}

/// A13: past the recording cap, head and tail are recorded and the middle is
/// not: the documented evasion bound, pinned. One cut is counted.
#[tokio::test]
async fn an_over_cap_result_records_head_and_tail_only() {
    let fx = fixture(Setup::default()).await;
    let firewall = Arc::clone(fx.state.firewall.as_ref().unwrap());
    fx.read(Some("a")).await;
    assert_eq!(firewall.relay_text_cuts(), 0, "a short result is not cut");
    let long = (0..12_000).fold(String::new(), |mut s, i| {
        let _ = write!(s, "w{i} ");
        s
    });
    fx.answer_read(Read::Text(long.clone()));
    fx.read(Some("a")).await;
    assert_eq!(firewall.relay_text_cuts(), 1);
    let middle = long.len() / 2;
    let head = &long[..1_000];
    let tail = &long[long.len() - 1_000..];
    assert_refused(&fx, &fx.send(Some("b"), head).await, 0);
    assert_refused(&fx, &fx.send(Some("b"), tail).await, 0);
    assert_sent(
        &fx,
        &fx.send(Some("b"), &long[middle..middle + 1_000]).await,
        1,
    );
}

/// A14: `off` builds no detector and checks nothing.
#[tokio::test]
async fn off_checks_nothing() {
    let fx = fixture(Setup {
        action: CollusionAction::Off,
        ..Setup::default()
    })
    .await;
    let firewall = fx.state.firewall.as_ref().unwrap();
    assert!(firewall.collusion_detector().is_none());
    fx.read(Some("a")).await;
    assert_sent(&fx, &fx.send(Some("b"), PROSE).await, 1);
}
