// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A save the shared writer turns down never reached its rename, so the
//! replace drops its journal and staged original and leaves gateway.yaml as
//! another process left it meanwhile. A refusal after the rename still puts
//! the original back (`replace_tests::a_refused_reload_rolls_the_file_back`).

use super::reload_context::replace::{Expected, ReplaceError, Replaced, replace_detached};
use super::replace_test_support::{NEXT, START, WAIT, names, read, setup, to};
use crate::config_persistence::writer_seams::{self as seams, Seams};

/// Each refusal: the error carries its code and sentence, the other
/// process's bytes stay exactly, and only the config and its lock sidecar
/// are left (no journal, staged original or scratch).
#[tokio::test]
async fn a_writer_refusal_keeps_the_other_writers_bytes_and_no_journal() {
    for code in ["foreign-owner", "target-changed", "acl-not-kept"] {
        let (dir, path, ctx) = setup();
        let other = format!("{START}# another writer\n");
        let mut put = Some(other.clone());
        let _armed = seams::arm(
            dir.path(),
            Seams {
                refuse: Some(code),
                // Once and in place, so only the injected refusal turns the
                // save down.
                before_verify: Some(Box::new(move |target, _scratch| {
                    if let Some(text) = put.take() {
                        std::fs::write(target, text).expect("the other writer");
                    }
                })),
                ..Seams::default()
            },
        );

        let failure = replace_detached(ctx, to(Expected::Any, NEXT, Replaced::Discard), WAIT)
            .await
            .expect_err("the writer refuses");

        match failure {
            ReplaceError::WriterRefused { code: got, text } => {
                assert_eq!(got, code);
                assert!(
                    text.starts_with(&format!("{code}: refused to replace ")),
                    "{code}: {text}"
                );
            }
            other => panic!("{code}: expected WriterRefused, got {other:?}"),
        }
        assert_eq!(read(&path), other, "{code}: the other writer's bytes stay");
        assert_eq!(
            names(dir.path()),
            [".gateway.yaml.lock", "gateway.yaml"],
            "{code}: nothing left beside the config"
        );
    }
}

/// gateway.yaml re-pointed at another config during the save: the refusal
/// removes this save's journal and staged original by the names it gave
/// them, and the other config's recovery files stay.
#[tokio::test]
async fn a_refusal_after_a_re_point_drops_only_its_own_journal() {
    let (dir, _path, ctx) = setup();
    let elsewhere = tempfile::tempdir().expect("tempdir");
    let other = elsewhere.path().join("gateway.yaml");
    std::fs::write(&other, START).expect("the other config");
    let theirs = [
        ".gateway.yaml.replace-journal",
        ".gateway.yaml.replace-original",
    ];
    for name in theirs {
        std::fs::write(elsewhere.path().join(name), b"theirs").expect("its recovery file");
    }
    let _armed = seams::arm(
        dir.path(),
        Seams {
            // No injected refusal: the writer's own check sees the re-point.
            before_verify: Some(Box::new(move |target, _scratch| {
                std::fs::rename(target, target.with_extension("moved")).expect("move away");
                std::os::unix::fs::symlink(&other, target).expect("re-point");
            })),
            ..Seams::default()
        },
    );

    let failure = replace_detached(ctx, to(Expected::Any, NEXT, Replaced::Discard), WAIT)
        .await
        .expect_err("the writer refuses");

    assert!(
        matches!(
            failure,
            ReplaceError::WriterRefused {
                code: "target-changed",
                ..
            }
        ),
        "{failure:?}"
    );
    for name in theirs {
        let kept = std::fs::read(elsewhere.path().join(name));
        assert_eq!(kept.ok().as_deref(), Some(&b"theirs"[..]), "{name} stays");
    }
    assert_eq!(
        names(dir.path()),
        [".gateway.yaml.lock", "gateway.moved", "gateway.yaml"],
        "this save's journal and staged original are gone"
    );
}
