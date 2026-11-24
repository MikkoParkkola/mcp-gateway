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
