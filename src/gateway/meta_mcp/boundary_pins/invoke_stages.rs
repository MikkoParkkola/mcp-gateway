// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-B1: the closed B1 table and its live pin row.

use std::path::Path;

use super::invoke_stages_allow::{
    ExtraKind, S1_INTAKE_ALLOW, S2_DIRECTIVES_ALLOW, S3_RESOLVE_ALLOW, S4_ADMIT_KEYS_ALLOW,
    S5_PRE_SEND_ALLOW, StageSpec,
};
use super::invoke_stages_r6::check_r6;
use super::invoke_stages_rules::{
    check_r0, check_r1, check_r2, check_r3, check_r4, check_r5, check_r8, check_r10, find_function,
};

/// The B1 stages: file, function, `In` type and permitted `&mut` extras.
pub(super) const STAGES: &[StageSpec] = &[
    StageSpec {
        file: "src/gateway/meta_mcp/invoke/intake.rs",
        func: "intake",
        input: "IntakeIn",
        extra: &[],
        allow: S1_INTAKE_ALLOW,
    },
    StageSpec {
        file: "src/gateway/meta_mcp/invoke/intake.rs",
        func: "directives",
        input: "DirectivesIn",
        extra: &[],
        allow: S2_DIRECTIVES_ALLOW,
    },
    StageSpec {
        file: "src/gateway/meta_mcp/invoke/resolve.rs",
        func: "resolve",
        input: "ResolveIn",
        extra: &[ExtraKind::Witness],
        allow: S3_RESOLVE_ALLOW,
    },
    StageSpec {
        file: "src/gateway/meta_mcp/invoke/keys.rs",
        func: "admit_keys",
        input: "KeysIn",
        extra: &[ExtraKind::Reservation],
        allow: S4_ADMIT_KEYS_ALLOW,
    },
    StageSpec {
        file: "src/gateway/meta_mcp/invoke/keys.rs",
        func: "pre_send",
        input: "PreSendIn",
        extra: &[ExtraKind::Witness, ExtraKind::Reservation],
        allow: S5_PRE_SEND_ALLOW,
    },
];

fn read_stage(path: &str) -> Option<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&root).ok()
}

fn prefixed(stage: &StageSpec, hits: Vec<String>) -> Vec<String> {
    hits.into_iter()
        .map(|hit| format!("{}::{}: {hit}", stage.file, stage.func))
        .collect()
}

/// The live pin: every closed-table stage is field-exact and within its allowlist.
/// Red while the stage files are missing; green once B1 lands them.
/// Accepted gaps, each deliberate:
/// - A dependency or `self` passed inside a macro argument is not checked.
/// - A local named like an external function hides that call, including `let hidden = hidden(args)`.
/// - Silencing attributes are not scanned. `#[forbid(unused_variables)]`, which R10 requires, makes `allow` or `expect` of `unused_variables` or `unused` a hard error (E0453). `allow(warnings)` compiles but cannot lower the forbidden lint, so it cannot hide an unused input.
#[test]
fn invoke_stages_are_field_exact_and_within_their_allowlists() {
    let mut violations = Vec::new();
    for stage in STAGES {
        let source = read_stage(stage.file);
        let parsed = if let Some(text) = &source {
            syn::parse_file(text).ok()
        } else {
            None
        };
        violations.extend(prefixed(
            stage,
            check_r0(stage.file, stage.func, source.as_deref(), parsed.as_ref()),
        ));
        let Some(file) = &parsed else {
            continue;
        };
        let Some(found) = find_function(file, stage.func) else {
            continue;
        };
        violations.extend(prefixed(stage, check_r1(&found, stage.input)));
        violations.extend(prefixed(stage, check_r2(&found, stage.input)));
        violations.extend(prefixed(stage, check_r3(&found, stage.input)));
        violations.extend(prefixed(stage, check_r4(&found, file, stage.input)));
        violations.extend(prefixed(stage, check_r5(&found, stage.input, stage.extra)));
        violations.extend(prefixed(stage, check_r6(&found, stage.allow)));
        violations.extend(prefixed(stage, check_r8(&found)));
        violations.extend(prefixed(stage, check_r10(&found, stage.input)));
    }
    assert!(
        violations.is_empty(),
        "stage pin violations:\n{}",
        violations.join("\n")
    );
}

/// The `prefixed` helper tags every hit with its stage file and function.
#[test]
fn prefixed_tags_hits_with_file_and_func() {
    let stage = StageSpec {
        file: "f.rs",
        func: "g",
        input: "IntakeIn",
        extra: &[],
        allow: &[],
    };
    // One sample hit is enough: the helper only prepends `<file>::<fn>`.
    let hits = prefixed(&stage, vec![String::from("R0: sample")]);
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0].starts_with("f.rs::g"),
        "want `<file>::<fn>` prefix, got {}",
        hits[0]
    );
}
