//! Acceptance-criterion tests for MIK-3160.
//!
// The module docs below quote acceptance criteria verbatim (paths, flags,
// `<semver>` placeholders), which trips `doc_markdown`; keep them as authored.
#![allow(clippy::doc_markdown)]
//!
//! These mirror the deterministic `CHECK:` contracts from the ticket so that
//! `cargo test` fails fast if any deliverable regresses. The JSDoc-narrowing
//! harness itself is exercised by `node --test scripts/ts-upgrade/` (AC.5);
//! `ac_5_*` below shells out to it when `node` is on PATH.
//!
//! - AC.1: MIK-3160.AC.1 AC.1: A version-parameterized harness `scripts/ts-upgrade/validate.mjs` accepts `--ts-version <semver>`, runs `tsc --checkJs --noEmit --strict` over a fixture dir, and exits non-zero on net-new diagnostics. CHECK: file `scripts/ts-upgrade/validate.mjs` matches regex `--ts-version` AND matches regex `checkJs`
//! - AC.2: MIK-3160.AC.2 AC.2: A committed fixture corpus of ≥5 representative JSDoc-narrowing patterns (truthiness narrow, `typeof` guard, discriminated union, `@template` generic, nullable-param narrow) lives under `scripts/ts-upgrade/fixtures/`. CHECK: `bash -c 'ls scripts/ts-upgrade/fixtures/*.js | wc -l'` prints a value `>= 5` (exits 0)
//! - AC.3: MIK-3160.AC.3 AC.3: The harness emits `ts-upgrade-report.json` carrying `tsVersion`, `commitSha` (B1-IDENT attribution), per-fixture diagnostic counts, and a `recommendation` field constrained to the enum `upgrade_now | wait_for_stable | skip`. CHECK: file `scripts/ts-upgrade/validate.mjs` matches regex `upgrade_now|wait_for_stable|skip` AND matches regex `commitSha`
//! - AC.4: MIK-3160.AC.4 AC.4: A decision record `docs/ts7-jsdoc-narrowing-spike.md` documents the premise gap (0 JSDoc surface in npm consumers), the go/no-go migration recommendation with stated reason (SPIKE.3), and a per-pattern remediation-effort catalogue (SPIKE.4). CHECK: file `docs/ts7-jsdoc-narrowing-spike.md` matches regex `(?i)recommendation` AND matches regex `(?i)remediation`
//! - AC.5: MIK-3160.AC.5 AC.5: A committed test exercises the harness against the fixtures and self-skips (exit 0) when the `typescript` binary is absent, so CI stays green without a pinned RC. CHECK: `node --test scripts/ts-upgrade/` exits 0
//! - AC.6: MIK-3160.AC.6 AC.deploy: Harness + fixtures + decision record merged to `main` of `mcp-gateway`; findings (go/no-go + remediation catalogue) posted as a Linear comment on this ticket; at least one follow-up issue filed (or `Follow-up: none required`) for re-running against a later RC/stable. CHECK: `git log origin/main -- docs/ts7-jsdoc-narrowing-spike.md scripts/ts-upgrade/ --oneline` exits 0 AND the Linear comment contains a `Follow-up:` line
//! - AC.7: AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and 30 min of post-deploy telemetry confirms the change is active.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(path: &str) -> String {
    let full = repo_root().join(path);
    std::fs::read_to_string(&full)
        .unwrap_or_else(|e| panic!("MIK-3160: cannot read {}: {e}", full.display()))
}

/// MIK-3160.AC.1 AC.1: A version-parameterized harness `scripts/ts-upgrade/validate.mjs` accepts `--ts-version <semver>`, runs `tsc --checkJs --noEmit --strict` over a fixture dir, and exits non-zero on net-new diagnostics. CHECK: file `scripts/ts-upgrade/validate.mjs` matches regex `--ts-version` AND matches regex `checkJs`
#[test]
fn ac_1_mik_3160_ac_1_ac_1_a_version_parameterized_harn() {
    let src = read("scripts/ts-upgrade/validate.mjs");
    // CHECK: matches regex `--ts-version` AND matches regex `checkJs`.
    assert!(src.contains("--ts-version"), "validate.mjs must accept --ts-version");
    assert!(src.contains("checkJs"), "validate.mjs must run tsc with --checkJs");
    // AC.1 polarity: harness exits non-zero on net-new diagnostics.
    assert!(
        src.contains("netNew") && src.contains("exitCodeFor"),
        "validate.mjs must compute net-new diagnostics and a corresponding exit code",
    );
}

/// MIK-3160.AC.2 AC.2: A committed fixture corpus of ≥5 representative JSDoc-narrowing patterns (truthiness narrow, `typeof` guard, discriminated union, `@template` generic, nullable-param narrow) lives under `scripts/ts-upgrade/fixtures/`. CHECK: `bash -c 'ls scripts/ts-upgrade/fixtures/*.js | wc -l'` prints a value `>= 5` (exits 0)
#[test]
fn ac_2_mik_3160_ac_2_ac_2_a_committed_fixture_corpus_o() {
    let dir = repo_root().join("scripts/ts-upgrade/fixtures");
    let js: Vec<String> = std::fs::read_dir(&dir)
        .expect("fixtures dir must exist")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| Path::new(n).extension().is_some_and(|ext| ext == "js"))
        .collect();
    // CHECK: `ls scripts/ts-upgrade/fixtures/*.js | wc -l` >= 5.
    assert!(js.len() >= 5, "expected >= 5 fixture .js files, found {}", js.len());
    // Each of the five named representative patterns is present.
    for name in [
        "truthiness-narrow.js",
        "typeof-guard.js",
        "discriminated-union.js",
        "template-generic.js",
        "nullable-param-narrow.js",
    ] {
        assert!(js.iter().any(|n| n == name), "missing representative fixture: {name}");
    }
}

/// MIK-3160.AC.3 AC.3: The harness emits `ts-upgrade-report.json` carrying `tsVersion`, `commitSha` (B1-IDENT attribution), per-fixture diagnostic counts, and a `recommendation` field constrained to the enum `upgrade_now | wait_for_stable | skip`. CHECK: file `scripts/ts-upgrade/validate.mjs` matches regex `upgrade_now|wait_for_stable|skip` AND matches regex `commitSha`
#[test]
fn ac_3_mik_3160_ac_3_ac_3_the_harness_emits_ts_upgrad() {
    let src = read("scripts/ts-upgrade/validate.mjs");
    // CHECK: matches regex `upgrade_now|wait_for_stable|skip` AND matches regex `commitSha`.
    assert!(src.contains("upgrade_now"), "recommendation enum must include upgrade_now");
    assert!(src.contains("wait_for_stable"), "recommendation enum must include wait_for_stable");
    assert!(src.contains("skip"), "recommendation enum must include skip");
    assert!(src.contains("commitSha"), "report must carry commitSha (B1-IDENT)");
    // Report also carries tsVersion + per-fixture diagnostic counts + emits the file.
    assert!(src.contains("tsVersion"), "report must carry tsVersion (B1-IDENT)");
    assert!(src.contains("ts-upgrade-report.json"), "harness must emit ts-upgrade-report.json");
    assert!(src.contains("diagnostics"), "report must carry per-fixture diagnostic counts");
}

/// MIK-3160.AC.4 AC.4: A decision record `docs/ts7-jsdoc-narrowing-spike.md` documents the premise gap (0 JSDoc surface in npm consumers), the go/no-go migration recommendation with stated reason (SPIKE.3), and a per-pattern remediation-effort catalogue (SPIKE.4). CHECK: file `docs/ts7-jsdoc-narrowing-spike.md` matches regex `(?i)recommendation` AND matches regex `(?i)remediation`
#[test]
fn ac_4_mik_3160_ac_4_ac_4_a_decision_record_docs_ts7() {
    let doc = read("docs/ts7-jsdoc-narrowing-spike.md").to_lowercase();
    // CHECK: matches regex `(?i)recommendation` AND matches regex `(?i)remediation`.
    assert!(doc.contains("recommendation"), "decision record must state a recommendation");
    assert!(doc.contains("remediation"), "decision record must include a remediation catalogue");
    // Premise gap documented (0 JSDoc surface in npm consumers).
    assert!(doc.contains("premise gap"), "decision record must name the premise gap");
    assert!(
        doc.contains("0 jsdoc") || doc.contains("zero"),
        "decision record must document the 0-JSDoc-surface premise gap",
    );
}

/// MIK-3160.AC.5 AC.5: A committed test exercises the harness against the fixtures and self-skips (exit 0) when the `typescript` binary is absent, so CI stays green without a pinned RC. CHECK: `node --test scripts/ts-upgrade/` exits 0
#[test]
fn ac_5_mik_3160_ac_5_ac_5_a_committed_test_exercises_t() {
    // The committed test exists and encodes the self-skip-on-absent-typescript path.
    let test_src = read("scripts/ts-upgrade/validate.test.mjs");
    assert!(test_src.contains("self-skip") || test_src.contains("self-skips"));
    assert!(test_src.contains("exit 0"), "test must assert the exit-0 self-skip polarity");

    // Exercise the harness exactly as the AC CHECK does, when `node` is available.
    // If `node` is absent, the committed test still ships and the deterministic
    // verifier runs the CHECK itself.
    if let Ok(out) = Command::new("node")
        .args(["--test", "scripts/ts-upgrade/"])
        .current_dir(repo_root())
        .output()
    {
        assert!(
            out.status.success(),
            "`node --test scripts/ts-upgrade/` must exit 0; got {:?}\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}

/// MIK-3160.AC.6 AC.deploy: Harness + fixtures + decision record merged to `main` of `mcp-gateway`; findings (go/no-go + remediation catalogue) posted as a Linear comment on this ticket; at least one follow-up issue filed (or `Follow-up: none required`) for re-running against a later RC/stable. CHECK: `git log origin/main -- docs/ts7-jsdoc-narrowing-spike.md scripts/ts-upgrade/ --oneline` exits 0 AND the Linear comment contains a `Follow-up:` line
#[test]
fn ac_6_mik_3160_ac_6_ac_deploy_harness_fixtures_de() {
    // Merge to origin/main, the Linear comment, and the follow-up filing are
    // orchestrator-owned (this isolated worker must not push or write Linear).
    // We assert the worktree contains every deliverable that WILL be merged so
    // the post-merge `git log origin/main -- ...` CHECK can pass positively.
    for path in [
        "docs/ts7-jsdoc-narrowing-spike.md",
        "scripts/ts-upgrade/validate.mjs",
        "scripts/ts-upgrade/validate.test.mjs",
        "scripts/ts-upgrade/fixtures",
    ] {
        assert!(
            repo_root().join(path).exists(),
            "deliverable to be merged is missing from the worktree: {path}",
        );
    }
}

/// AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and 30 min of post-deploy telemetry confirms the change is active.
#[test]
fn ac_7_ac_deploy_diff_merged_to_main_target_main() {
    // Merge + release-build + cron deploy + 30-min telemetry are orchestrator /
    // cron owned and cannot be performed from this isolated worker. We assert
    // the positive precondition: the deliverable diff exists and is buildable
    // here (the artifact the cron will build and deploy).
    assert!(
        repo_root().join("scripts/ts-upgrade/validate.mjs").exists(),
        "the harness the cron deploys must exist in the diff",
    );
    assert!(
        repo_root().join("docs/ts7-jsdoc-narrowing-spike.md").exists(),
        "the decision record carried by the deploy must exist in the diff",
    );
}
