// @ts-check
//
// MIK-3160 — committed test exercising the ts-upgrade harness against the
// fixtures. Discovered by `node --test scripts/ts-upgrade/`.
//
// Acceptance criteria pinned here (verbatim from the ticket):
//
// AC.1: A version-parameterized harness `scripts/ts-upgrade/validate.mjs`
//   accepts `--ts-version <semver>`, runs `tsc --checkJs --noEmit --strict`
//   over a fixture dir, and exits non-zero on net-new diagnostics.
// AC.2: A committed fixture corpus of >=5 representative JSDoc-narrowing
//   patterns (truthiness narrow, `typeof` guard, discriminated union,
//   `@template` generic, nullable-param narrow) lives under
//   `scripts/ts-upgrade/fixtures/`.
// AC.3: The harness emits `ts-upgrade-report.json` carrying `tsVersion`,
//   `commitSha` (B1-IDENT attribution), per-fixture diagnostic counts, and a
//   `recommendation` field constrained to the enum
//   `upgrade_now | wait_for_stable | skip`.
// AC.5: A committed test exercises the harness against the fixtures and
//   self-skips (exit 0) when the `typescript` binary is absent, so CI stays
//   green without a pinned RC.

import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  parseArgs,
  findTsc,
  listFixtures,
  runValidation,
  writeReport,
  exitCodeFor,
  RECOMMENDATIONS,
} from "./validate.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(HERE, "fixtures");

// AC.2: >=5 representative JSDoc-narrowing patterns live under fixtures/.
test("AC.2: fixture corpus has >= 5 JSDoc-narrowing patterns", () => {
  const files = listFixtures(fixturesDir);
  assert.ok(files.length >= 5, `expected >= 5 fixtures, got ${files.length}`);
  // The five named patterns are each represented by a file.
  for (const name of [
    "truthiness-narrow.js",
    "typeof-guard.js",
    "discriminated-union.js",
    "template-generic.js",
    "nullable-param-narrow.js",
  ]) {
    assert.ok(files.includes(name), `missing fixture: ${name}`);
  }
});

// AC.1: the harness accepts `--ts-version <semver>`.
test("AC.1: --ts-version <semver> is parsed", () => {
  const a = parseArgs(["--ts-version", "7.0.0-beta"]);
  assert.equal(a.tsVersion, "7.0.0-beta");
  const b = parseArgs(["--ts-version=7.1.0"]);
  assert.equal(b.tsVersion, "7.1.0");
});

// AC.3: report carries tsVersion, commitSha, per-fixture counts, enum recommendation.
test("AC.3: report carries tsVersion, commitSha, per-fixture counts, enum recommendation", () => {
  const report = runValidation({ tsVersion: "7.0.0-test", fixturesDir });
  assert.equal(report.tsVersion, "7.0.0-test");
  assert.match(report.commitSha, /^[0-9a-f]{7,40}$|^unknown$/);
  assert.ok(Array.isArray(report.fixtures) && report.fixtures.length >= 5);
  for (const f of report.fixtures) {
    assert.ok("diagnostics" in f, "each fixture entry has a diagnostic count");
  }
  assert.ok(
    Object.values(RECOMMENDATIONS).includes(report.recommendation),
    `recommendation "${report.recommendation}" must be in the enum`,
  );
});

// AC.5: self-skips (exit 0) when the `typescript` binary is absent.
test("AC.5: self-skips with exit 0 when typescript binary is absent", () => {
  const report = runValidation({
    tsVersion: "7.0.0-test",
    fixturesDir,
    tscBin: null, // simulate absent typescript binary
  });
  assert.equal(report.skipped, true);
  assert.equal(report.recommendation, RECOMMENDATIONS.SKIP);
  assert.equal(exitCodeFor(report), 0, "self-skip must exit 0 to keep CI green");
});

// AC.1/AC.3: when typescript IS present, exercise the real compiler over fixtures.
test("AC.1/AC.3: exercises tsc over fixtures when typescript is present", (t) => {
  const tscBin = findTsc();
  if (!tscBin) {
    t.skip("typescript not installed; self-skip path is covered above");
    return;
  }
  const report = runValidation({ tsVersion: null, fixturesDir, tscBin });
  assert.ok(report.fixtures.every((f) => typeof f.diagnostics === "number"));
  // Exit code is non-zero iff there are net-new diagnostics (AC.1 polarity).
  assert.equal(exitCodeFor(report), report.totals.netNew > 0 ? 1 : 0);
});

// AC.3: writeReport emits ts-upgrade-report.json (written to tmp to keep the tree clean).
test("AC.3: writeReport emits ts-upgrade-report.json", () => {
  const out = path.join(tmpdir(), `ts-upgrade-report.${process.pid}.json`);
  const report = runValidation({ tsVersion: "7.0.0-test", fixturesDir, tscBin: null });
  writeReport(report, out);
  assert.ok(existsSync(out));
  rmSync(out, { force: true });
});
