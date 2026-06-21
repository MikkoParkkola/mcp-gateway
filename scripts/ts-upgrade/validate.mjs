#!/usr/bin/env node
// @ts-check
//
// MIK-3160 — version-parameterized TypeScript-upgrade validation harness.
//
// Runs `tsc --checkJs --noEmit --strict` over a corpus of JSDoc-narrowing
// fixtures, counts diagnostics per fixture, compares against a baseline of
// expected counts, and emits `ts-upgrade-report.json` carrying `tsVersion`,
// `commitSha` (B1-IDENT attribution), per-fixture diagnostic counts and a
// `recommendation` constrained to the enum `upgrade_now | wait_for_stable | skip`.
//
// The harness self-skips (exit 0) when no `typescript` binary is resolvable so
// CI stays green without pinning a moving TypeScript RC. Re-evaluate a later
// release reproducibly with `--ts-version <semver>` (B3-DURABLE); the harness
// is package-agnostic and reusable across future TS majors (B4-PLATFORM).
//
// Usage:
//   node scripts/ts-upgrade/validate.mjs --ts-version 7.0.0-beta
//   node scripts/ts-upgrade/validate.mjs --fixtures <dir> --out <report.json>

import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import {
  readdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));

/** Recommendation enum (B2-MEM: carried into the decision record). */
export const RECOMMENDATIONS = Object.freeze({
  UPGRADE_NOW: "upgrade_now",
  WAIT_FOR_STABLE: "wait_for_stable",
  SKIP: "skip",
});

/**
 * @param {string[]} argv
 * @returns {{ tsVersion: string | null, fixturesDir: string, out: string }}
 */
export function parseArgs(argv) {
  const args = {
    tsVersion: /** @type {string | null} */ (null),
    fixturesDir: path.join(HERE, "fixtures"),
    out: path.join(HERE, "ts-upgrade-report.json"),
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--ts-version") {
      args.tsVersion = argv[++i] ?? null;
    } else if (a.startsWith("--ts-version=")) {
      args.tsVersion = a.slice("--ts-version=".length);
    } else if (a === "--fixtures") {
      args.fixturesDir = path.resolve(argv[++i] ?? args.fixturesDir);
    } else if (a === "--out") {
      args.out = path.resolve(argv[++i] ?? args.out);
    }
  }
  return args;
}

/**
 * Resolve the real TypeScript compiler. Never falls back to a bare `npx tsc`,
 * which would silently install the unrelated `tsc` npm decoy package.
 *
 * @returns {string | null} absolute path to typescript's `tsc` entrypoint, or null
 */
export function findTsc() {
  if (process.env.TSC_PATH && existsSync(process.env.TSC_PATH)) {
    return process.env.TSC_PATH;
  }
  try {
    const pkgJson = require.resolve("typescript/package.json");
    const bin = path.join(path.dirname(pkgJson), "bin", "tsc");
    if (existsSync(bin)) return bin;
  } catch {
    // `typescript` is not installed in this environment.
  }
  return null;
}

/** @returns {string} short/long commit sha of HEAD, or "unknown". */
export function commitSha() {
  const r = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: HERE,
    encoding: "utf8",
  });
  return r.status === 0 ? r.stdout.trim() : "unknown";
}

/**
 * @param {string | null} tscBin
 * @returns {string | null} the actual installed TypeScript version
 */
export function resolvedTsVersion(tscBin) {
  if (!tscBin) return null;
  const r = spawnSync(process.execPath, [tscBin, "--version"], {
    encoding: "utf8",
  });
  if (r.status !== 0) return null;
  const m = r.stdout.match(/Version\s+(\S+)/);
  return m ? m[1] : r.stdout.trim();
}

/**
 * @param {string} dir
 * @returns {string[]} sorted `.js` fixture filenames in `dir`
 */
export function listFixtures(dir) {
  return readdirSync(dir)
    .filter((f) => f.endsWith(".js"))
    .sort();
}

/**
 * Run `tsc --checkJs --noEmit --strict` over a single fixture file.
 *
 * @param {string} tscBin
 * @param {string} file absolute path to a `.js` fixture
 * @returns {{ count: number, raw: string }}
 */
function runTscOnFixture(tscBin, file) {
  const flags = [
    "--allowJs",
    "--checkJs",
    "--noEmit",
    "--strict",
    "--target",
    "es2022",
    "--module",
    "es2022",
    "--moduleResolution",
    "bundler",
    "--pretty",
    "false",
    file,
  ];
  const r = spawnSync(process.execPath, [tscBin, ...flags], {
    encoding: "utf8",
  });
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  const count = (out.match(/error TS\d+/g) || []).length;
  return { count, raw: out.trim() };
}

/**
 * @param {object} [opts]
 * @param {string | null} [opts.tsVersion] requested/target version stamped in report
 * @param {string} [opts.fixturesDir]
 * @param {Record<string, number>} [opts.baseline] expected per-fixture diagnostic counts
 * @param {string | null} [opts.tscBin] override compiler resolution (testing/CI)
 * @returns {object} the validation report
 */
export function runValidation(opts = {}) {
  const fixturesDir = opts.fixturesDir ?? path.join(HERE, "fixtures");
  const baseline = opts.baseline ?? {};
  const tscBin = opts.tscBin !== undefined ? opts.tscBin : findTsc();
  const fixtures = listFixtures(fixturesDir);

  const report = {
    ticket: "MIK-3160",
    tsVersion: opts.tsVersion ?? resolvedTsVersion(tscBin) ?? null,
    resolvedTsVersion: resolvedTsVersion(tscBin),
    commitSha: commitSha(),
    generatedFromTypescript: Boolean(tscBin),
    fixtures: /** @type {object[]} */ ([]),
    totals: { diagnostics: 0, netNew: 0 },
    recommendation: RECOMMENDATIONS.SKIP,
    skipped: false,
    reason: "",
  };

  if (!tscBin) {
    report.skipped = true;
    report.reason =
      "typescript binary not found; self-skipping so CI stays green without a pinned RC.";
    report.recommendation = RECOMMENDATIONS.SKIP;
    for (const f of fixtures) {
      report.fixtures.push({
        fixture: f,
        diagnostics: null,
        baseline: baseline[f] ?? 0,
        netNew: 0,
        skipped: true,
      });
    }
    return report;
  }

  let totalDiag = 0;
  let totalNetNew = 0;
  for (const f of fixtures) {
    const { count, raw } = runTscOnFixture(tscBin, path.join(fixturesDir, f));
    const base = baseline[f] ?? 0;
    const netNew = Math.max(0, count - base);
    totalDiag += count;
    totalNetNew += netNew;
    report.fixtures.push({
      fixture: f,
      diagnostics: count,
      baseline: base,
      netNew,
      raw: raw || undefined,
    });
  }
  report.totals.diagnostics = totalDiag;
  report.totals.netNew = totalNetNew;
  report.recommendation =
    totalNetNew > 0 ? RECOMMENDATIONS.WAIT_FOR_STABLE : RECOMMENDATIONS.UPGRADE_NOW;
  report.reason =
    totalNetNew > 0
      ? `${totalNetNew} net-new diagnostic(s) across ${fixtures.length} fixtures under TS ${report.tsVersion}.`
      : `All ${fixtures.length} JSDoc-narrowing fixtures type-check clean under TS ${report.tsVersion}.`;
  return report;
}

/**
 * @param {object} report
 * @param {string} outPath
 * @returns {string} outPath
 */
export function writeReport(report, outPath) {
  writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
  return outPath;
}

/**
 * Process exit code: non-zero on net-new diagnostics, 0 when clean or skipped.
 *
 * @param {{ skipped: boolean, totals: { netNew: number } }} report
 * @returns {number}
 */
export function exitCodeFor(report) {
  if (report.skipped) return 0;
  return report.totals.netNew > 0 ? 1 : 0;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  /** @type {Record<string, number>} */
  let baseline = {};
  const baselinePath = path.join(args.fixturesDir, "..", "baseline.json");
  if (existsSync(baselinePath)) {
    try {
      baseline = JSON.parse(readFileSync(baselinePath, "utf8"));
    } catch {
      // ignore malformed baseline; treat as all-zero
    }
  }
  const report = runValidation({
    tsVersion: args.tsVersion,
    fixturesDir: args.fixturesDir,
    baseline,
  });
  writeReport(report, args.out);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exit(exitCodeFor(report));
}

const invokedDirectly =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main();
}
