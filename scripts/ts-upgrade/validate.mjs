#!/usr/bin/env node
// Version-parameterized JSDoc check. --ts-version is the compiler this run
// claims to test. tsc is taken from PATH (or TSC). The report records that
// binary's version, and recommendation is skip when the two differ.
// checkJs --noEmit --strict is the gate. Missing tsc writes recommendation
// skip and exits 0 unless --require-tsc.
import { spawnSync, execSync } from "node:child_process";
import { readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] || "" : "";
}

const tsVersion = arg("--ts-version") || "unspecified";
const fixturesDir = arg("--fixtures") || join(here, "fixtures");
const outPath = arg("--out") || "ts-upgrade-report.json";
const tsc = process.env.TSC || "tsc";

function commitSha() {
  try {
    return execSync("git rev-parse HEAD", { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}

function versionOf(text) {
  const match = String(text).match(/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/);
  return match ? match[1] : "";
}

function recommendation(diagnosticCount, version) {
  if (diagnosticCount > 0) return "skip";
  if (/rc|beta|alpha|dev/i.test(version)) return "wait_for_stable";
  return "upgrade_now";
}

const files = readdirSync(fixturesDir).filter((name) => name.endsWith(".js")).sort();
const probe = spawnSync(tsc, ["--version"], { encoding: "utf8" });
const perFixture = [];

if (probe.status !== 0) {
  const report = {
    tsVersion,
    commitSha: commitSha(),
    fixtures: perFixture,
    recommendation: "skip",
  };
  writeFileSync(outPath, JSON.stringify(report, null, 2));
  process.exit(process.argv.includes("--require-tsc") ? 1 : 0);
}

let diagnostics = 0;
for (const name of files) {
  const run = spawnSync(
    tsc,
    ["--checkJs", "--noEmit", "--strict", "--allowJs", "--target", "ES2022", join(fixturesDir, name)],
    { encoding: "utf8" },
  );
  const text = `${run.stdout || ""}${run.stderr || ""}`;
  const count = run.status === 0 ? 0 : text.split("\n").filter((line) => line.includes("error TS")).length || 1;
  diagnostics += count;
  perFixture.push({ file: name, diagnostics: count });
}

const compilerVersion = versionOf(`${probe.stdout || ""}${probe.stderr || ""}`);
let verdict = recommendation(diagnostics, compilerVersion || tsVersion);
if (tsVersion !== "unspecified" && compilerVersion !== tsVersion) verdict = "skip";
const report = {
  tsVersion,
  compilerVersion,
  commitSha: commitSha(),
  fixtures: perFixture,
  recommendation: verdict,
};
writeFileSync(outPath, JSON.stringify(report, null, 2));
if (diagnostics > 0) process.exit(1);
