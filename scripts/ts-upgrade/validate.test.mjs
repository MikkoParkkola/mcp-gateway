import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const harness = join(here, "validate.mjs");

test("skips when the typescript binary is absent", () => {
  const out = join(mkdtempSync(join(tmpdir(), "ts-upgrade-")), "ts-upgrade-report.json");
  const run = spawnSync(process.execPath, [harness, "--ts-version", "7.0.0-rc", "--out", out], {
    encoding: "utf8",
    env: { ...process.env, TSC: "tsc-not-installed-mik3160" },
  });
  if (run.status !== 0) {
    throw new Error(run.stderr || run.stdout || "harness failed closed without tsc");
  }
  const report = JSON.parse(readFileSync(out, "utf8"));
  if (report.recommendation !== "skip" || !report.commitSha) {
    throw new Error(JSON.stringify(report));
  }
});

test("checks fixtures when tsc is present", () => {
  const probe = spawnSync("tsc", ["--version"], { encoding: "utf8" });
  if (probe.status !== 0) return;
  const out = join(mkdtempSync(join(tmpdir(), "ts-upgrade-")), "ts-upgrade-report.json");
  const run = spawnSync(
    process.execPath,
    [harness, "--ts-version", "5.9.0", "--out", out],
    { encoding: "utf8" },
  );
  if (run.status !== 0) {
    throw new Error(run.stderr || run.stdout || "fixtures failed");
  }
  const report = JSON.parse(readFileSync(out, "utf8"));
  if (report.fixtures.length < 5 || report.recommendation !== "upgrade_now") {
    throw new Error(JSON.stringify(report));
  }
});
