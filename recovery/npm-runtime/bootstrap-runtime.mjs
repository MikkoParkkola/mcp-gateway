#!/opt/homebrew/bin/node
// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { spawnSync } from "node:child_process";
import { copyFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildIsolatedEnvironment,
  createExclusiveDirectory,
  readJson,
  sha256File,
  verifyInstalledRuntime,
  verifyLockGraph,
  verifyToolchain,
} from "./lib/runtime.mjs";
import { smokeRuntime } from "./smoke-runtime.mjs";

const BUNDLE_ROOT = path.dirname(fileURLToPath(import.meta.url));
const REGISTRY = "https://registry.npmjs.org/";
const MAX_OUTPUT = 8 * 1024 * 1024;

async function writeJsonExclusive(file, value) {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: 0o600 });
}

async function makeAttemptDirectories(evidenceRoot, suffix) {
  const values = {
    install: path.join(evidenceRoot, `install-${suffix}`),
    cache: path.join(evidenceRoot, `cache-${suffix}`),
    home: path.join(evidenceRoot, `home-${suffix}`),
    tmpdir: path.join(evidenceRoot, `tmp-${suffix}`),
    config: path.join(evidenceRoot, `config-${suffix}`),
  };
  for (const directory of Object.values(values)) await createExclusiveDirectory(directory);
  values.userconfig = path.join(values.config, "user.npmrc");
  values.globalconfig = path.join(values.config, "global.npmrc");
  await writeFile(values.userconfig, "", { flag: "wx", mode: 0o600 });
  await writeFile(values.globalconfig, "", { flag: "wx", mode: 0o600 });
  return values;
}

async function copyReviewedInputs(installRoot) {
  await copyFile(path.join(BUNDLE_ROOT, "package.json"), path.join(installRoot, "package.json"));
  await copyFile(
    path.join(BUNDLE_ROOT, "package-lock.json"),
    path.join(installRoot, "package-lock.json"),
  );
}

async function recordCommandOutput(evidenceRoot, label, result) {
  await writeFile(path.join(evidenceRoot, `${label}.stdout.txt`), result.stdout ?? "", {
    flag: "wx",
    mode: 0o600,
  });
  await writeFile(path.join(evidenceRoot, `${label}.stderr.txt`), result.stderr ?? "", {
    flag: "wx",
    mode: 0o600,
  });
}

function npmArguments(pins, operation, attempt) {
  return [
    pins.toolchain.npm.resolved_path,
    operation,
    "--ignore-scripts",
    "--no-fund",
    `--cache=${attempt.cache}`,
    `--userconfig=${attempt.userconfig}`,
    `--globalconfig=${attempt.globalconfig}`,
    `--registry=${REGISTRY}`,
    "--install-strategy=hoisted",
    "--include=optional",
    "--foreground-scripts=false",
    "--update-notifier=false",
    "--loglevel=warn",
  ];
}

async function runNpmCi({ pins, attempt, evidenceRoot, label }) {
  const result = spawnSync(
    pins.toolchain.node.path,
    [...npmArguments(pins, "ci", attempt), "--no-audit"],
    {
      cwd: attempt.install,
      encoding: "utf8",
      env: buildIsolatedEnvironment({ home: attempt.home, tmpdir: attempt.tmpdir }),
      maxBuffer: MAX_OUTPUT,
      timeout: 180_000,
    },
  );
  await recordCommandOutput(evidenceRoot, `npm-ci-${label}`, result);
  if (result.error || result.status !== 0) {
    throw new Error(`npm ci ${label} failed; retained bounded output in evidence`);
  }
}

async function runNpmAudit({ pins, attempt, evidenceRoot }) {
  const result = spawnSync(
    pins.toolchain.node.path,
    [...npmArguments(pins, "audit", attempt), "--json", "--omit=dev"],
    {
      cwd: attempt.install,
      encoding: "utf8",
      env: buildIsolatedEnvironment({ home: attempt.home, tmpdir: attempt.tmpdir }),
      maxBuffer: MAX_OUTPUT,
      timeout: 120_000,
    },
  );
  await writeFile(path.join(evidenceRoot, "npm-audit.json"), result.stdout ?? "", {
    flag: "wx",
    mode: 0o600,
  });
  await writeFile(path.join(evidenceRoot, "npm-audit.stderr.txt"), result.stderr ?? "", {
    flag: "wx",
    mode: 0o600,
  });
  if (result.error) throw new Error("npm audit process failed; retained output in evidence");

  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    throw new Error("npm audit returned non-JSON output; retained output in evidence");
  }
  if (!report.metadata?.vulnerabilities || report.error) {
    throw new Error("npm audit registry/authentication request failed; retained report in evidence");
  }
  if (![0, 1].includes(result.status)) {
    throw new Error(`npm audit failed with unexpected exit status ${result.status}`);
  }
  return {
    exit_status: result.status,
    vulnerabilities: report.metadata.vulnerabilities,
    dependency_counts: report.metadata.dependencies ?? null,
    fix_invoked: false,
  };
}

function argument(argv, name) {
  const index = argv.indexOf(name);
  if (index < 0 || !argv[index + 1]) throw new Error(`missing ${name}`);
  return argv[index + 1];
}

async function main() {
  const evidenceRoot = argument(process.argv.slice(2), "--evidence");
  if (!path.isAbsolute(evidenceRoot)) throw new Error("evidence root must be absolute");

  let evidenceCreated = false;
  let phase = "create-evidence";
  try {
    await createExclusiveDirectory(evidenceRoot);
    evidenceCreated = true;
    await writeJsonExclusive(path.join(evidenceRoot, "bootstrap-state.json"), {
      schema_version: 1,
      state: "started",
      evidence_root: evidenceRoot,
      cleanup_policy: "preserve-on-success-and-failure",
      publish_performed: false,
      activation_performed: false,
    });

    phase = "create-isolated-roots";
    const attemptA = await makeAttemptDirectories(evidenceRoot, "a");
    const attemptB = await makeAttemptDirectories(evidenceRoot, "b");
    const toolchainHome = path.join(evidenceRoot, "toolchain-home");
    const toolchainTmp = path.join(evidenceRoot, "toolchain-tmp");
    const smokeHome = path.join(evidenceRoot, "smoke-home");
    const smokeTmp = path.join(evidenceRoot, "smoke-tmp");
    const smokeCwd = path.join(evidenceRoot, "smoke-cwd");
    for (const directory of [toolchainHome, toolchainTmp, smokeHome, smokeTmp, smokeCwd]) {
      await createExclusiveDirectory(directory);
    }

    phase = "verify-reviewed-inputs";
    const manifest = await readJson(path.join(BUNDLE_ROOT, "package.json"));
    const lock = await readJson(path.join(BUNDLE_ROOT, "package-lock.json"));
    const pins = await readJson(path.join(BUNDLE_ROOT, "pins.json"));
    verifyLockGraph({ manifest, lock, pins });
    const sourceHashes = {
      package_json: await sha256File(path.join(BUNDLE_ROOT, "package.json")),
      package_lock_json: await sha256File(path.join(BUNDLE_ROOT, "package-lock.json")),
      pins_json: await sha256File(path.join(BUNDLE_ROOT, "pins.json")),
    };
    const toolchain = await verifyToolchain(pins, { home: toolchainHome, tmpdir: toolchainTmp });

    phase = "install-a";
    await copyReviewedInputs(attemptA.install);
    await runNpmCi({ pins, attempt: attemptA, evidenceRoot, label: "a" });
    const firstA = await verifyInstalledRuntime({
      installRoot: attemptA.install,
      manifest,
      lock,
      pins,
    });

    phase = "install-b";
    await copyReviewedInputs(attemptB.install);
    await runNpmCi({ pins, attempt: attemptB, evidenceRoot, label: "b" });
    const firstB = await verifyInstalledRuntime({
      installRoot: attemptB.install,
      manifest,
      lock,
      pins,
    });
    if (firstA.tree_digest !== firstB.tree_digest) {
      throw new Error("independent npm installs produced different canonical tree digests");
    }

    phase = "audit";
    const audit = await runNpmAudit({ pins, attempt: attemptA, evidenceRoot });

    phase = "smoke";
    const smoke = await smokeRuntime({
      installRoot: attemptA.install,
      home: smokeHome,
      tmpdir: smokeTmp,
      cwd: smokeCwd,
      pins,
    });
    await writeJsonExclusive(path.join(evidenceRoot, "smoke.json"), smoke);

    phase = "post-smoke-reverification";
    const finalA = await verifyInstalledRuntime({
      installRoot: attemptA.install,
      manifest,
      lock,
      pins,
    });
    const finalB = await verifyInstalledRuntime({
      installRoot: attemptB.install,
      manifest,
      lock,
      pins,
    });
    if (
      finalA.tree_digest !== firstA.tree_digest ||
      finalB.tree_digest !== firstB.tree_digest ||
      finalA.tree_digest !== finalB.tree_digest
    ) {
      throw new Error("runtime tree changed during audit or smoke verification");
    }

    phase = "write-verification";
    const destination = path.join(pins.publish_root, finalA.tree_digest);
    const evidenceHashes = {
      npm_audit_json: await sha256File(path.join(evidenceRoot, "npm-audit.json")),
      smoke_json: await sha256File(path.join(evidenceRoot, "smoke.json")),
    };
    await writeJsonExclusive(path.join(evidenceRoot, "verification.json"), {
      schema_version: 1,
      verified: true,
      platform: pins.platform,
      registry: REGISTRY,
      npm_flags: npmArguments(pins, "ci", attemptA).slice(2),
      source_hashes: sourceHashes,
      evidence_hashes: evidenceHashes,
      toolchain,
      tree_digest: finalA.tree_digest,
      installs: {
        a: { paths: attemptA, verification: finalA },
        b: { paths: attemptB, verification: finalB },
      },
      determinism_scope: "two clean installs on the pinned darwin/arm64 host",
      audit,
      smoke_summary: smoke.backends.map(({ backend, success, tool_count }) => ({
        backend,
        success,
        tool_count,
      })),
      publish_plan: {
        destination,
        method:
          "permission-sealed object, atomic exclusive digest symlink, and post-publication verification on the same filesystem",
        refuse_existing_destination: true,
        requires_object_inside_publish_root: true,
        removes_write_bits_before_publication: true,
        reverifies_alias_seal_symlinks_and_digest_after_publication: true,
        trust_boundary: "no hostile or uncoordinated writers running as the object owner",
        publish_performed: false,
      },
      activation_plan: {
        generated_commands_pin_literal_digest: true,
        current_symlink_switched: false,
        gateway_configuration_changed: false,
      },
      rollback_plan:
        "Retain prior digest directory and select its reviewed snippet in a separately authorized deployment.",
    });
    console.log(
      JSON.stringify({ verified: true, tree_digest: finalA.tree_digest, evidence: evidenceRoot }),
    );
  } catch (error) {
    if (evidenceCreated) {
      await writeJsonExclusive(path.join(evidenceRoot, "failure.json"), {
        verified: false,
        phase,
        error: error.message,
        evidence_preserved: true,
      }).catch(() => {});
    }
    throw error;
  }
}

main().catch((error) => {
  console.error(`bootstrap-runtime: ${error.message}`);
  process.exitCode = 1;
});
