#!/opt/homebrew/bin/node
// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  readJson,
  sha256File,
  verifyInstalledRuntime,
  verifyLockGraph,
  verifyToolchain,
} from "./lib/runtime.mjs";

const BUNDLE_ROOT = path.dirname(fileURLToPath(import.meta.url));

function argument(argv, name) {
  const index = argv.indexOf(name);
  if (index < 0 || !argv[index + 1]) throw new Error(`missing ${name}`);
  return argv[index + 1];
}

export async function verifyEvidence(evidenceRoot) {
  if (!path.isAbsolute(evidenceRoot)) throw new Error("evidence root must be absolute");

  const manifest = await readJson(path.join(BUNDLE_ROOT, "package.json"));
  const lock = await readJson(path.join(BUNDLE_ROOT, "package-lock.json"));
  const pins = await readJson(path.join(BUNDLE_ROOT, "pins.json"));
  const recorded = await readJson(path.join(evidenceRoot, "verification.json"));
  if (recorded.verified !== true) throw new Error("bootstrap evidence is not marked verified");
  if (
    recorded.publish_plan?.publish_performed !== false ||
    recorded.activation_plan?.gateway_configuration_changed !== false
  ) {
    throw new Error("bootstrap evidence does not preserve the no-deployment boundary");
  }
  verifyLockGraph({ manifest, lock, pins });

  const sourceHashes = {
    package_json: await sha256File(path.join(BUNDLE_ROOT, "package.json")),
    package_lock_json: await sha256File(path.join(BUNDLE_ROOT, "package-lock.json")),
    pins_json: await sha256File(path.join(BUNDLE_ROOT, "pins.json")),
  };
  if (JSON.stringify(sourceHashes) !== JSON.stringify(recorded.source_hashes)) {
    throw new Error("reviewed source inputs differ from bootstrap evidence");
  }

  await verifyToolchain(pins, {
    home: path.join(evidenceRoot, "toolchain-home"),
    tmpdir: path.join(evidenceRoot, "toolchain-tmp"),
  });
  const installA = path.join(evidenceRoot, "install-a");
  const installB = path.join(evidenceRoot, "install-b");
  if (
    recorded.installs?.a?.paths?.install !== installA ||
    recorded.installs?.b?.paths?.install !== installB
  ) {
    throw new Error("recorded install paths do not match the evidence root");
  }

  const verifiedA = await verifyInstalledRuntime({ installRoot: installA, manifest, lock, pins });
  const verifiedB = await verifyInstalledRuntime({ installRoot: installB, manifest, lock, pins });
  if (
    verifiedA.tree_digest !== verifiedB.tree_digest ||
    verifiedA.tree_digest !== recorded.tree_digest
  ) {
    throw new Error("retained install digests do not match bootstrap evidence");
  }

  const smoke = await readJson(path.join(evidenceRoot, "smoke.json"));
  const evidenceHashes = {
    npm_audit_json: await sha256File(path.join(evidenceRoot, "npm-audit.json")),
    smoke_json: await sha256File(path.join(evidenceRoot, "smoke.json")),
  };
  if (JSON.stringify(evidenceHashes) !== JSON.stringify(recorded.evidence_hashes)) {
    throw new Error("retained smoke or audit evidence differs from bootstrap verification");
  }
  const expectedBackends = Object.keys(pins.packages).sort();
  const successfulBackends = (smoke.backends ?? [])
    .filter((entry) => entry.success)
    .map((entry) => entry.backend)
    .sort();
  if (JSON.stringify(expectedBackends) !== JSON.stringify(successfulBackends)) {
    throw new Error("retained smoke evidence does not cover all pinned backends");
  }

  const audit = await readJson(path.join(evidenceRoot, "npm-audit.json"));
  if (!audit.metadata?.vulnerabilities || audit.error) {
    throw new Error("retained npm audit evidence is not a successful audit response");
  }

  return {
    verified: true,
    tree_digest: verifiedA.tree_digest,
    installed_package_count: verifiedA.installed_package_count,
    smoke_backends: successfulBackends,
    audit_vulnerabilities: audit.metadata.vulnerabilities,
    publish_performed: false,
    activation_performed: false,
    pins,
  };
}

async function main() {
  const evidenceRoot = argument(process.argv.slice(2), "--evidence");
  const result = await verifyEvidence(evidenceRoot);
  const { pins: _pins, ...summary } = result;
  console.log(JSON.stringify(summary));
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    console.error(`verify-runtime: ${error.message}`);
    process.exitCode = 1;
  });
}
