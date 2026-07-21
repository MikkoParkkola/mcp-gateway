#!/opt/homebrew/bin/node
// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { writeFile } from "node:fs/promises";
import path from "node:path";

import { renderGatewayConfig } from "./lib/runtime.mjs";
import { verifyEvidence } from "./verify-runtime.mjs";

function argument(argv, name, required = true) {
  const index = argv.indexOf(name);
  if (index < 0 || !argv[index + 1]) {
    if (required) throw new Error(`missing ${name}`);
    return undefined;
  }
  return argv[index + 1];
}

async function main() {
  const argv = process.argv.slice(2);
  const evidenceRoot = argument(argv, "--evidence");
  const output = argument(argv, "--output", false);
  if (!path.isAbsolute(evidenceRoot)) throw new Error("evidence root must be absolute");
  if (output && !path.isAbsolute(output)) throw new Error("output path must be absolute");
  if (output && path.dirname(output) !== evidenceRoot) {
    throw new Error("output must remain directly inside the verified evidence root");
  }

  const evidence = await verifyEvidence(evidenceRoot);
  const installRoot = path.join(evidence.pins.publish_root, evidence.tree_digest);
  const rendered = renderGatewayConfig({
    nodePath: evidence.pins.toolchain.node.path,
    installRoot,
    pins: evidence.pins,
  });
  if (output) {
    await writeFile(output, rendered, { flag: "wx", mode: 0o600 });
  } else {
    process.stdout.write(rendered);
  }
}

main().catch((error) => {
  console.error(`render-config: ${error.message}`);
  process.exitCode = 1;
});
