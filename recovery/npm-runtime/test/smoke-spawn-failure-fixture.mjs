// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { mkdir, mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { smokeRuntime } from "../smoke-runtime.mjs";

const root = await mkdtemp(path.join(os.tmpdir(), "npm-runtime-spawn-failure-child-"));
const home = path.join(root, "home");
const tmpdir = path.join(root, "tmp");
const cwd = path.join(root, "cwd");
for (const directory of [home, tmpdir, cwd]) await mkdir(directory);

const pins = {
  toolchain: { node: { path: path.join(root, "missing-node") } },
  packages: {
    broken: {
      package: "@example/missing",
      entrypoint: "dist/index.js",
      args: [],
    },
  },
};

try {
  await smokeRuntime({ installRoot: root, home, tmpdir, cwd, pins });
  throw new Error("smoke unexpectedly succeeded");
} catch (error) {
  if (!/failed to start|protocol stdin/i.test(error.message)) throw error;
}
