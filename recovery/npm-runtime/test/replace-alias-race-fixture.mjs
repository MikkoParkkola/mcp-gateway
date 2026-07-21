// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { lstatSync, symlinkSync, unlinkSync } from "node:fs";
import path from "node:path";

const [destination, relativeTarget] = process.argv.slice(2);
if (!path.isAbsolute(destination) || !relativeTarget || path.isAbsolute(relativeTarget)) {
  throw new Error("expected an absolute destination and relative target");
}

process.stdout.write("ready\n");
const sleeper = new Int32Array(new SharedArrayBuffer(4));
const deadline = Date.now() + 5_000;
while (Date.now() < deadline) {
  try {
    if (lstatSync(destination).isSymbolicLink()) {
      unlinkSync(destination);
      symlinkSync(relativeTarget, destination, "dir");
      process.exit(0);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  Atomics.wait(sleeper, 0, 0, 1);
}
throw new Error("digest alias did not appear before timeout");
