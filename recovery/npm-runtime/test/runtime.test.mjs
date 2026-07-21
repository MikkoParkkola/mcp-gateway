// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  lstat,
  readFile,
  rename,
  stat,
  symlink,
  unlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertContainedSymlinks,
  assertExactVersion,
  atomicPublish,
  buildIsolatedEnvironment,
  canonicalTreeDigest,
  renderGatewayConfig,
  verifyDirectPackageRecords,
  verifyLockGraph,
} from "../lib/runtime.mjs";
import { smokeRuntime } from "../smoke-runtime.mjs";

const DIRECT_PACKAGE = "@example/server";
const ENTRYPOINT = "dist/index.js";
const RUNTIME_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function directFixture() {
  const manifest = {
    dependencies: {
      [DIRECT_PACKAGE]: "1.2.3",
    },
  };
  const lock = {
    lockfileVersion: 3,
    packages: {
      "": {
        dependencies: {
          [DIRECT_PACKAGE]: "1.2.3",
        },
      },
      [`node_modules/${DIRECT_PACKAGE}`]: {
        version: "1.2.3",
        resolved: "https://registry.npmjs.org/@example/server/-/server-1.2.3.tgz",
        integrity: "sha512-example",
        bin: {
          "example-server": ENTRYPOINT,
        },
      },
    },
  };
  const pins = {
    packages: {
      example: {
        package: DIRECT_PACKAGE,
        version: "1.2.3",
        integrity: "sha512-example",
        bin: "example-server",
        entrypoint: ENTRYPOINT,
        args: [],
      },
    },
  };
  return { manifest, lock, pins };
}

test("exact versions reject npm ranges and tags", () => {
  for (const value of ["^1.2.3", "~1.2.3", ">=1.2.3", "1.2.x", "*", "latest", "v1.2.3", " 1.2.3"])
    assert.throws(() => assertExactVersion(value, "fixture"), /exact version/i);

  assert.doesNotThrow(() => assertExactVersion("1.2.3", "fixture"));
  assert.doesNotThrow(() => assertExactVersion("2026.7.10", "fixture"));
});

test("direct package version, SRI, and bin mismatches are rejected", () => {
  for (const [field, value] of [
    ["version", "1.2.4"],
    ["integrity", "sha512-wrong"],
    ["bin", { "wrong-bin": ENTRYPOINT }],
  ]) {
    const fixture = directFixture();
    fixture.lock.packages[`node_modules/${DIRECT_PACKAGE}`][field] = value;
    assert.throws(
      () => verifyDirectPackageRecords(fixture),
      new RegExp(field === "bin" ? "bin" : field, "i"),
    );
  }
});

test("the full lock rejects missing integrity and non-registry resolutions", () => {
  for (const [field, value] of [
    ["integrity", undefined],
    ["resolved", "git+https://example.invalid/server.git"],
  ]) {
    const fixture = directFixture();
    fixture.lock.packages[`node_modules/${DIRECT_PACKAGE}`][field] = value;
    assert.throws(() => verifyLockGraph(fixture), /integrity|registry|resolved URL/i);
  }
});

test("isolated child environments omit ambient credentials and npm configuration", () => {
  const isolated = buildIsolatedEnvironment({
    home: "/private/tmp/runtime-home",
    tmpdir: "/private/tmp/runtime-tmp",
  });
  assert.deepEqual(Object.keys(isolated).sort(), [
    "CI",
    "HOME",
    "LANG",
    "LC_ALL",
    "NO_COLOR",
    "PATH",
    "TMPDIR",
  ]);
  assert.equal(isolated.HOME, "/private/tmp/runtime-home");
  assert.equal(isolated.TMPDIR, "/private/tmp/runtime-tmp");
  assert.equal(isolated.NODE_OPTIONS, undefined);
  assert.equal(isolated.NODE_PATH, undefined);
});

test("symlinks escaping the staged root are rejected", async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "npm-runtime-symlink-"));
  const root = path.join(parent, "runtime");
  await mkdir(root);
  await writeFile(path.join(parent, "outside"), "do-not-follow");
  await symlink("../outside", path.join(root, "escape"));

  await assert.rejects(() => assertContainedSymlinks(root), /escapes staged root/i);
});

test("canonical tree digest ignores timestamps and binds bytes, mode, path, and symlink target", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "npm-runtime-digest-"));
  const file = path.join(root, "server.js");
  const link = path.join(root, "server-link");
  await writeFile(file, "one\n", { mode: 0o644 });
  await symlink("server.js", link);
  const baseline = await canonicalTreeDigest(root);

  await utimes(file, new Date(1_000), new Date(2_000));
  assert.equal(await canonicalTreeDigest(root), baseline, "timestamps must not affect digest");

  await writeFile(file, "two\n");
  assert.notEqual(await canonicalTreeDigest(root), baseline, "file bytes must affect digest");
  await writeFile(file, "one\n");
  assert.equal(await canonicalTreeDigest(root), baseline);

  await chmod(file, 0o755);
  assert.notEqual(await canonicalTreeDigest(root), baseline, "executable mode must affect digest");
  await chmod(file, 0o644);
  assert.equal(await canonicalTreeDigest(root), baseline);

  const renamed = path.join(root, "renamed.js");
  await rename(file, renamed);
  assert.notEqual(await canonicalTreeDigest(root), baseline, "relative path must affect digest");
  await rename(renamed, file);
  assert.equal(await canonicalTreeDigest(root), baseline);

  await writeFile(path.join(root, "other.js"), "one\n");
  await unlink(link);
  await symlink("other.js", link);
  assert.notEqual(await canonicalTreeDigest(root), baseline, "symlink target must affect digest");
});

test("atomic publish refuses existing destinations and creates an exclusive digest alias", async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "npm-runtime-publish-"));
  const occupiedStage = path.join(parent, "occupied-stage");
  await mkdir(occupiedStage);
  const occupiedDestination = path.join(parent, await canonicalTreeDigest(occupiedStage));
  await mkdir(occupiedDestination);
  await assert.rejects(
    () => atomicPublish(occupiedStage, occupiedDestination),
    /already exists/i,
  );
  assert.equal((await stat(occupiedStage)).isDirectory(), true, "refused staging tree must remain");

  const stage = path.join(parent, "new-stage");
  await mkdir(stage);
  await writeFile(path.join(stage, "server.js"), "verified\n");
  const destination = path.join(parent, await canonicalTreeDigest(stage));
  await atomicPublish(stage, destination);
  assert.equal((await lstat(destination)).isSymbolicLink(), true);
  assert.equal(await readFile(path.join(destination, "server.js"), "utf8"), "verified\n");
  assert.equal(await readFile(path.join(stage, "server.js"), "utf8"), "verified\n");

  const racingStage = path.join(parent, "racing-stage");
  await mkdir(racingStage);
  await writeFile(path.join(racingStage, "server.js"), "race-safe\n");
  const racingDestination = path.join(parent, await canonicalTreeDigest(racingStage));
  const outcomes = await Promise.allSettled([
    atomicPublish(racingStage, racingDestination),
    atomicPublish(racingStage, racingDestination),
  ]);
  assert.equal(outcomes.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(outcomes.filter(({ status }) => status === "rejected").length, 1);
  assert.equal((await lstat(racingDestination)).isSymbolicLink(), true);
  assert.equal(await readFile(path.join(racingStage, "server.js"), "utf8"), "race-safe\n");
});

test("config rendering requires absolute paths and emits literal digest-root commands", () => {
  const digest = "a".repeat(64);
  const installRoot = `/Users/mikko/.local/libexec/mcp-gateway/npm-runtime/${digest}`;
  const pins = directFixture().pins;

  assert.throws(
    () => renderGatewayConfig({ nodePath: "node", installRoot, pins }),
    /absolute Node path/i,
  );
  assert.throws(
    () => renderGatewayConfig({ nodePath: "/opt/homebrew/bin/node", installRoot: "relative", pins }),
    /absolute install root/i,
  );

  const rendered = renderGatewayConfig({
    nodePath: "/opt/homebrew/bin/node",
    installRoot,
    pins,
  });
  assert.match(rendered, new RegExp(installRoot));
  assert.ok(rendered.includes('command: "/opt/homebrew/bin/node '));
  assert.doesNotMatch(rendered, /<tree-digest>|\bnpx\b/);
  assert.doesNotMatch(rendered, /^\s+(?:enabled|description|env|headers):/m);
  assert.match(rendered, /MERGE FRAGMENT ONLY/);
});

test("render CLI refuses caller-supplied unverified digests", () => {
  const result = spawnSync(
    process.execPath,
    [path.join(RUNTIME_ROOT, "render-config.mjs"), "--tree-digest", "a".repeat(64)],
    { encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 5_000 },
  );
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /missing --evidence/);
});

test("a failed verification leaves staging and evidence intact", async () => {
  const evidence = await mkdtemp(path.join(os.tmpdir(), "npm-runtime-evidence-"));
  const stage = path.join(evidence, "install-a");
  await mkdir(stage);
  await writeFile(path.join(stage, "forensics.txt"), "preserve me\n");

  const fixture = directFixture();
  fixture.lock.packages[`node_modules/${DIRECT_PACKAGE}`].integrity = "sha512-wrong";
  assert.throws(() => verifyDirectPackageRecords(fixture), /integrity/i);
  assert.equal(await readFile(path.join(stage, "forensics.txt"), "utf8"), "preserve me\n");
});

test("smoke process spawn failures terminate without hanging", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "npm-runtime-spawn-failure-"));
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
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("smoke process cleanup hung")), 3_000);
  });
  try {
    await assert.rejects(
      Promise.race([smokeRuntime({ installRoot: root, home, tmpdir, cwd, pins }), timeout]),
      /failed to start|protocol stdin/i,
    );
  } finally {
    clearTimeout(timer);
  }
});
