// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  lstat,
  mkdir,
  readFile,
  readdir,
  readlink,
  realpath,
  stat,
  symlink,
} from "node:fs/promises";
import path from "node:path";

const EXACT_SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_COMMAND_PART = /^[A-Za-z0-9_@./+:-]+$/;

export function assertExactVersion(value, label = "dependency") {
  if (typeof value !== "string" || !EXACT_SEMVER.test(value)) {
    throw new Error(`${label} must use an exact version`);
  }
}

export async function readJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

export async function sha256File(file) {
  return createHash("sha256").update(await readFile(file)).digest("hex");
}

function expectedBinTarget(record, pin) {
  if (typeof record.bin === "string") return record.bin;
  if (record.bin && typeof record.bin === "object") return record.bin[pin.bin];
  return undefined;
}

export function verifyDirectPackageRecords({ manifest, lock, pins }) {
  if (lock?.lockfileVersion !== 3 || !lock.packages || typeof lock.packages !== "object") {
    throw new Error("package-lock.json must use lockfileVersion 3");
  }
  if (!manifest?.dependencies || !pins?.packages) {
    throw new Error("manifest dependencies and direct package pins are required");
  }

  const pinned = Object.values(pins.packages);
  const expectedPackages = pinned.map((pin) => pin.package).sort();
  const manifestPackages = Object.keys(manifest.dependencies).sort();
  if (JSON.stringify(expectedPackages) !== JSON.stringify(manifestPackages)) {
    throw new Error("manifest dependencies do not exactly match direct package pins");
  }

  const rootDependencies = lock.packages[""]?.dependencies ?? {};
  for (const pin of pinned) {
    assertExactVersion(pin.version, `${pin.package} pin`);
    const manifestVersion = manifest.dependencies[pin.package];
    assertExactVersion(manifestVersion, `${pin.package} manifest dependency`);
    if (manifestVersion !== pin.version) {
      throw new Error(`${pin.package} manifest version does not match pin`);
    }
    if (rootDependencies[pin.package] !== pin.version) {
      throw new Error(`${pin.package} root lock version does not match pin`);
    }

    const record = lock.packages[`node_modules/${pin.package}`];
    if (!record) throw new Error(`${pin.package} is missing from lock packages`);
    if (record.version !== pin.version) {
      throw new Error(`${pin.package} locked version does not match pin`);
    }
    if (record.integrity !== pin.integrity) {
      throw new Error(`${pin.package} locked integrity does not match pin`);
    }
    if (expectedBinTarget(record, pin) !== pin.entrypoint) {
      throw new Error(`${pin.package} locked bin target does not match pin`);
    }
  }
}

export function verifyLockGraph({ manifest, lock, pins }) {
  verifyDirectPackageRecords({ manifest, lock, pins });

  for (const [location, record] of Object.entries(lock.packages)) {
    if (location === "") continue;
    if (record.link) throw new Error(`lock graph contains unsupported link at ${location}`);
    if (!record.version || !record.resolved || !record.integrity) {
      throw new Error(`lock graph package ${location} lacks version, resolved URL, or integrity`);
    }
    let resolved;
    try {
      resolved = new URL(record.resolved);
    } catch {
      throw new Error(`lock graph package ${location} has an invalid resolved URL`);
    }
    if (resolved.protocol !== "https:" || resolved.hostname !== "registry.npmjs.org") {
      throw new Error(`lock graph package ${location} is not pinned to the npm registry`);
    }
    if (!/^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(record.integrity)) {
      throw new Error(`lock graph package ${location} has invalid integrity metadata`);
    }
  }
}

function isInside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

async function walkTree(root, visit, relative = "") {
  const directory = path.join(root, relative);
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)));
  for (const entry of entries) {
    const childRelative = relative ? path.join(relative, entry.name) : entry.name;
    const child = path.join(root, childRelative);
    const metadata = await lstat(child);
    await visit(child, childRelative, metadata);
    if (metadata.isDirectory()) await walkTree(root, visit, childRelative);
  }
}

export async function assertContainedSymlinks(root) {
  const rootReal = await realpath(root);
  await walkTree(rootReal, async (absolute, relative, metadata) => {
    if (!metadata.isSymbolicLink()) return;
    const target = await readlink(absolute);
    if (path.isAbsolute(target)) {
      throw new Error(`symlink ${relative} uses an absolute target`);
    }
    let resolved;
    try {
      resolved = await realpath(absolute);
    } catch {
      throw new Error(`symlink ${relative} is dangling or unreadable`);
    }
    if (!isInside(rootReal, resolved)) {
      throw new Error(`symlink ${relative} escapes staged root`);
    }
  });
}

export async function canonicalTreeDigest(root) {
  const rootReal = await realpath(root);
  const digest = createHash("sha256");
  const frame = (value) => {
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    digest.update(length);
    digest.update(bytes);
  };
  await walkTree(rootReal, async (absolute, relative, metadata) => {
    const portablePath = relative.split(path.sep).join("/");
    if (metadata.isDirectory()) return;
    if (metadata.isFile()) {
      digest.update(Buffer.from([0x46]));
      frame(portablePath);
      const executable = Buffer.alloc(4);
      executable.writeUInt32BE(metadata.mode & 0o111);
      digest.update(executable);
      frame(await readFile(absolute));
      return;
    }
    if (metadata.isSymbolicLink()) {
      digest.update(Buffer.from([0x4c]));
      frame(portablePath);
      frame(await readlink(absolute, { encoding: "buffer" }));
      return;
    }
    throw new Error(`unsupported filesystem object in runtime tree: ${portablePath}`);
  });

  return digest.digest("hex");
}

export function buildIsolatedEnvironment({ home, tmpdir }) {
  if (!path.isAbsolute(home) || !path.isAbsolute(tmpdir)) {
    throw new Error("isolated HOME and TMPDIR must be absolute");
  }
  return {
    CI: "true",
    HOME: home,
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
    PATH: "/opt/homebrew/bin:/usr/bin:/bin",
    TMPDIR: tmpdir,
  };
}

export async function createExclusiveDirectory(directory) {
  if (!path.isAbsolute(directory)) throw new Error("exclusive directory path must be absolute");
  await mkdir(directory, { mode: 0o700 });
  return directory;
}

async function pathExists(candidate) {
  try {
    await lstat(candidate);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

export async function atomicPublish(stagingRoot, destinationRoot) {
  if (!path.isAbsolute(stagingRoot) || !path.isAbsolute(destinationRoot)) {
    throw new Error("publish paths must be absolute");
  }
  if (await pathExists(destinationRoot)) {
    throw new Error(`publish destination already exists: ${destinationRoot}`);
  }

  await assertContainedSymlinks(stagingRoot);
  const stagingReal = await realpath(stagingRoot);
  const destinationParentReal = await realpath(path.dirname(destinationRoot));
  const staging = await stat(stagingReal);
  const destinationParent = await stat(destinationParentReal);
  if (!staging.isDirectory()) throw new Error("publish staging root must be a directory");
  if (staging.dev !== destinationParent.dev) {
    throw new Error("atomic publish requires staging and destination on the same filesystem");
  }
  if (!isInside(destinationParentReal, stagingReal) || stagingReal === destinationParentReal) {
    throw new Error("publish staging object must already be inside the destination filesystem root");
  }

  const treeDigest = await canonicalTreeDigest(stagingReal);
  if (path.basename(destinationRoot) !== treeDigest) {
    throw new Error("publish destination name must equal the verified tree digest");
  }

  // Creating the digest alias as a symlink is one atomic, no-clobber operation:
  // unlike rename(2), symlink(2) fails with EEXIST even when another process
  // races to create an empty destination. The verified object is pre-positioned
  // under the same publish root and remains retained for rollback/forensics.
  const relativeTarget = path.relative(destinationParentReal, stagingReal);
  try {
    await symlink(relativeTarget, destinationRoot, "dir");
  } catch (error) {
    if (error?.code === "EEXIST") {
      throw new Error(`publish destination already exists: ${destinationRoot}`);
    }
    throw error;
  }
  return { tree_digest: treeDigest, object: stagingReal, destination: destinationRoot };
}

function safeCommandPart(value, label) {
  if (!path.isAbsolute(value)) throw new Error(`${label} must be absolute`);
  if (!SAFE_COMMAND_PART.test(value)) throw new Error(`${label} contains unsafe shell characters`);
  return value;
}

export function renderGatewayConfig({ nodePath, installRoot, pins }) {
  if (!path.isAbsolute(nodePath)) throw new Error("absolute Node path is required");
  if (!path.isAbsolute(installRoot)) throw new Error("absolute install root is required");
  if (!SHA256.test(path.basename(installRoot))) {
    throw new Error("install root must end in a literal SHA-256 tree digest");
  }
  safeCommandPart(nodePath, "Node path");

  const lines = [
    "# MERGE FRAGMENT ONLY — DO NOT REPLACE THE COMPLETE PRIVATE CONFIG.",
    "# Change only these four command values; preserve every existing backend,",
    "# enabled state, env/header reference, timeout, and recovered process environment.",
    "backends:",
  ];
  for (const [backend, pin] of Object.entries(pins.packages ?? {})) {
    if (!/^[a-z0-9_-]+$/.test(backend)) throw new Error(`unsafe backend name: ${backend}`);
    if (path.isAbsolute(pin.entrypoint) || pin.entrypoint.split(/[\\/]/).includes("..")) {
      throw new Error(`${backend} entrypoint must be a contained relative path`);
    }
    const entrypoint = path.join(installRoot, "node_modules", pin.package, pin.entrypoint);
    if (!isInside(installRoot, entrypoint)) throw new Error(`${backend} entrypoint escapes install root`);
    const parts = [nodePath, entrypoint, ...(pin.args ?? [])];
    for (const [index, part] of parts.entries()) {
      safeCommandPart(part, `${backend} command part ${index}`);
    }
    lines.push(`  ${backend}:`);
    lines.push(`    command: ${JSON.stringify(parts.join(" "))}`);
  }
  return `${lines.join("\n")}\n`;
}

function constraintMatches(values, actual) {
  if (!Array.isArray(values) || values.length === 0) return true;
  const positive = values.filter((value) => !value.startsWith("!"));
  if (values.includes(`!${actual}`)) return false;
  return positive.length === 0 || positive.includes(actual);
}

function lockRecordApplies(record, platform) {
  return constraintMatches(record.os, platform.os) && constraintMatches(record.cpu, platform.arch);
}

function packageNameFromLocation(location) {
  const parts = location.split("/");
  const nodeModules = parts.lastIndexOf("node_modules");
  const first = parts[nodeModules + 1];
  return first.startsWith("@") ? `${first}/${parts[nodeModules + 2]}` : first;
}

async function scanInstalledNodeModules(installRoot) {
  const found = new Map();

  async function scan(directory, locationPrefix) {
    if (!(await pathExists(directory))) return;
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)));
    for (const entry of entries) {
      if (entry.name === ".bin" || entry.name === ".package-lock.json") continue;
      const absolute = path.join(directory, entry.name);
      if (entry.name.startsWith("@")) {
        if (!entry.isDirectory()) throw new Error(`invalid scope entry ${absolute}`);
        const scoped = await readdir(absolute, { withFileTypes: true });
        scoped.sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)));
        for (const child of scoped) {
          if (!child.isDirectory()) throw new Error(`invalid scoped package entry ${child.name}`);
          const packageRoot = path.join(absolute, child.name);
          const location = `${locationPrefix}/${entry.name}/${child.name}`;
          const packageJson = await readJson(path.join(packageRoot, "package.json"));
          found.set(location, packageJson);
          await scan(path.join(packageRoot, "node_modules"), `${location}/node_modules`);
        }
      } else {
        if (!entry.isDirectory()) throw new Error(`invalid node_modules entry ${absolute}`);
        const location = `${locationPrefix}/${entry.name}`;
        const packageJson = await readJson(path.join(absolute, "package.json"));
        found.set(location, packageJson);
        await scan(path.join(absolute, "node_modules"), `${location}/node_modules`);
      }
    }
  }

  await scan(path.join(installRoot, "node_modules"), "node_modules");
  return found;
}

export async function verifyInstalledRuntime({ installRoot, manifest, lock, pins }) {
  if (!path.isAbsolute(installRoot)) throw new Error("installed runtime root must be absolute");
  verifyLockGraph({ manifest, lock, pins });
  await assertContainedSymlinks(installRoot);

  const installedManifest = await readJson(path.join(installRoot, "package.json"));
  const installedLock = await readJson(path.join(installRoot, "package-lock.json"));
  if (JSON.stringify(installedManifest) !== JSON.stringify(manifest)) {
    throw new Error("installed package.json differs from the reviewed manifest");
  }
  if (JSON.stringify(installedLock) !== JSON.stringify(lock)) {
    throw new Error("installed package-lock.json differs from the reviewed lock");
  }

  const installed = await scanInstalledNodeModules(installRoot);
  for (const [location, packageJson] of installed) {
    const record = lock.packages[location];
    if (!record) throw new Error(`unexpected installed package ${location}`);
    if (packageJson.version !== record.version) {
      throw new Error(`${location} installed version does not match lock`);
    }
    const expectedName = record.name ?? packageNameFromLocation(location);
    if (packageJson.name !== expectedName) {
      throw new Error(`${location} package name does not match its installed location`);
    }
  }

  for (const [location, record] of Object.entries(lock.packages)) {
    if (location === "" || !lockRecordApplies(record, pins.platform)) continue;
    if (!installed.has(location)) throw new Error(`locked package ${location} was not installed`);
  }

  const bins = {};
  const installReal = await realpath(installRoot);
  for (const [backend, pin] of Object.entries(pins.packages)) {
    const packageRoot = path.join(installRoot, "node_modules", pin.package);
    const packageJson = await readJson(path.join(packageRoot, "package.json"));
    if (packageJson.version !== pin.version) {
      throw new Error(`${pin.package} installed version does not match direct pin`);
    }
    if (expectedBinTarget(packageJson, pin) !== pin.entrypoint) {
      throw new Error(`${pin.package} installed bin target does not match direct pin`);
    }

    const entrypoint = path.join(packageRoot, pin.entrypoint);
    const metadata = await lstat(entrypoint);
    if (!metadata.isFile()) throw new Error(`${pin.package} entrypoint is not a regular file`);
    const entryReal = await realpath(entrypoint);
    if (!isInside(installReal, entryReal)) throw new Error(`${pin.package} entrypoint escapes install root`);

    const bin = path.join(installRoot, "node_modules", ".bin", pin.bin);
    const binMetadata = await lstat(bin);
    if (!binMetadata.isSymbolicLink()) throw new Error(`${pin.package} npm bin is not a symlink`);
    if ((await realpath(bin)) !== entryReal) {
      throw new Error(`${pin.package} npm bin does not resolve to the pinned entrypoint`);
    }
    bins[backend] = { entrypoint: entryReal, bin: await realpath(bin) };
  }

  const runtimeChecks = {};
  for (const check of pins.runtime_checks ?? []) {
    const packageRoot = path.join(installRoot, "node_modules", check.package);
    const packageJson = await readJson(path.join(packageRoot, "package.json"));
    if (packageJson.version !== check.version) {
      throw new Error(`${check.name} package version does not match pin`);
    }
    const executable = path.join(packageRoot, check.path);
    const metadata = await lstat(executable);
    if (!metadata.isFile() || (metadata.mode & 0o111) === 0) {
      throw new Error(`${check.name} is not an executable regular file`);
    }
    const resolved = await realpath(executable);
    if (!isInside(installReal, resolved)) throw new Error(`${check.name} escapes install root`);
    runtimeChecks[check.name] = { path: resolved, version: packageJson.version };
  }

  return {
    tree_digest: await canonicalTreeDigest(installRoot),
    installed_package_count: installed.size,
    bins,
    runtime_checks: runtimeChecks,
  };
}

export async function verifyToolchain(pins, { home, tmpdir } = {}) {
  if (process.platform !== pins.platform?.os || process.arch !== pins.platform?.arch) {
    throw new Error(`host platform ${process.platform}/${process.arch} does not match pin`);
  }
  const environment = buildIsolatedEnvironment({ home, tmpdir });
  const result = {};
  for (const [name, pin] of Object.entries(pins.toolchain ?? {})) {
    if (!path.isAbsolute(pin.path) || !path.isAbsolute(pin.resolved_path)) {
      throw new Error(`${name} toolchain paths must be absolute`);
    }
    const resolved = await realpath(pin.path);
    if (resolved !== pin.resolved_path) {
      throw new Error(`${name} resolved path does not match pin`);
    }
    const digest = await sha256File(resolved);
    if (!SHA256.test(pin.sha256) || digest !== pin.sha256) {
      throw new Error(`${name} binary SHA-256 does not match pin`);
    }
    await access(pin.path);
    result[name] = { ...pin, actual_sha256: digest };
  }

  await assertContainedSymlinks(pins.toolchain.npm.module_root);
  const npmTreeDigest = await canonicalTreeDigest(pins.toolchain.npm.module_root);
  if (!SHA256.test(pins.toolchain.npm.tree_sha256) || npmTreeDigest !== pins.toolchain.npm.tree_sha256) {
    throw new Error("npm module tree SHA-256 does not match pin");
  }
  result.npm.actual_tree_sha256 = npmTreeDigest;

  const nodeVersion = spawnSync(pins.toolchain.node.path, ["--version"], {
    encoding: "utf8",
    env: environment,
    maxBuffer: 1024 * 1024,
    timeout: 10_000,
  });
  if (nodeVersion.error || nodeVersion.status !== 0 || nodeVersion.stdout.trim() !== pins.toolchain.node.version) {
    throw new Error("Node version does not match pin");
  }

  const npmVersion = spawnSync(
    pins.toolchain.node.path,
    [pins.toolchain.npm.resolved_path, "--version"],
    {
      encoding: "utf8",
      env: environment,
      maxBuffer: 1024 * 1024,
      timeout: 10_000,
    },
  );
  if (npmVersion.error || npmVersion.status !== 0 || npmVersion.stdout.trim() !== pins.toolchain.npm.version) {
    throw new Error("npm version does not match pin");
  }

  result.platform = { os: process.platform, arch: process.arch };
  return result;
}
