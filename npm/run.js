#!/usr/bin/env node
"use strict";

const { execFileSync, execSync } = require("child_process");
const { existsSync, mkdirSync, chmodSync, createWriteStream } = require("fs");
const { join } = require("path");
const https = require("https");
const os = require("os");

const VERSION = "2.7.3";
const REPO = "MikkoParkkola/mcp-gateway";
const BIN_DIR = join(__dirname, ".bin");
const BIN_NAME = "mcp-gateway";

function getPlatform() {
  const arch = os.arch();
  const platform = os.platform();

  if (platform === "darwin" && arch === "arm64")
    return "mcp-gateway-darwin-arm64";
  if (platform === "darwin" && arch === "x64")
    return "mcp-gateway-darwin-x86_64";
  if (platform === "linux" && arch === "x64")
    return "mcp-gateway-linux-x86_64";

  throw new Error(
    `Unsupported platform: ${platform}-${arch}. ` +
      `Install via cargo: cargo install mcp-gateway`
  );
}

function download(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return download(res.headers.location).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        const binPath = join(BIN_DIR, BIN_NAME);
        const file = createWriteStream(binPath);
        res.pipe(file);
        file.on("finish", () => {
          file.close();
          chmodSync(binPath, 0o755);
          resolve(binPath);
        });
        file.on("error", reject);
      })
      .on("error", reject);
  });
}

async function install() {
  const artifact = getPlatform();
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${artifact}`;

  mkdirSync(BIN_DIR, { recursive: true });

  console.log(`Downloading mcp-gateway v${VERSION} (${artifact})...`);
  const binPath = await download(url);
  console.log(`Installed to ${binPath}`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args[0] === "--install") {
    await install();
    return;
  }

  const binPath = join(BIN_DIR, BIN_NAME);

  if (!existsSync(binPath)) {
    await install();
  }

  try {
    execFileSync(binPath, args, { stdio: "inherit" });
  } catch (e) {
    process.exit(e.status || 1);
  }
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
