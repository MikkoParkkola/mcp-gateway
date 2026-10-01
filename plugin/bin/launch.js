"use strict";

const { spawn } = require("child_process");
const path = require("path");

const capabilitiesDir = path.resolve(__dirname, "..", "capabilities");
const env = { ...process.env, MCP_GATEWAY_CAPABILITIES: capabilitiesDir };

// Published package, pinned, as a local stdio server: serve --stdio
const child = spawn(
  "npx",
  ["-y", "@mikkoparkkola/mcp-gateway@3.5.1", "serve", "--stdio"],
  { stdio: "inherit", env },
);

child.on("exit", (code) => {
  process.exit(code === null ? 1 : code);
});
