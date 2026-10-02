"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const heartbeat = require("./heartbeat");

// The published 3.5.1 binary does not contain this client. The launcher sends
// the daily POST, and a later build shares ~/.config/mcp-gateway/telemetry.
heartbeat.start({
  project: "mcp-gateway",
  version: "3.5.1",
  optOut: ["MCP_GATEWAY_NO_TELEMETRY"],
  endpointEnv: "MCP_GATEWAY_TELEMETRY_ENDPOINT",
  stateParts: [".config", "mcp-gateway", "telemetry"],
});

const capabilitiesDir = path.resolve(__dirname, "..", "capabilities");
const configPath = path.join(os.tmpdir(), `mcp-gateway-plugin-${process.pid}.yaml`);
// The published 3.5.1 binary deserializes every MCP_GATEWAY_* variable onto
// Config. `capabilities` is a struct, so a directory path in
// MCP_GATEWAY_CAPABILITIES exits before tools/list. Point serve at this
// folder with a config file instead.
const lines = [
  "capabilities:",
  "  enabled: true",
  "  directories:",
  "    - " + JSON.stringify(capabilitiesDir),
  "meta_mcp:",
  "  surfaced_tools:",
  "    - server: gateway",
  "      tool: stripe_list_charges",
  "    - server: gateway",
  "      tool: audio_transcribe",
  "    - server: gateway",
  "      tool: image_to_text",
  "    - server: gateway",
  "      tool: screenshot_url",
  "",
];
fs.writeFileSync(configPath, lines.join("\n"));

const env = { ...process.env };
for (const key of Object.keys(env)) {
  if (key === "MCP_GATEWAY_CAPABILITIES" || key.startsWith("MCP_GATEWAY_CAPABILITIES_")) {
    delete env[key];
  }
}
delete env.MCP_GATEWAY_CONFIG;

const child = spawn(
  "npx",
  ["-y", "@mikkoparkkola/mcp-gateway@3.5.1", "--config", configPath, "serve", "--stdio"],
  { stdio: "inherit", env },
);

function finish(code) {
  fs.rmSync(configPath, { force: true });
  process.exit(code === null ? 1 : code);
}

child.on("exit", finish);
child.on("error", () => finish(1));
