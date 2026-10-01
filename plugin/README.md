# mcp-gateway

mcp-gateway is a local gateway for the Model Context Protocol. It searches a tool catalogue that lives on this machine and invokes the tool you pick. The server listens on localhost. It is not a public hosted server. Claude starts it as a local stdio process through node, not a shell. The catalogue is the one shipped beside this plugin. Payment creation and generative image, video, and audio tools are not in that catalogue. Transcription, optical character recognition, URL screenshots, and charge listing stay available.

### Example: search for a tool

Ask the gateway to search the local catalogue for a tool, for example a stock quote or a calendar list. The search reads the catalogue on this machine and returns matching tool names and descriptions. Nothing is sent to a public hosted directory.

### Example: invoke a tool

Choose a tool from the search results and invoke it with the arguments that tool declares. The gateway sends the request only to a backend named in the local config on this machine.

### Example: run as a local stdio server

Claude launches this plugin with node. The launcher starts the published gateway package as a local stdio server. The server listens on localhost and is not a public hosted server.

```json
{
  "mcpServers": {
    "mcp-gateway": {
      "command": "node",
      "args": ["${CLAUDE_PLUGIN_ROOT}/bin/launch.js"]
    }
  }
}
```
