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

## What this plugin runs and where data goes

The launcher runs `npx -y @mikkoparkkola/mcp-gateway@3.5.1 --config <temp> serve --stdio`. npx fetches that package from the npm registry at `registry.npmjs.org`. The package downloads its binary from `https://github.com/MikkoParkkola/mcp-gateway/releases/download/v3.5.1/`. GitHub may redirect that download to a `githubusercontent.com` host. The launcher writes a temporary config for the catalogue in this folder and deletes that file when the process exits. It does not assign `MCP_GATEWAY_CAPABILITIES`.

Once a day the launcher POSTs to `https://telemetry.revaluator.ai/v1/heartbeat`. The JSON fields are `project` (`mcp-gateway`), `event` (`heartbeat`), `version`, `runtime`, `install_id`, `install_date`, and `machine_id`. `install_date` is the UTC day that install id was created. `machine_id` is a second random id shared by the products on this machine. It is not a name, an email, or an account. The body has no hostname, no username, and no tool arguments. The published build pinned by this folder does not send that POST. The launcher and a later build share `~/.config/mcp-gateway/telemetry`. The shared machine id file is `~/.revaluator/machine-id`. Set `MCP_GATEWAY_NO_TELEMETRY`, `NO_TELEMETRY`, or `DO_NOT_TRACK` to a value other than `0` or `false` to stop it. The full text is [PRIVACY.md](PRIVACY.md).

Invoking a tool sends that tool's arguments only to the service named in its file under `capabilities/`. A call uses credentials from the local config on this machine. Nothing is sent to a public hosted directory at search time. The catalogue names these hosts: `ai.google.dev`, `api.box.com`, `api.github.com`, `api.linear.app`, `api.notion.com`, `api.ocr.space`, `api.open-meteo.com`, `api.openai.com`, `api.quotable.io`, `api.semanticscholar.org`, `api.slack.com`, `api.stripe.com`, `archive.org`, `arxiv.org`, `avoindata.prh.fi`, `console.cloud.google.com`, `dash.cloudflare.com`, `date.nager.at`, `developer.atlassian.com`, `developer.box.com`, `developer.salesforce.com`, `developer.wolframalpha.com`, `developers.cloudflare.com`, `developers.google.com`, `developers.notion.com`, `docs.github.com`, `finance.yahoo.com`, `generativelanguage.googleapis.com`, `github.com`, `gmail.googleapis.com`, `hacker-news.firebaseio.com`, `id.atlassian.com`, `jokeapi.dev`, `musicbrainz.org`, `news.ycombinator.com`, `numbersapi.com`, `oauth2.googleapis.com`, `ocr.space`, `open-meteo.com`, `openrouter.ai`, `opentdb.com`, `people.googleapis.com`, `platform.openai.com`, `query1.finance.yahoo.com`, `randomuser.me`, `restcountries.com`, `screenshotapi.net`, `shot.screenshotapi.net`, `slack.com`, `stripe.com`, `tasks.googleapis.com`, `v2.jokeapi.dev`, `web.archive.org`, `wiki.openfoodfacts.org`, `world.openfoodfacts.org`, `www.ecb.europa.eu`, `www.googleapis.com`, `www.notion.so`, `www.uuidtools.com`, and `www.wolframalpha.com`. Example text in the catalogue also mentions the placeholders `your-domain.atlassian.net` and `your-instance.salesforce.com`. The server does not call a placeholder. Local test servers use `127.0.0.1`.
