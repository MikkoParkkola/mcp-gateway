# MCP Gateway — give your AI every tool without burning context
Output demo.gif

Require mcp-gateway

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 800
Set Padding 16
Set TypingSpeed 25ms
Set Theme "Catppuccin Mocha"

# ─── Scene 1: The Problem ───────────────────────────────────────────────

Type "# The Problem: every MCP tool burns ~150 context tokens"
Enter
Sleep 1500ms

Type "# A typical setup — 5 MCP servers, 100+ tools:"
Enter
Sleep 1s

Type@20ms "cat ~/github/mcp-gateway/examples/servers.yaml"
Enter
Sleep 8s

Type ""
Enter
Type "# Each server exposes 5-30 tools. ALL loaded EVERY request."
Enter
Type "# 100 tools x 150 tokens = 15,000 tokens burned before you even start."
Enter
Sleep 4s

Ctrl+L
Sleep 200ms

# ─── Scene 2: The Solution — 4 Meta-Tools ───────────────────────────────

Type "# The Solution: connect to ONE gateway, get 4 meta-tools"
Enter
Sleep 2s

Type@20ms "cat /tmp/gw-demo/client-config.json"
Enter
Sleep 4s

Type ""
Enter
Type "# That is your entire MCP config. 4 meta-tools replace everything:"
Enter
Sleep 1500ms

Type@20ms "cat /tmp/gw-demo/meta-tools.txt"
Enter
Sleep 4s

Ctrl+L
Sleep 200ms

# ─── Scene 3: Works With ANY MCP Server ──────────────────────────────────

Type "# Works with ANY MCP server — stdio, HTTP, or SSE"
Enter
Sleep 2s

Type "# Backends in your gateway config:"
Enter
Sleep 1s

Type@20ms "cat /tmp/gw-demo/backends.txt"
Enter
Sleep 5s

Type ""
Enter
Type "# Unlimited backends. Circuit breakers isolate failures."
Enter
Type "# Change config? Gateway restarts in ~8ms. AI session stays alive."
Enter
Sleep 4s

Ctrl+L
Sleep 200ms

# ─── Scene 4: REST APIs Without MCP Servers ──────────────────────────────

Type "# REST APIs without an MCP server? Drop a YAML file:"
Enter
Sleep 2s

Type@20ms "head -35 ~/github/mcp-gateway/capabilities/examples/weather.yaml"
Enter
Sleep 7s

Type ""
Enter
Type "# Hot-reloaded in ~500ms. No server to build. 42 ship out of the box:"
Enter
Sleep 1500ms

Type@20ms "ls ~/github/mcp-gateway/capabilities/*/*.yaml | wc -l"
Enter
Sleep 2s

Type@20ms "ls ~/github/mcp-gateway/capabilities/*/"
Enter
Sleep 4s

Type ""
Enter
Type "# 25 zero-config (weather, Wikipedia, HN, GitHub, Reddit, SEC...)"
Enter
Sleep 3s

Ctrl+L
Sleep 200ms

# ─── Scene 5: Token Savings ──────────────────────────────────────────────

Type "# Token savings at scale (Claude Opus @ $15/M input tokens)"
Enter
Sleep 2s

Type@20ms "cat /tmp/gw-demo/savings.txt"
Enter
Sleep 6s

Ctrl+L
Sleep 200ms

# ─── End Card ────────────────────────────────────────────────────────────

Type "# cargo install mcp-gateway"
Enter
Type "# brew install MikkoParkkola/tap/mcp-gateway"
Enter
Type "# github.com/MikkoParkkola/mcp-gateway"
Enter
Sleep 3s
