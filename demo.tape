Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 500
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

Type "# MCP Gateway — Single port, all your MCP servers"
Enter
Sleep 500ms

Type "# Let's validate our capability definitions"
Enter
Sleep 500ms

Type "mcp-gateway validate capabilities/examples/"
Enter
Sleep 3s

Type ""
Enter
Sleep 500ms

Type "# 9 agent-UX rules checked. Now let's see token savings:"
Enter
Sleep 500ms

Type "python3 benchmarks/token_savings.py --backends 5 --tools-per-backend 20"
Enter
Sleep 3s

Type ""
Enter
Sleep 500ms

Type "# 98% fewer tokens. One gateway, all your tools."
Enter
Sleep 2s
