Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 920
Set Height 520
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 30ms
Set WindowBar Colorful
Set WindowBarSize 40

Type `# MCP Gateway — validate your tool definitions`
Enter
Sleep 800ms

Type `/tmp/mcp-gateway-bin validate capabilities/examples/weather.yaml`
Enter
Sleep 3s

Type ""
Enter
Sleep 500ms

Type `# Now measure token savings with Meta-MCP:`
Enter
Sleep 800ms

Type `python3 benchmarks/token_savings.py`
Enter
Sleep 4s

Sleep 2s
