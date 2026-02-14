Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 920
Set Height 600
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 30ms
Set WindowBar Colorful
Set WindowBarSize 40

Type `# Validate your MCP tool definitions`
Enter
Sleep 800ms

Type `mcp-gateway validate capabilities/examples/weather.yaml`
Enter
Sleep 200ms
Hide
Type `/tmp/demo-validate.sh`
Enter
Sleep 500ms
Show
Sleep 3s

Type ""
Enter
Sleep 500ms

Type `# Measure token savings with Meta-MCP`
Enter
Sleep 800ms

Type `python3 benchmarks/token_savings.py`
Enter
Sleep 200ms
Hide
Type `/tmp/demo-benchmark.sh`
Enter
Sleep 500ms
Show
Sleep 4s

Sleep 2s
