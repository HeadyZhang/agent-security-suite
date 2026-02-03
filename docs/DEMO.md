# Creating the Demo GIF

To create a demo GIF for the README, follow these steps:

## Recording Tools

- **macOS**: Use [Kap](https://getkap.co/) or [CleanShot X](https://cleanshot.com/)
- **Linux**: Use [Peek](https://github.com/phw/peek) or [Gifski](https://gif.ski/)
- **Windows**: Use [ScreenToGif](https://www.screentogif.com/)

## What to Record

### Demo 1: Basic Scan (`demo.gif`)

1. Open terminal with a clean prompt
2. Navigate to a sample project with vulnerabilities
3. Run: `agent-audit scan .`
4. Show the colorful output with findings
5. Total recording time: ~15-20 seconds

```bash
# Example commands to record
cd my-vulnerable-agent
agent-audit scan .
```

### Demo 2: MCP Inspection (`demo-inspect.gif`)

1. Run: `agent-audit inspect stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp`
2. Show the MCP server capabilities being probed
3. Total recording time: ~10-15 seconds

## GIF Specifications

- **Width**: 800-1000px
- **Frame rate**: 10-15 fps
- **Max file size**: 5MB (for fast loading)
- **Format**: GIF or WebP

## Tips

1. Use a dark terminal theme (looks better on GitHub dark mode)
2. Increase font size to 16-18pt for readability
3. Clear your terminal history before recording
4. Pause briefly on important findings
5. Optimize the GIF with [gifsicle](https://www.lcdf.org/gifsicle/): `gifsicle -O3 --colors 128 demo.gif -o demo-optimized.gif`

## File Placement

Save the final GIF as `docs/demo.gif` in the repository root.
