# Requirements

`mcp-audit` reads agent and MCP configuration JSON and reports risky server launches. It does not start a server and it does not use the network.

## Inputs

JSON files. The shapes this tool understands are an object with `mcpServers`, or a Claude-style settings object that also has `permissions`. Other product keys are not inferred. See the threat model.

## Rules

Each finding has an id, a severity, a location, and a fix hint. Secret values are never printed. The report says `[REDACTED]` and the JSON path.

- `npx` or `uvx` package with no version pin.
- A secret-like key or a recognizable token in config or args.
- A filesystem root of `/`, `~`, or `$HOME`.
- A remote server URL that starts with `http://`.
- A server with no deny list in the file (`deny`, `disabledTools`, or `alwaysDeny`).
- A server whose command is a shell (`sh`, `bash`, `zsh`, `pwsh`, `powershell`, `cmd`).

## Output

Human text and JSON. Exit non-zero when a finding is at or above `--fail-on` (default `low`). Exit 2 when a selected file cannot be read or parsed.

## Tests

Passing and failing fixtures. Tests do not use the network. A test asserts that a planted secret string is absent from the report.
