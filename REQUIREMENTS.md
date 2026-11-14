# Requirements

`mcp-audit` reads agent and MCP configuration JSON and reports risky server launches. It does not start a server and it does not use the network.

## Inputs

JSON files. The shapes this tool understands are listed under Review fixes 2026-11-14 below (`mcpServers`, `servers`, `context_servers`, `projects.*.mcpServers`). Other product keys are not inferred. See the threat model.

## Rules

Each finding has an id, a severity, a location, and a fix hint. Secret values are never printed. The report says `[REDACTED]` and the JSON path.

- `npx` or `uvx` package with no version pin.
- A secret-like key or a recognizable token in config or args.
- A filesystem root of `/`, `~`, or `$HOME` (broadened below to drive roots and home directories).
- A remote server URL that starts with `http://` or `ws://`.
- A server with no deny list in the file (`deny`, `disabledTools`, `deniedTools`, or `alwaysDeny` on the server, or `permissions.deny`; see below).
- A server whose command is a shell (`sh`, `bash`, `zsh`, `pwsh`, `powershell`, `cmd`).

## Output

Human text and JSON. Exit non-zero when a finding is at or above `--fail-on` (default `low`). Exit 2 when a selected file cannot be read or parsed.

## Tests

Passing and failing fixtures. Tests do not use the network. A test asserts that a planted secret string is absent from the report.

## Review fixes 2026-11-14

Source: review findings from the 2026-11-13 catch-up (the review files are not committed). Standard library only; no new dependencies.

- Unknown input is loud. An unrecognized shape (including `null`, `{"mcpServers":null}`, non-object servers) yields a HIGH `MCP-UNKNOWN-SHAPE` finding and exit 1. Common shapes are supported by name: `mcpServers`, VS Code `servers`, `~/.claude.json` `projects.*.mcpServers`, Zed `context_servers`. Invalid JSON, duplicate keys, nesting deeper than 64, unreadable, oversized or non-regular files exit 2.
- Reads are bounded: open once, `Stat`, require a regular file, read through a 1 MiB limit. Non-regular files never block.
- Secret detection covers flag values (`--token=x`, `--api-key x`), `Authorization`/`X-API-Key` header values, URL userinfo and query keys, secret-named env keys, and known token prefixes anywhere in a value. `${VAR}`, `$VAR`, `%VAR%` references and empty or non-string values are not secrets. Secret-looking key or server names print as `[REDACTED]`.
- Deny lists are per server: a non-empty `disabledTools`, `deniedTools`, `alwaysDeny` or `deny` array on the server, or a `permissions.deny` entry equal to `mcp__<server>` or starting `mcp__<server>__`. Empty, null and wrong-typed values do not count.
- Pin, launcher, root, plain-HTTP and shell rules use normalized, structured matching as listed in findings 8-12.
- Output is sorted, and names and paths are quoted with `%q`.
- Tests: each rule has passing and failing fixtures and near-miss tables; CLI tests assert exact exit codes and that planted secrets are absent from stdout and stderr in both formats.
- Docs state only what the code enforces, including that symlinked config files are refused but a symlinked parent directory is followed.
