# mcp-audit

Scans MCP and agent JSON config and reports unpinned `npx` or `uvx` packages, secrets, filesystem roots (`/`, drive roots, home directories), remote `http://` and `ws://` servers, servers with no deny list, shell launchers, and files whose shape it does not recognize.

It does not start a server and it does not use the network. Secret values are not printed. A finding names the file and the JSON path and shows `[REDACTED]`. File names, server names and paths are printed quoted, so control characters in them cannot forge output. A key or server name that looks like a credential prints as `[REDACTED]`.

```bash
go run ./cmd/mcp-audit --format text settings.json
go run ./cmd/mcp-audit --format json --fail-on high settings.json
bash scripts/check.sh
```

Flags go before the files. A file whose name starts with `-` must be passed as `./name`.

## Exit codes

- 0: no finding is at or above `--fail-on` (default `low`).
- 1: a finding is at or above `--fail-on`. An unrecognized file shape is a high finding, `MCP-UNKNOWN-SHAPE`, so it exits 1.
- 2: usage error, or a file could not be read or parsed. Other files on the command line are still audited and their findings printed, but the exit is 2.

## Input

Recognized shapes: `mcpServers` (Claude Desktop, Cursor), `servers` (VS Code), `context_servers` (Zed), and `projects.<path>.mcpServers` (`~/.claude.json`). A file with none of these, a `null` root, or a server list or server entry of the wrong type yields `MCP-UNKNOWN-SHAPE`. Invalid JSON, duplicate object keys, nesting deeper than 64, `args` that is not an array of strings, and `env` that is not an object of strings exit 2.

A config file is opened once and read through a 1 MiB limit. A file over 1 MiB, or anything that is not a regular file (a FIFO, `/dev/zero`), exits 2. A symlinked config file is refused. A symlinked parent directory is still followed, so the check does not stop `dir-link/settings.json` from resolving elsewhere.

## Deny lists

Checked per server. A server has a deny list when it has a non-empty `disabledTools`, `deniedTools`, `alwaysDeny` or `deny` array, or when the top-level `permissions.deny` array has an entry equal to `mcp__<server>` or starting with `mcp__<server>__`. Empty arrays, `null` and wrong-typed values do not count, and a deny list on one server never clears another. Other product keys are not inferred. See `docs/threat-model.md`.
