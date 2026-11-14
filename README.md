# mcp-audit

Scans MCP and agent JSON config and reports unpinned `npx` or `uvx` packages, secrets, filesystem roots (`/`, `~`, `$HOME`), remote `http://` servers, servers with no deny list, and shell launchers.

It does not start a server and it does not use the network. Secret values are not printed. A finding names the file and the JSON path and shows `[REDACTED]`.

```bash
go run ./cmd/mcp-audit --format text settings.json
go run ./cmd/mcp-audit --format json --fail-on high settings.json
bash scripts/check.sh
```

Exit 0 when no finding is at or above `--fail-on` (default `low`). Exit 1 when one is. Exit 2 when a file cannot be read or parsed. Symlinks and files over 1 MiB are refused.

The deny-list keys this tool recognizes are `deny`, `disabledTools`, and `alwaysDeny`, plus Claude `permissions.deny`. Other product keys are not inferred. See `docs/threat-model.md`.
