# Step 1: HIGH findings (1, 2, 3, 4)

Covers findings 1, 2, 3, 4 (and finding 14 duplicate-key rejection, since it falls out of the single-pass decoder; counted under step 2 for status).

## Design
- `config.readBounded(path)`: open (`O_NOFOLLOW|O_NONBLOCK` on Unix), `Stat`, `IsRegular`, `io.LimitReader(MaxBytes+1)`. Replaces Lstat+ReadFile. Errors -> exit 2.
- `config.Parse` decodes once with `json.Decoder.Token()` into `any` with depth cap 64 and duplicate-key rejection; over depth -> error (exit 2). Hand the decoded tree to both server extraction and secret walking (no repeated `json.Unmarshal` of raw subtrees).
- Shape detection by name: `mcpServers`, `servers`, `projects.<p>.mcpServers`, `context_servers`. Nothing recognized, `null`, `{"mcpServers":null}`, or non-object server entries -> `File.Unknown` set; `rules.Evaluate` emits HIGH `MCP-UNKNOWN-SHAPE` (exit 1).
- Secret detection (`config/secrets.go`): split `--flag=value`; value after a secret-named flag is secret; header strings `Authorization: Bearer ...`; `url.Parse` userinfo and query keys; env keys normalized (`-`->`_`, lowercase) matching secret/token/password/api_key/pat/private_key/database_url with credentials; contains-match prefixes (`ghp_`, `github_pat_`, `ghs_`, `glpat-`, `xoxb-`, `sk-`, `AKIA`).

## Types
- `config.File` gains `Unknown bool` (plus `Reason string`); `Server` gains `Origin string` (path of the object it came from).
- `rules.Finding` unchanged; new ID `MCP-UNKNOWN-SHAPE`.

## Ownership
No shared mutable state. Parse and Evaluate are pure functions on values; main runs sequentially on one goroutine.

## Tests (written failing first, via real CLI binary and `config.Parse`)
1. VS Code `servers`, `~/.claude.json` `projects`, Zed `context_servers` parse and yield servers.
2. `null`, `{}`, `{"mcpServers":null}`, `{"foo":1}` -> exit exactly 1 with `MCP-UNKNOWN-SHAPE`; invalid JSON -> exit exactly 2.
3. Each secret pattern (one test row each): `--token=ghp_...`, `--api-key v`, `Authorization: Bearer v`, `https://user:hunter2@h/mcp`, `?api_key=v`, `X-API-Key` header, env `GITHUB_PAT`, `PRIVATE_KEY`, `DATABASE_URL=postgres://u:p@db`, `sk-`, `xoxb-`, `glpat-`, `ghs_`; planted value absent from stdout and stderr in text and JSON.
4. Negative secret rows: `--token-count 5`, `https://h/mcp`, plain args do not fire.
5. 1 MiB file of ~9000 nested arrays and 100-deep nesting exit 2 within a 10 s test timeout.
6. `/dev/zero` and a FIFO path exit 2 without hanging (run with context timeout); a symlink is refused (exit 2); file at 1 MiB+1 exits 2, exactly 1 MiB accepted.

## Files
- internal/config/config.go
- internal/config/secrets.go
- internal/config/open_unix.go
- internal/config/open_other.go
- internal/config/config_test.go
- internal/config/secrets_test.go
- internal/rules/rules.go
- internal/rules/rules_test.go
- internal/rules/testdata/unknown-shape.json
- internal/rules/testdata/secret.json
- cmd/mcp-audit/main.go
- cmd/mcp-audit/main_test.go
