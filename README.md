# mcp-audit

Scans MCP and agent JSON config and reports unpinned `npx` or `uvx` packages, secrets, filesystem roots (`/`, drive roots, home directories), remote `http://` and `ws://` servers, servers with no deny list, shell launchers, and files whose shape it does not recognize.

It does not start a server and it does not use the network. Secret values are not printed. A finding names the file and the JSON path and shows `[REDACTED]`. File names, server names and paths are printed quoted, so control characters in them cannot forge output. A key or server name that looks like a credential prints as `[REDACTED]`.

## Run

```bash
go run ./cmd/mcp-audit --format text settings.json
go run ./cmd/mcp-audit --format json --fail-on high settings.json
bash scripts/check.sh
```

Usage: `mcp-audit [--format text|json] [--fail-on low|medium|high] file...`

Flags go before the files. A flag after a file name is a usage error (exit 2). A file whose name starts with `-` must be passed as `./name`. At least one file is required. Go standard library only.

`bash scripts/check.sh` is the validation gate: agent-misbehavior and assertion checks, then gofmt, go vet, govulncheck and `go test -race`. It ends with `CHECK PASSED` or `CHECK FAILED`. govulncheck is skipped with a notice when it is not installed or cannot reach the network.

## Output

Text prints one line per finding, `<severity> <id> "<file>" server "<name>" at "<json path>"`, followed by an indented `fix:` line, or `no findings`. JSON prints `{"fail_on": ..., "findings": [{id, severity, file, server, location, fix, detail}]}`, with `server`, `location` and `detail` omitted when empty. Findings are sorted by file, server, id and location, so output is the same on every run.

## Rules

| Id | Severity | Reported when |
|----|----------|---------------|
| `MCP-UNKNOWN-SHAPE` | high | The file has no recognized server list, or a list or entry has the wrong type. |
| `MCP-SECRET` | high | A value looks like a credential (see Secrets). |
| `MCP-UNPINNED-PACKAGE` | high | An `npx` or `uvx` launch whose package is not an exact version. |
| `MCP-PLAIN-HTTP` | high | A `url`, `serverUrl` or `httpUrl` field, or a launch argument, is an `http://` or `ws://` URL. `localhost` and loopback addresses are not exempt. |
| `MCP-SHELL` | high | The launch goes through a shell (`sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, `csh`, `tcsh`, `ash`, `pwsh`, `powershell`, `cmd`), even behind `env` or `cmd /c`, or runs inline code with `node`/`nodejs`/`ruby`/`perl` `-e` or `python` `-c`. |
| `MCP-BROAD-ROOT` | medium | An argument, `--flag=value`, or the host side of a Docker `-v`/`--mount`, is `/`, a drive root, or a home directory (`~`, `$HOME`, `%USERPROFILE%`, `/home/<user>`, `/Users/<user>`, `C:\Users\<user>`, `/root`). |
| `MCP-NO-DENY` | medium | The server has no deny list (see Deny lists). One finding per server. |

`MCP-UNPINNED-PACKAGE` accepts only an exact version: `name@1.2.3` for npm or `name==1.2.3` for Python, optionally with a pre-release or build suffix. Ranges, tags such as `@latest`, and a missing version are unpinned. Every package named with `-p`, `--package`, `--from` or `--with` must be pinned. A positional argument that is a path (`.`, `./x`, `/x`, `~`, a drive path, or contains a slash and is not `@scope/name`) is not treated as a package. `env` and `cmd /c` wrappers are unwrapped before the launcher is identified, and the launcher must be the command itself, not a word in the arguments.

## Secrets

Secret values are never printed. Detected forms: well-known token prefixes anywhere in a string (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`, `glpat-`, `xox[abprs]-`, `sk-`, `AKIA`); `Authorization`, `Proxy-Authorization`, `X-API-Key`, `API-Key` and `X-Auth-Token` header values; `Bearer` values; passwords in URL userinfo; credential-named URL query parameters; credential-named JSON keys (for example in `env`) with a non-empty string value; and `--token=x` or `--token x` style arguments. `${VAR}`, `$VAR` and `%VAR%` references, empty values and non-string values are not secrets, and names ending in `_count`, `_tokens`, `_limit`, `_file`, `_path` and similar are treated as non-credentials.

## Exit codes

- 0: no finding is at or above `--fail-on` (default `low`).
- 1: a finding is at or above `--fail-on`. An unrecognized file shape is a high finding, `MCP-UNKNOWN-SHAPE`, so it exits 1.
- 2: usage error, or a file could not be read or parsed. Other files on the command line are still audited and their findings printed, but the exit is 2.

## Input

Recognized shapes: `mcpServers` (Claude Desktop, Cursor), `servers` (VS Code), `context_servers` (Zed), and `projects.<path>.mcpServers` (`~/.claude.json`). A file with none of these, a `null` root, or a server list or server entry of the wrong type yields `MCP-UNKNOWN-SHAPE`. Invalid JSON, duplicate object keys, nesting deeper than 64, `command` or `url` that is not a string, `args` that is not an array of strings, and `env` that is not an object of strings exit 2.

A config file is opened once and read through a 1 MiB limit. A file over 1 MiB, or anything that is not a regular file (a FIFO, `/dev/zero`), exits 2. A symlinked config file is refused (on Unix). A symlinked parent directory is still followed, so the check does not stop `dir-link/settings.json` from resolving elsewhere.

## Deny lists

Checked per server. A server has a deny list when it has a non-empty `disabledTools`, `deniedTools`, `alwaysDeny` or `deny` array, or when the top-level `permissions.deny` array has an entry equal to `mcp__<server>` or starting with `mcp__<server>__`. Empty arrays, `null` and wrong-typed values do not count, and a deny list on one server never clears another. Other product keys are not inferred. See `docs/threat-model.md`.

## Pairing and review scripts

`scripts/plan-review.sh` and `scripts/cross-review.sh` (and `cross-review.ps1`) come from a pairing kit and are optional. `cross-review.sh` sends the diff to another AI provider for review. The request is scanned with gitleaks first; if gitleaks is missing or fails, or the scan matches, nothing is sent. Secret-looking files (`.env*`, keys, credentials) are never sent. `plan-review.sh` sends a plan file through the same scan. See `CLAUDE.md` for the working agreements.
