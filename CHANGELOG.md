# Changelog

## 2026-11-14

Branch `improve/tldr-catchup-2026-11-13`, compared with `origin/main`.

### Changed

- Unrecognized input fails loudly: a file with no recognized server list, a `null` root, or a server list or entry of the wrong type yields a high `MCP-UNKNOWN-SHAPE` finding and exit 1.
- Supported shapes: `mcpServers`, `servers` (VS Code), `context_servers` (Zed), `projects.<path>.mcpServers` (`~/.claude.json`).
- Deny lists are per server (`disabledTools`, `deniedTools`, `alwaysDeny`, `deny`, or a `permissions.deny` entry for `mcp__<server>`), so one server's deny list no longer clears the others.
- Package pinning accepts only exact versions (`name@1.2.3`, `name==1.2.3`) and checks `-p`, `--package`, `--from` and `--with`. `env` and `cmd /c` wrappers are unwrapped when identifying the launcher or a shell.
- Broad-root detection covers drive roots, home directories, environment-variable forms, `file://` paths and Docker `-v`/`--mount` sources.
- Plain-HTTP detection covers `http://` and `ws://` in `url`, `serverUrl`, `httpUrl` and launch arguments, including `localhost`.
- `MCP-SHELL` also covers inline code with `node`/`ruby`/`perl` `-e` and `python` `-c`.
- Secret detection covers token prefixes, header and Bearer values, URL userinfo, query parameters, credential-named keys and flags. Environment references and names such as `MAX_TOKENS` are not reported.
- Output is sorted and deterministic. File, server and location text is printed quoted, and credential-looking key or server names print as `[REDACTED]`.
- A file that cannot be read no longer stops the run: other files are audited, their findings printed, and the exit is 2.
- Flags after a file name are a usage error. A file name starting with `-` must be passed as `./name`.
- Reads open the file once, require a regular file, and stop at 1 MiB. JSON nesting deeper than 64 and duplicate object keys exit 2. A symlinked config file is refused; a symlinked parent directory is followed.
- Docs (README, threat model, REQUIREMENTS, DECISIONS, CLAUDE.md, AGENTS.md) updated to match the code.

### Tooling

- Refreshed `scripts/` from the pairing kit: `check.sh` (secret scan of staged additions), `assertion-check.sh`, `misbehavior-check.sh`, `review-call.sh`, `cross-review.sh` and `cross-review.ps1`.
