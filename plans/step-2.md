# Step 2: MEDIUM findings (5, 6, 7, 8, 9, 10, 11, 12, 13, 14)

## Design
- 5/6: `report` quotes file, server and location with `%q`; keys containing `.` or `[` use bracket notation (`$["a.b"]`). Keys and server names that pass `looksLikeToken` print as `[REDACTED]` (also in JSON output).
- 7 (D6): `Server.HasDeny` computed per server: non-empty `disabledTools`/`deniedTools` array on that server, or top-level `permissions.deny` non-empty array with an entry starting `mcp__<server>`. Empty, null, wrong-typed do not count. `File.HasDeny` removed; `MCP-NO-DENY` emitted per server with `Server` set. `alwaysDeny`/`deny` stay accepted only as non-empty arrays on the server. Update `http-shell.json` expectations (no longer relies on `deny: []`).
- 8: pin = exact semver `x.y.z` (optional pre-release/build) after `@` or `==`; reject `^ ~ * x latest next beta`, ranges, `1`, `1.x`, `==1.*`, case-insensitive.
- 9: launcher = basename lowercased, strip `.exe`/`.cmd`; split a single string command containing spaces; table of value-taking flags (`--python`, `--package`, `-p`, `--from`, ...); first non-flag positional is the package; `cmd /c npx ...` unwrapped; non-array `args` or non-string-map `env` -> parse error (exit 2).
- 10: normalize root candidates (trim, `path.Clean`, `${HOME}`, `$HOME/`, `%USERPROFILE%`, `C:\`, `C:/`, `//`, `/.`, `file:///`, `/home/<u>`, `/Users/<u>`, docker `-v /:/host`) before comparing.
- 11: URL fields `url`, `serverUrl`, `httpUrl`, plus http/ws URLs in args, via `url.Parse` with `TrimSpace`; `http://` and `ws://` flagged.
- 12: shell basename set expanded (dash, ksh, fish, csh, tcsh, bash/pwsh/powershell/cmd with `.exe`, case-insensitive); `env bash -c`, `node -e`, `python -c`/`python3 -c`.
- 13: skip `${VAR}`, `$VAR`, `%VAR%`, empty and non-string values for key-name secrets; `MAX_TOKENS`-style names need an allowlist of benign suffixes (`_TOKENS`, `_COUNT`).
- 14: duplicate JSON keys already rejected by step 1 decoder; this step adds the test coverage and nested-object cases (exit 2).

## Types
- `config.Server` gains `HasDeny bool`; `File.HasDeny` removed. New helper types stay unexported in `rules` (`launchSpec`).

## Ownership
No shared state; pure functions. Single goroutine in main.

## Tests (failing first; per-rule pass + fail fixture and near-miss tables)
1. Deny: one server with `disabledTools` does not clear another; `deny: []`, `null`, `"x"`, unrelated `permissions.deny` do not count; `mcp__srv` entry counts only for `srv`.
2. Secret-looking key name and server name print `[REDACTED]`; control chars (`\n`, ESC) in names appear escaped; dotted key uses bracket notation.
3. Pin table: `^1`, `~1.2`, `*`, `1`, `1.x`, `next`, `beta`, `LATEST`, `==1.*` unpinned; `pkg@1.2.3`, `pkg==1.2.3`, `@scope/pkg@1.2.3` pinned.
4. Launcher table: `npx.exe`, `"npx -y evil"` single string flagged; `uvx --python 3.12 pkg==1.0.0`, `npx --package=foo@1.0.0 foo`, `cmd /c npx -y pkg@1.0.0` handled with no false positive; `"args": "x"` and bad `env` exit 2.
5. Root table, each form listed above flagged; `/srv/task` not flagged.
6. URL table: `serverUrl`, `httpUrl`, `ws://`, leading whitespace, `npx mcp-remote@1.0.0 http://evil/mcp` flagged; `https://` and `wss://` not.
7. Shell table: all listed names/forms flagged; `node server.js`, `python app.py` not.
8. `${API_TOKEN}`, `$X`, `%X%`, `""`, `5`, `MAX_TOKENS: "100"` not flagged.
9. Duplicate keys at top level and inside a server exit exactly 2.

## Files
- internal/config/config.go
- internal/config/secrets.go
- internal/config/config_test.go
- internal/rules/rules.go
- internal/rules/launcher.go
- internal/rules/roots.go
- internal/rules/rules_test.go
- internal/rules/testdata/http-shell.json
- internal/rules/testdata/pass.json
- internal/rules/testdata/unpinned.json
- internal/report/report.go
- internal/report/report_test.go
- cmd/mcp-audit/main_test.go
