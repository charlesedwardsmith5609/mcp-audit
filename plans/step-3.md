# Step 3: LOW findings (15, 16, 17, 19)

Finding 18 (go directive) is already `go 1.26.11` and D10 says keep it; no change unless a tool cannot resolve the toolchain (then use `go 1.26` + `toolchain go1.26.11` and note it).

## Design
- 15: `rules.Evaluate` and `config.Parse` sort servers by name; findings sorted by (file, server, id, location) with `sort.SliceStable` before reporting.
- 16: flags must precede files (`flag.Parse` stops at first non-flag); a later arg starting with `-` is a usage error, exit 2 (so it is never read as a file). An unreadable file is reported on stderr, remaining files are still audited, and the final exit is 2.
- 17: test hardening: per-rule pass/fail fixtures and near-miss tables (from steps 1-2 audited for coverage); CLI tests assert `ExitError.ExitCode()` exactly 1 / 2 and that planted secrets are absent from stdout and stderr in text and JSON.
- 19: README and threat model: symlinked config files are refused; a symlinked parent directory is still followed; add the shapes now supported and the unknown-shape behavior; remove claims the code does not enforce.

## Types
No new types. Optional `main.run(args, stdout, stderr) int` extracted for testability.

## Ownership
No shared state; main is single-goroutine, sorted slices are local.

## Tests (failing first)
1. Same input run 20 times produces byte-identical output.
2. `mcp-audit good.json --format json` -> exit 2 with usage message; flag-looking arg never opened as file.
3. Two files, first missing: stderr names it, second file's findings still printed, exit exactly 2.
4. Exit-code table: clean=0, finding=1, bad JSON=2, `--fail-on` raised above findings=0, bad `--format`=2.
5. Docs test: README mentions symlinked-parent caveat (grep-style string assertion).

## Files
- cmd/mcp-audit/main.go
- cmd/mcp-audit/main_test.go
- internal/rules/rules.go
- internal/rules/rules_test.go
- internal/config/config.go
- README.md
- docs/threat-model.md
