# Decisions

## 2026-11-13: Local repo, GitHub create not available

Context: `mcp-audit` was not on GitHub. `gh` is not logged in.

Choice: scaffold with agent-pairing-kit `new-project.sh` and develop on `improve/tldr-catchup-2026-11-13`. Push stays blocked. `go 1.26.11` matches the toolchain that passes govulncheck. The scaffold's 1.22.2 stdlib does not.

## 2026-11-13 phase 1 review

Finding: unpinned CI actions. Resolution: pin checkout and setup-go to the same commits used in iam-trust-audit. No second model was available for cross-review.sh.

## 2026-11-13 phase 2 review

Finding: a secret in an args array would be missed by a map-only walk. Resolution: the walker visits objects, arrays, and strings. A secret-like key is recorded as a path and the value is not copied into the finding. No second model was available.

## 2026-11-13 phase 3 review

Finding: a directory argument after a pinned npx package looks like an unpinned package because it has no version. Resolution: a token that contains a slash and does not start with @ is a path, not a package. @scope/name is still a package. The first package token decides. No second model was available.

## 2026-11-13 phase 4 review

Finding: the report could echo env values. Resolution: secret findings carry the location and the marker [REDACTED]. The CLI test plants a fake token and asserts the output does not contain it. No second model was available.

## 2026-11-13 phase 5 review

Finding: a clean report could be read as proof that every product deny-list key was checked. Resolution: the README lists the keys this tool knows and points at the threat model for the rest. Updated 2026-11-14: the list is now `disabledTools`, `deniedTools`, `alwaysDeny`, `deny` and `permissions.deny`, checked per server. No second model was available.

## 2026-11-14: unknown shapes fail, deny lists per server, docs match code

Finding: a file in a layout the tool did not know produced no findings and exit 0. Resolution: it yields high `MCP-UNKNOWN-SHAPE` and exit 1. Deny lists are decided per server, so a deny list on one server no longer clears the others. Docs now describe only what the code enforces, including that a symlinked parent directory is followed and that `localhost` `http://` URLs are still flagged.
