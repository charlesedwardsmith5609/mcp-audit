# Threat model

The tool reads JSON the operator names. It does not launch MCP servers and it does not send the config anywhere.

## Assets

Config files often hold tokens in `env` or args. The report may name the key and the file. It must not print the value. Tests plant a fake token and assert the output does not contain it.

## Rules that are file claims

An unpinned `npx` or `uvx` package can change on the next launch. A shell command can run whatever the args say. `http://` is not TLS. A root of `/` or a home directory lets a filesystem server read more than the task.

## Needs verification

Product-specific deny-list keys besides `deny`, `disabledTools`, and `alwaysDeny` are not detected. A Cursor or Claude build that uses a different key will look like it has no deny list. Confirm the key in the settings file you actually use before treating a clean report as a complete allow/deny review.

## Failure

Symlinks, files over 1 MiB, and invalid JSON exit 2.
