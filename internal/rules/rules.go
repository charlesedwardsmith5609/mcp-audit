// Package rules flags risky MCP server configuration.
package rules

import (
	"strings"

	"mcp-audit/internal/config"
)

// Finding does not carry secret values.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Server   string `json:"server,omitempty"`
	Location string `json:"location,omitempty"`
	Fix      string `json:"fix"`
	Detail   string `json:"detail,omitempty"`
}

// Evaluate returns findings for one file.
func Evaluate(file config.File) []Finding {
	var out []Finding
	if file.Unknown {
		out = append(out, Finding{
			ID:       "MCP-UNKNOWN-SHAPE",
			Severity: "high",
			File:     file.Path,
			Detail:   file.Reason,
			Fix:      "Audit cannot read this file. Point it at a config with mcpServers, servers, context_servers, or projects.*.mcpServers.",
		})
	}
	for _, site := range file.SecretAt {
		out = append(out, Finding{
			ID:       "MCP-SECRET",
			Severity: "high",
			File:     file.Path,
			Location: site.Path,
			Detail:   "[REDACTED]",
			Fix:      "Remove the secret from the config. Pass it from a secret store at runtime.",
		})
	}
	if len(file.Servers) > 0 && !file.HasDeny {
		out = append(out, Finding{
			ID:       "MCP-NO-DENY",
			Severity: "medium",
			File:     file.Path,
			Fix:      "Add a deny list (deny, disabledTools, or alwaysDeny) for tools this server must not call.",
		})
	}
	for _, server := range file.Servers {
		out = append(out, serverFindings(file.Path, server)...)
	}
	return out
}

func serverFindings(file string, server config.Server) []Finding {
	var out []Finding
	if unpinned(server) {
		out = append(out, Finding{
			ID: "MCP-UNPINNED-PACKAGE", Severity: "high", File: file, Server: server.Name,
			Fix: "Pin the npx or uvx package to a version.",
		})
	}
	if broadRoot(server.Args) {
		out = append(out, Finding{
			ID: "MCP-BROAD-ROOT", Severity: "medium", File: file, Server: server.Name,
			Fix: "Point the filesystem server at the task directory, not / or the home directory.",
		})
	}
	if strings.HasPrefix(strings.ToLower(server.URL), "http://") {
		out = append(out, Finding{
			ID: "MCP-PLAIN-HTTP", Severity: "high", File: file, Server: server.Name,
			Fix: "Use https for the remote server, or a local stdio command.",
		})
	}
	if shell(server) {
		out = append(out, Finding{
			ID: "MCP-SHELL", Severity: "high", File: file, Server: server.Name,
			Fix: "Launch the server binary directly. Do not wrap it in a shell.",
		})
	}
	return out
}

func unpinned(server config.Server) bool {
	tokens := append([]string{server.Command}, server.Args...)
	if !usesLauncher(tokens) {
		return false
	}
	for _, token := range tokens {
		if launcher(token) || strings.HasPrefix(token, "-") {
			continue
		}
		if strings.ContainsAny(token, `/\`) && !strings.HasPrefix(token, "@") {
			continue
		}
		return !pinned(token)
	}
	return true
}

func usesLauncher(tokens []string) bool {
	for _, token := range tokens {
		if launcher(token) {
			return true
		}
	}
	return false
}

func launcher(token string) bool {
	base := token
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	return base == "npx" || base == "uvx" || base == "npx.cmd"
}

func pinned(token string) bool {
	if strings.Contains(token, "==") {
		parts := strings.SplitN(token, "==", 2)
		return parts[1] != "" && parts[1] != "latest"
	}
	at := strings.LastIndex(token, "@")
	if at <= 0 || at == len(token)-1 {
		return false
	}
	version := token[at+1:]
	return version != "latest" && !strings.Contains(version, "/")
}

func broadRoot(args []string) bool {
	for i, arg := range args {
		if isRoot(arg) || isRoot(afterEquals(arg)) {
			return true
		}
		if arg == "--root" || arg == "--allowed-directory" {
			if i+1 < len(args) && isRoot(args[i+1]) {
				return true
			}
		}
	}
	return false
}

func afterEquals(arg string) string {
	_, value, ok := strings.Cut(arg, "=")
	if !ok {
		return ""
	}
	return value
}

func isRoot(value string) bool {
	switch value {
	case "/", "~", "$HOME", "~/":
		return true
	default:
		return false
	}
}

func shell(server config.Server) bool {
	base := server.Command
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	switch base {
	case "sh", "bash", "zsh", "pwsh", "powershell", "cmd", "cmd.exe":
		return true
	}
	return false
}
