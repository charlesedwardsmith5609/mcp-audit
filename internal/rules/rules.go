// Package rules flags risky MCP server configuration.
package rules

import (
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
	for _, server := range file.Servers {
		out = append(out, serverFindings(file.Path, server)...)
	}
	return out
}

func serverFindings(file string, server config.Server) []Finding {
	var out []Finding
	name := config.Redact(server.Name)
	spec := resolve(server)
	if !server.HasDeny {
		out = append(out, Finding{
			ID: "MCP-NO-DENY", Severity: "medium", File: file, Server: name,
			Fix: "Add a non-empty deny list for this server: disabledTools or deniedTools on it, or a permissions.deny entry starting mcp__<server>.",
		})
	}
	if unpinned(spec) {
		out = append(out, Finding{
			ID: "MCP-UNPINNED-PACKAGE", Severity: "high", File: file, Server: name,
			Fix: "Pin the npx or uvx package to an exact version (name@1.2.3 or name==1.2.3).",
		})
	}
	if broadRoot(spec.args) {
		out = append(out, Finding{
			ID: "MCP-BROAD-ROOT", Severity: "medium", File: file, Server: name,
			Fix: "Point the filesystem server at the task directory, not / or the home directory.",
		})
	}
	if plainHTTP(server.URLs, spec.args) {
		out = append(out, Finding{
			ID: "MCP-PLAIN-HTTP", Severity: "high", File: file, Server: name,
			Fix: "Use https or wss for the remote server, or a local stdio command.",
		})
	}
	if shell(spec) {
		out = append(out, Finding{
			ID: "MCP-SHELL", Severity: "high", File: file, Server: name,
			Fix: "Launch the server binary directly. Do not wrap it in a shell or run inline code.",
		})
	}
	return out
}
