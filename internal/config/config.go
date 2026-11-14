// Package config reads MCP and agent JSON. It does not launch servers.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const MaxBytes = 1 << 20

// Server is one MCP server entry.
type Server struct {
	Name    string
	Command string
	Args    []string
	Env     map[string]string
	URL     string
}

// File is one config file.
type File struct {
	Path     string
	Servers  []Server
	HasDeny  bool
	SecretAt []SecretSite
}

// SecretSite is a location whose value must not be printed.
type SecretSite struct {
	Path string
}

// ReadFile loads path. Symlinks and oversized files are errors.
func ReadFile(path string) (File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return File{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return File{}, fmt.Errorf("%s is a symlink", path)
	}
	if info.Size() > MaxBytes {
		return File{}, fmt.Errorf("%s is larger than %d bytes", path, MaxBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	return Parse(path, data)
}

// Parse decodes a settings object. Unknown shapes with no mcpServers yield an empty server list.
func Parse(path string, data []byte) (File, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	out := File{Path: path, HasDeny: hasDeny(root), SecretAt: walkSecrets("$", data)}
	raw, ok := root["mcpServers"]
	if !ok {
		return out, nil
	}
	var servers map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &servers); err != nil {
		return File{}, fmt.Errorf("%s: mcpServers: %w", path, err)
	}
	for name, fields := range servers {
		server := Server{Name: name, Env: map[string]string{}}
		if cmd, ok := stringField(fields, "command"); ok {
			server.Command = cmd
		}
		if url, ok := stringField(fields, "url"); ok {
			server.URL = url
		}
		if args, ok := fields["args"]; ok {
			_ = json.Unmarshal(args, &server.Args)
		}
		if env, ok := fields["env"]; ok {
			_ = json.Unmarshal(env, &server.Env)
		}
		if hasDeny(fields) {
			out.HasDeny = true
		}
		out.Servers = append(out.Servers, server)
	}
	return out, nil
}

func hasDeny(obj map[string]json.RawMessage) bool {
	for _, key := range []string{"deny", "disabledTools", "alwaysDeny"} {
		if _, ok := obj[key]; ok {
			return true
		}
	}
	if raw, ok := obj["permissions"]; ok {
		var perms map[string]json.RawMessage
		if json.Unmarshal(raw, &perms) == nil {
			if _, ok := perms["deny"]; ok {
				return true
			}
		}
	}
	return false
}

func stringField(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := fields[key]
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func walkSecrets(prefix string, raw json.RawMessage) []SecretSite {
	if len(raw) == 0 {
		return nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if looksLikeToken(text) {
			return []SecretSite{{Path: prefix}}
		}
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		var out []SecretSite
		for key, value := range obj {
			lower := strings.ToLower(key)
			if secretKey(lower) {
				out = append(out, SecretSite{Path: prefix + "." + key})
				continue
			}
			out = append(out, walkSecrets(prefix+"."+key, value)...)
		}
		return out
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		var out []SecretSite
		for i, value := range list {
			out = append(out, walkSecrets(fmt.Sprintf("%s[%d]", prefix, i), value)...)
		}
		return out
	}
	return nil
}

func secretKey(lower string) bool {
	return strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "password") || strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") || lower == "authorization"
}

func looksLikeToken(value string) bool {
	if strings.HasPrefix(value, "AKIA") && len(value) >= 20 {
		return true
	}
	if strings.HasPrefix(value, "ghp_") || strings.HasPrefix(value, "github_pat_") {
		return true
	}
	return false
}
