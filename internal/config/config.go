// Package config reads MCP and agent JSON. It does not launch servers.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const MaxBytes = 1 << 20

// Server is one MCP server entry.
type Server struct {
	Name    string
	Origin  string // JSON path of the object the server came from
	Command string
	Args    []string
	Env     map[string]string
	URL     string   // the "url" field
	URLs    []string // url, serverUrl and httpUrl fields, in that order, when present
	HasDeny bool     // this server has a non-empty deny list (D6)
}

// File is one config file.
type File struct {
	Path     string
	Servers  []Server
	SecretAt []SecretSite
	// Unknown is set when the file has no recognized server list or a recognized list has the
	// wrong type. Reason is a fixed string and never echoes file content.
	Unknown bool
	Reason  string

	denyEntries []string // top-level permissions.deny strings
}

// SecretSite is a location whose value must not be printed.
type SecretSite struct {
	Path string
}

// maxDepth caps JSON nesting so a hostile file cannot exhaust memory or the stack.
const maxDepth = 64

// ReadFile loads path. It opens the file once, refuses symlinks, requires a regular file and
// reads at most MaxBytes. Anything else is an error.
func ReadFile(path string) (File, error) {
	f, err := os.OpenFile(path, openFlags, 0)
	if err != nil {
		if isSymlinkErr(err) {
			return File{}, fmt.Errorf("%q is a symlink", path)
		}
		return File{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return File{}, err
	}
	if !info.Mode().IsRegular() {
		return File{}, fmt.Errorf("%q is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return File{}, err
	}
	if len(data) > MaxBytes {
		return File{}, fmt.Errorf("%q is larger than %d bytes", path, MaxBytes)
	}
	return Parse(path, data)
}

// Parse decodes a settings object once, with a depth cap and duplicate-key rejection, then
// extracts servers and secret sites from the decoded tree. A shape it does not recognize sets
// File.Unknown instead of reporting nothing.
func Parse(path string, data []byte) (File, error) {
	tree, err := decode(data)
	if err != nil {
		return File{}, fmt.Errorf("%q: %w", path, err)
	}
	out := File{Path: path, SecretAt: walkSecrets("$", tree)}
	root, ok := tree.(map[string]any)
	if !ok {
		out.markUnknown("top-level value is not an object")
		return out, nil
	}
	out.denyEntries = permissionsDeny(root)
	found := false
	for _, key := range []string{"mcpServers", "servers", "context_servers"} {
		if raw, ok := root[key]; ok {
			found = true
			if err := out.addServers("$."+key, raw); err != nil {
				return File{}, fmt.Errorf("%q: %w", path, err)
			}
		}
	}
	if raw, ok := root["projects"]; ok {
		projects, ok := raw.(map[string]any)
		if !ok {
			out.markUnknown("projects is not an object")
		}
		for name, rawProject := range projects {
			project, ok := rawProject.(map[string]any)
			if !ok {
				out.markUnknown("a project entry is not an object")
				continue
			}
			if rawServers, ok := project["mcpServers"]; ok {
				found = true
				if err := out.addServers(childPath("$.projects", name)+".mcpServers", rawServers); err != nil {
					return File{}, fmt.Errorf("%q: %w", path, err)
				}
			}
		}
	}
	if !found {
		out.markUnknown("no recognized server list (mcpServers, servers, context_servers, projects.*.mcpServers)")
	}
	sort.Slice(out.Servers, func(i, j int) bool { return out.Servers[i].Origin < out.Servers[j].Origin })
	sort.Slice(out.SecretAt, func(i, j int) bool { return out.SecretAt[i].Path < out.SecretAt[j].Path })
	return out, nil
}

func (f *File) markUnknown(reason string) {
	if !f.Unknown {
		f.Unknown, f.Reason = true, reason
	}
}

func (f *File) addServers(origin string, raw any) error {
	servers, ok := raw.(map[string]any)
	if !ok {
		f.markUnknown("a server list is not an object")
		return nil
	}
	for name, rawServer := range servers {
		fields, ok := rawServer.(map[string]any)
		if !ok {
			f.markUnknown("a server entry is not an object")
			continue
		}
		server := Server{Name: name, Origin: childPath(origin, name), Env: map[string]string{}}
		fail := func(format string, a ...any) error {
			return fmt.Errorf("server %q: %s", Redact(name), fmt.Sprintf(format, a...))
		}
		var err error
		if server.Command, err = optString(fields, "command"); err != nil {
			return fail("%v", err)
		}
		for _, key := range []string{"url", "serverUrl", "httpUrl"} {
			value, err := optString(fields, key)
			if err != nil {
				return fail("%v", err)
			}
			if value == "" {
				continue
			}
			if key == "url" {
				server.URL = value
			}
			server.URLs = append(server.URLs, value)
		}
		if raw, ok := fields["args"]; ok {
			list, ok := raw.([]any)
			if !ok {
				return fail("args must be an array of strings")
			}
			for _, item := range list {
				arg, ok := item.(string)
				if !ok {
					return fail("args must be an array of strings")
				}
				server.Args = append(server.Args, arg)
			}
		}
		if raw, ok := fields["env"]; ok {
			env, ok := raw.(map[string]any)
			if !ok {
				return fail("env must be an object of strings")
			}
			for key, value := range env {
				text, ok := value.(string)
				if !ok {
					return fail("env values must be strings")
				}
				server.Env[key] = text
			}
		}
		server.HasDeny = serverDeny(fields) || denied(f.denyEntries, name)
		f.Servers = append(f.Servers, server)
	}
	return nil
}

func optString(fields map[string]any, key string) (string, error) {
	raw, ok := fields[key]
	if !ok {
		return "", nil
	}
	text, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return text, nil
}

// decode parses one JSON value with json.Decoder.Token so nesting depth and duplicate keys are
// checked before any large structure is built.
func decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the top-level value")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	if depth+1 > maxDepth {
		return nil, fmt.Errorf("nesting deeper than %d", maxDepth)
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, _ := keyTok.(string)
			if _, dup := obj[key]; dup {
				return nil, errors.New("duplicate object key")
			}
			value, err := decodeValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			obj[key] = value
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return obj, nil
	default:
		list := []any{}
		for dec.More() {
			value, err := decodeValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, value)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return list, nil
	}
}

// serverDeny reports a non-empty deny array on the server itself. Empty, null and wrong-typed
// values do not count.
func serverDeny(fields map[string]any) bool {
	for _, key := range []string{"disabledTools", "deniedTools", "alwaysDeny", "deny"} {
		if list, ok := fields[key].([]any); ok && len(list) > 0 {
			return true
		}
	}
	return false
}

func permissionsDeny(root map[string]any) []string {
	perms, _ := root["permissions"].(map[string]any)
	list, _ := perms["deny"].([]any)
	var out []string
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// denied reports a permissions.deny entry for this server: mcp__<server> or mcp__<server>__<tool>.
// A longer server name that merely starts with this one does not match.
func denied(entries []string, server string) bool {
	prefix := "mcp__" + server
	for _, entry := range entries {
		if entry == prefix || strings.HasPrefix(entry, prefix+"__") {
			return true
		}
	}
	return false
}
