// Package config reads MCP and agent JSON. It does not launch servers.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

const MaxBytes = 1 << 20

// Server is one MCP server entry.
type Server struct {
	Name    string
	Origin  string // JSON path of the object the server came from
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
	// Unknown is set when the file has no recognized server list or a recognized list has the
	// wrong type. Reason is a fixed string and never echoes file content.
	Unknown bool
	Reason  string
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
			return File{}, fmt.Errorf("%s is a symlink", path)
		}
		return File{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return File{}, err
	}
	if !info.Mode().IsRegular() {
		return File{}, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return File{}, err
	}
	if len(data) > MaxBytes {
		return File{}, fmt.Errorf("%s is larger than %d bytes", path, MaxBytes)
	}
	return Parse(path, data)
}

// Parse decodes a settings object once, with a depth cap and duplicate-key rejection, then
// extracts servers and secret sites from the decoded tree. A shape it does not recognize sets
// File.Unknown instead of reporting nothing.
func Parse(path string, data []byte) (File, error) {
	tree, err := decode(data)
	if err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	out := File{Path: path, SecretAt: walkSecrets("$", tree)}
	root, ok := tree.(map[string]any)
	if !ok {
		out.markUnknown("top-level value is not an object")
		return out, nil
	}
	out.HasDeny = hasDeny(root)
	found := false
	for _, key := range []string{"mcpServers", "servers", "context_servers"} {
		if raw, ok := root[key]; ok {
			found = true
			out.addServers("$."+key, raw)
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
				out.addServers("$.projects["+strconv.Quote(name)+"].mcpServers", rawServers)
			}
		}
	}
	if !found {
		out.markUnknown("no recognized server list (mcpServers, servers, context_servers, projects.*.mcpServers)")
	}
	return out, nil
}

func (f *File) markUnknown(reason string) {
	if !f.Unknown {
		f.Unknown, f.Reason = true, reason
	}
}

func (f *File) addServers(origin string, raw any) {
	servers, ok := raw.(map[string]any)
	if !ok {
		f.markUnknown("a server list is not an object")
		return
	}
	for name, rawServer := range servers {
		fields, ok := rawServer.(map[string]any)
		if !ok {
			f.markUnknown("a server entry is not an object")
			continue
		}
		server := Server{Name: name, Origin: origin + "." + name, Env: map[string]string{}}
		server.Command, _ = fields["command"].(string)
		server.URL, _ = fields["url"].(string)
		if args, ok := fields["args"].([]any); ok {
			for _, arg := range args {
				if s, ok := arg.(string); ok {
					server.Args = append(server.Args, s)
				}
			}
		}
		if env, ok := fields["env"].(map[string]any); ok {
			for key, value := range env {
				if s, ok := value.(string); ok {
					server.Env[key] = s
				}
			}
		}
		if hasDeny(fields) {
			f.HasDeny = true
		}
		f.Servers = append(f.Servers, server)
	}
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

func hasDeny(obj map[string]any) bool {
	for _, key := range []string{"deny", "disabledTools", "alwaysDeny"} {
		if _, ok := obj[key]; ok {
			return true
		}
	}
	if perms, ok := obj["permissions"].(map[string]any); ok {
		if _, ok := perms["deny"]; ok {
			return true
		}
	}
	return false
}
