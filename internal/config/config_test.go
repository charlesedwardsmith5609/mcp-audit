package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseServersAndRefuseSymlink(t *testing.T) {
	file, err := Parse("cfg.json", []byte(`{"permissions":{"deny":["rm"]},"mcpServers":{"fs":{"command":"npx","args":["-y","@scope/pkg@1.2.3","/work"],"url":"https://example.invalid"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Servers) != 1 || file.Servers[0].Command != "npx" {
		t.Fatalf("%+v", file)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"mcpServers":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link); err == nil {
		t.Fatal("symlink should be refused")
	}
}

func TestParseShapes(t *testing.T) {
	cases := []struct {
		name, body string
		servers    int
		unknown    bool
	}{
		{"classic", `{"mcpServers":{"a":{"command":"x"}}}`, 1, false},
		{"vscode", `{"servers":{"a":{"command":"x"}}}`, 1, false},
		{"zed", `{"context_servers":{"a":{"command":"x"}}}`, 1, false},
		{"claude projects", `{"projects":{"/p":{"mcpServers":{"a":{"command":"x"}}},"/q":{"mcpServers":{"b":{"command":"y"}}}}}`, 2, false},
		{"empty servers is known", `{"mcpServers":{}}`, 0, false},
		{"null root", `null`, 0, true},
		{"empty root", `{}`, 0, true},
		{"mcpServers null", `{"mcpServers":null}`, 0, true},
		{"server is string", `{"mcpServers":{"a":"x"}}`, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse("c.json", []byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if len(file.Servers) != tc.servers || file.Unknown != tc.unknown {
				t.Fatalf("servers=%d unknown=%v reason=%q", len(file.Servers), file.Unknown, file.Reason)
			}
			if tc.unknown && file.Reason == "" {
				t.Fatal("unknown shape needs a reason")
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	deep := strings.Repeat("[", 65) + strings.Repeat("]", 65)
	ok := strings.Repeat("[", 60) + strings.Repeat("]", 60)
	for name, body := range map[string]string{
		"invalid":       `{nope`,
		"trailing data": `{"mcpServers":{}} {}`,
		"too deep":      `{"mcpServers":{},"x":` + deep + `}`,
	} {
		if _, err := Parse("c.json", []byte(body)); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
	if _, err := Parse("c.json", []byte(`{"mcpServers":{},"x":`+ok+`}`)); err != nil {
		t.Fatalf("60 deep should parse: %v", err)
	}
}
