package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseServersAndRefuseSymlink(t *testing.T) {
	file, err := Parse("cfg.json", []byte(`{"permissions":{"deny":["rm"]},"mcpServers":{"fs":{"command":"npx","args":["-y","@scope/pkg@1.2.3","/work"],"url":"https://example.invalid"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !file.HasDeny || len(file.Servers) != 1 || file.Servers[0].Command != "npx" {
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
