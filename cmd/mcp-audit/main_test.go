package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIHidesSecrets(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "mcp-audit")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	secret := filepath.Join("..", "..", "internal", "rules", "testdata", "secret.json")
	cmd := exec.Command(bin, "--format", "json", secret)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("secret fixture should exit non-zero")
	}
	if strings.Contains(string(out), "super-secret-value") || strings.Contains(string(out), "ghp_EXAMPLEEXAMPLEEXAMPLEEX") {
		t.Fatalf("cli leaked a secret: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED]") {
		t.Fatalf("json: %s", out)
	}
	pass := filepath.Join("..", "..", "internal", "rules", "testdata", "pass.json")
	ok := exec.Command(bin, "--format", "text", pass)
	out, err = ok.CombinedOutput()
	if err != nil {
		t.Fatalf("pass: %v\n%s", err, out)
	}
}
