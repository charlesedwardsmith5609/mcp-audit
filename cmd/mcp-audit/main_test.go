package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mcp-audit-bin")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "mcp-audit")
	if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// runCLI runs the binary with a deadline and returns stdout, stderr and the exit code.
func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("mcp-audit %v timed out", args)
	}
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run: %v", err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixture(name string) string {
	return filepath.Join("..", "..", "internal", "rules", "testdata", name)
}

func TestCLIHidesSecrets(t *testing.T) {
	out, errOut, code := runCLI(t, "--format", "json", fixture("secret.json"))
	if code != 1 {
		t.Fatalf("secret fixture exit %d, want 1", code)
	}
	for _, leaked := range []string{"super-secret-value", "ghp_EXAMPLEEXAMPLEEXAMPLEEX"} {
		if strings.Contains(out+errOut, leaked) {
			t.Fatalf("cli leaked %s: %s", leaked, out)
		}
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("json: %s", out)
	}
	if _, _, code := runCLI(t, "--format", "text", fixture("pass.json")); code != 0 {
		t.Fatalf("pass fixture exit %d, want 0", code)
	}
}

// Each row plants one secret in a distinct form. The planted value must never
// reach stdout or stderr, in either format, and the run must exit 1.
func TestCLISecretPatterns(t *testing.T) {
	rows := []struct{ name, server, planted string }{
		{"flag equals", `{"command":"node","args":["s.js","--token=ghp_PLANTEDPLANTEDPLANTED"]}`, "ghp_PLANTEDPLANTEDPLANTED"},
		{"flag then value", `{"command":"node","args":["s.js","--api-key","plantedvalue123"]}`, "plantedvalue123"},
		{"bearer header arg", `{"command":"node","args":["s.js","--header","Authorization: Bearer plantedbearer99"]}`, "plantedbearer99"},
		{"url userinfo", `{"url":"https://user:hunter2planted@h.example/mcp"}`, "hunter2planted"},
		{"url query", `{"url":"https://h.example/mcp?api_key=plantedquery77"}`, "plantedquery77"},
		{"x-api-key header", `{"url":"https://h.example/mcp","headers":{"X-API-Key":"plantedheader55"}}`, "plantedheader55"},
		{"env GITHUB_PAT", `{"command":"node","env":{"GITHUB_PAT":"plantedpat0001"}}`, "plantedpat0001"},
		{"env PRIVATE_KEY", `{"command":"node","env":{"PRIVATE_KEY":"plantedprivkey1"}}`, "plantedprivkey1"},
		{"env DATABASE_URL", `{"command":"node","env":{"DATABASE_URL":"postgres://u:plantedpgpass@db/app"}}`, "plantedpgpass"},
		{"sk- prefix", `{"command":"node","args":["s.js","sk-plantedplantedplanted1"]}`, "sk-plantedplantedplanted1"},
		{"xoxb- prefix", `{"command":"node","args":["s.js","xoxb-planted-planted-1234"]}`, "xoxb-planted-planted-1234"},
		{"glpat- prefix", `{"command":"node","args":["s.js","glpat-plantedplanted12"]}`, "glpat-plantedplanted12"},
		{"ghs_ prefix", `{"command":"node","args":["s.js","ghs_plantedplantedplanted"]}`, "ghs_plantedplantedplanted"},
		{"prefix after flag", `{"command":"node","args":["s.js","--auth=ghp_PLANTEDPLANTEDPLANTED"]}`, "ghp_PLANTEDPLANTEDPLANTED"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			path := writeConfig(t, `{"mcpServers":{"srv":`+row.server+`}}`)
			for _, format := range []string{"text", "json"} {
				out, errOut, code := runCLI(t, "--format", format, path)
				if code != 1 {
					t.Fatalf("%s: exit %d, want 1\n%s%s", format, code, out, errOut)
				}
				if !strings.Contains(out, "MCP-SECRET") {
					t.Fatalf("%s: no MCP-SECRET finding\n%s", format, out)
				}
				if strings.Contains(out+errOut, row.planted) {
					t.Fatalf("%s: leaked %q\n%s%s", format, row.planted, out, errOut)
				}
			}
		})
	}
}

// Near misses must not raise MCP-SECRET.
func TestCLISecretNearMisses(t *testing.T) {
	rows := []struct{ name, server string }{
		{"token-count flag", `{"command":"node","args":["s.js","--token-count","5"]}`},
		{"plain https url", `{"url":"https://h.example/mcp"}`},
		{"disk- is not sk-", `{"command":"node","args":["disk-tool-runner-for-things"]}`},
		{"plain args", `{"command":"node","args":["server.js","--port","8080"]}`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			path := writeConfig(t, `{"permissions":{"deny":["mcp__srv"]},"mcpServers":{"srv":`+row.server+`}}`)
			out, _, _ := runCLI(t, "--format", "text", path)
			if strings.Contains(out, "MCP-SECRET") {
				t.Fatalf("false positive:\n%s", out)
			}
		})
	}
}

func TestCLIShapes(t *testing.T) {
	supported := map[string]string{
		"vscode":  `{"servers":{"s":{"command":"node","args":["a.js"]}}}`,
		"claude":  `{"projects":{"/p":{"mcpServers":{"s":{"command":"node","args":["a.js"]}}}}}`,
		"zed":     `{"context_servers":{"s":{"command":"node","args":["a.js"]}}}`,
		"classic": `{"mcpServers":{"s":{"command":"node","args":["a.js"]}}}`,
	}
	for name, body := range supported {
		t.Run("supported "+name, func(t *testing.T) {
			out, _, code := runCLI(t, "--format", "text", writeConfig(t, body))
			if strings.Contains(out, "MCP-UNKNOWN-SHAPE") {
				t.Fatalf("shape rejected:\n%s", out)
			}
			// Supported shapes are evaluated: the server has no deny list.
			if code != 1 || !strings.Contains(out, "MCP-NO-DENY") {
				t.Fatalf("exit %d, server not evaluated:\n%s", code, out)
			}
		})
	}
	unknown := map[string]string{
		"null":                `null`,
		"empty object":        `{}`,
		"mcpServers null":     `{"mcpServers":null}`,
		"unrelated key":       `{"foo":1}`,
		"array root":          `[]`,
		"servers not object":  `{"servers":[]}`,
		"server not object":   `{"mcpServers":{"s":"npx"}}`,
		"projects wrong type": `{"projects":{"/p":5}}`,
	}
	for name, body := range unknown {
		t.Run("unknown "+name, func(t *testing.T) {
			out, _, code := runCLI(t, "--format", "text", writeConfig(t, body))
			if code != 1 || !strings.Contains(out, "MCP-UNKNOWN-SHAPE") {
				t.Fatalf("exit %d, want 1 with MCP-UNKNOWN-SHAPE:\n%s", code, out)
			}
		})
	}
	if _, _, code := runCLI(t, writeConfig(t, `{not json`)); code != 2 {
		t.Fatalf("invalid json exit %d, want 2", code)
	}
}

func TestCLIDeepNestingExits2(t *testing.T) {
	for _, depth := range []int{100, 9000} {
		body := strings.Repeat("[", depth) + strings.Repeat("]", depth)
		path := writeConfig(t, `{"mcpServers":{},"x":`+body+`}`)
		if _, _, code := runCLI(t, path); code != 2 {
			t.Fatalf("depth %d: exit %d, want 2", depth, code)
		}
	}
	// 1 MiB of brackets stays under the size cap and still must not exhaust memory.
	body := strings.Repeat("[", 500000) + strings.Repeat("]", 500000)
	if _, _, code := runCLI(t, writeConfig(t, body)); code != 2 {
		t.Fatalf("huge nesting: exit %d, want 2", code)
	}
}

func TestCLINonRegularAndSymlinkAndSize(t *testing.T) {
	if _, _, code := runCLI(t, "/dev/zero"); code != 2 {
		t.Fatalf("/dev/zero exit %d, want 2", code)
	}
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	if _, _, code := runCLI(t, fifo); code != 2 {
		t.Fatalf("fifo exit %d, want 2", code)
	}
	target := writeConfig(t, `{"mcpServers":{}}`)
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLI(t, link); code != 2 {
		t.Fatalf("symlink exit %d, want 2", code)
	}
	pad := func(n int) string {
		prefix := `{"mcpServers":{},"pad":"`
		suffix := `"}`
		return prefix + strings.Repeat("a", n-len(prefix)-len(suffix)) + suffix
	}
	if _, _, code := runCLI(t, writeConfig(t, pad(1<<20))); code != 0 {
		t.Fatalf("exactly 1 MiB exit %d, want 0", code)
	}
	if _, _, code := runCLI(t, writeConfig(t, pad(1<<20+1))); code != 2 {
		t.Fatalf("1 MiB + 1 exit %d, want 2", code)
	}
}
