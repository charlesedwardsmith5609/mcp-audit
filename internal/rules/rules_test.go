package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mcp-audit/internal/config"
)

func TestFixtures(t *testing.T) {
	cases := []struct {
		name string
		want []string
		hide []string
		not  []string
	}{
		{"pass.json", nil, nil, nil},
		{"unpinned.json", []string{"MCP-UNPINNED-PACKAGE", "MCP-BROAD-ROOT", "MCP-NO-DENY"}, nil, nil},
		{"secret.json", []string{"MCP-SECRET"}, []string{"ghp_EXAMPLEEXAMPLEEXAMPLEEX", "super-secret-value"}, nil},
		{"unknown-shape.json", []string{"MCP-UNKNOWN-SHAPE"}, nil, nil},
		{"http-shell.json", []string{"MCP-PLAIN-HTTP", "MCP-SHELL"}, nil, []string{"MCP-NO-DENY"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join("testdata", tc.name)
			file, err := config.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			findings := Evaluate(file)
			raw, err := json.Marshal(findings)
			if err != nil {
				t.Fatal(err)
			}
			for _, hidden := range tc.hide {
				if strings.Contains(string(raw), hidden) || strings.Contains(file.Path, hidden) {
					t.Fatalf("report leaked a secret: %s", raw)
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(body), hidden) {
					t.Fatalf("fixture lost the planted value %s", hidden)
				}
			}
			got := map[string]bool{}
			for _, finding := range findings {
				if finding.ID == "" || finding.Severity == "" || finding.Fix == "" {
					t.Fatalf("incomplete finding %+v", finding)
				}
				if finding.ID == "MCP-SECRET" && finding.Detail != "[REDACTED]" {
					t.Fatalf("secret detail: %+v", finding)
				}
				got[finding.ID] = true
			}
			if len(tc.want) == 0 && len(findings) != 0 {
				t.Fatalf("expected a clean file, got %s", raw)
			}
			for _, id := range tc.not {
				if got[id] {
					t.Fatalf("unexpected %s in %s", id, raw)
				}
			}
			for _, id := range tc.want {
				if !got[id] {
					t.Fatalf("missing %s in %s", id, raw)
				}
			}
		})
	}
}

// wrap puts one server body into a config with a matching deny entry, so only the rule under
// test can fire.
func wrap(body string) string {
	return `{"permissions":{"deny":["mcp__s"]},"mcpServers":{"s":` + body + `}}`
}

func evalBody(t *testing.T, body string) []Finding {
	t.Helper()
	file, err := config.Parse("t.json", []byte(body))
	if err != nil {
		t.Fatalf("parse %s: %v", body, err)
	}
	return Evaluate(file)
}

func hasID(findings []Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestDenyIsPerServer(t *testing.T) {
	cases := []struct {
		name, body string
		noDeny     []string // servers expected to have MCP-NO-DENY
	}{
		{"one server with disabledTools does not clear the other",
			`{"mcpServers":{"a":{"command":"node","disabledTools":["x"]},"b":{"command":"node"}}}`, []string{"b"}},
		{"empty deny array does not count",
			`{"mcpServers":{"a":{"command":"node","deny":[]}}}`, []string{"a"}},
		{"null does not count",
			`{"mcpServers":{"a":{"command":"node","disabledTools":null}}}`, []string{"a"}},
		{"wrong type does not count",
			`{"mcpServers":{"a":{"command":"node","deniedTools":"x"}}}`, []string{"a"}},
		{"unrelated permissions.deny does not count",
			`{"permissions":{"deny":["Bash(rm:*)"]},"mcpServers":{"a":{"command":"node"}}}`, []string{"a"}},
		{"empty permissions.deny does not count",
			`{"permissions":{"deny":[]},"mcpServers":{"a":{"command":"node"}}}`, []string{"a"}},
		{"mcp__ entry counts only for its server",
			`{"permissions":{"deny":["mcp__a__delete"]},"mcpServers":{"a":{"command":"node"},"b":{"command":"node"}}}`, []string{"b"}},
		{"prefix of another server name does not count",
			`{"permissions":{"deny":["mcp__ab"]},"mcpServers":{"a":{"command":"node"}}}`, []string{"a"}},
		{"non-empty disabledTools counts",
			`{"mcpServers":{"a":{"command":"node","disabledTools":["x"]}}}`, nil},
		{"non-empty deniedTools counts",
			`{"mcpServers":{"a":{"command":"node","deniedTools":["x"]}}}`, nil},
		{"bare mcp__a entry counts",
			`{"permissions":{"deny":["mcp__a"]},"mcpServers":{"a":{"command":"node"}}}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, f := range evalBody(t, tc.body) {
				if f.ID == "MCP-NO-DENY" {
					if f.Server == "" {
						t.Fatalf("MCP-NO-DENY without Server: %+v", f)
					}
					got = append(got, f.Server)
				}
			}
			if strings.Join(got, ",") != strings.Join(tc.noDeny, ",") {
				t.Fatalf("NO-DENY servers = %v, want %v", got, tc.noDeny)
			}
		})
	}
}

func TestPinTable(t *testing.T) {
	unpinnedSpecs := []string{"pkg@^1", "pkg@~1.2", "pkg@*", "pkg@1", "pkg@1.x", "pkg@next", "pkg@beta",
		"pkg@LATEST", "pkg@latest", "pkg@1.2", "pkg@>=1.0.0", "pkg", "@scope/pkg", "@scope/pkg@^1.2.3"}
	for _, spec := range unpinnedSpecs {
		if body := wrap(`{"command":"npx","args":["-y","` + spec + `"]}`); !hasID(evalBody(t, body), "MCP-UNPINNED-PACKAGE") {
			t.Errorf("npx %s should be unpinned", spec)
		}
	}
	for _, spec := range []string{"pkg==1.*", "pkg==1", "pkg==LATEST", "pkg==", "pkg", "pkg>=1.0.0", "pkg==1.2"} {
		if body := wrap(`{"command":"uvx","args":["` + spec + `"]}`); !hasID(evalBody(t, body), "MCP-UNPINNED-PACKAGE") {
			t.Errorf("uvx %s should be unpinned", spec)
		}
	}
	for _, spec := range []string{"pkg@1.2.3", "@scope/pkg@1.2.3", "pkg@1.2.3-beta.1", "pkg@1.2.3+build5"} {
		if body := wrap(`{"command":"npx","args":["-y","` + spec + `"]}`); hasID(evalBody(t, body), "MCP-UNPINNED-PACKAGE") {
			t.Errorf("npx %s should be pinned", spec)
		}
	}
	if hasID(evalBody(t, wrap(`{"command":"uvx","args":["pkg==1.2.3"]}`)), "MCP-UNPINNED-PACKAGE") {
		t.Error("uvx pkg==1.2.3 should be pinned")
	}
}

func TestLauncherTable(t *testing.T) {
	flagged := map[string]string{
		"npx.exe":            `{"command":"npx.exe","args":["-y","evil"]}`,
		"NPX.CMD":            `{"command":"NPX.CMD","args":["evil"]}`,
		"full path":          `{"command":"C:\\tools\\npx.cmd","args":["evil"]}`,
		"single string":      `{"command":"npx -y evil"}`,
		"uvx.exe":            `{"command":"uvx.exe","args":["evil"]}`,
		"package flag unpin": `{"command":"npx","args":["--package=foo@^1","foo"]}`,
		"uvx from unpinned":  `{"command":"uvx","args":["--from","foo>=1","foo"]}`,
		"cmd /c unpinned":    `{"command":"cmd","args":["/c","npx","-y","pkg"]}`,
		"cmd /c single":      `{"command":"cmd.exe","args":["/c","npx -y pkg"]}`,
		"github shorthand":   `{"command":"npx","args":["github:user/repo"]}`,
		"python flag unpin":  `{"command":"uvx","args":["--python","3.12","pkg"]}`,
	}
	for name, server := range flagged {
		if !hasID(evalBody(t, wrap(server)), "MCP-UNPINNED-PACKAGE") {
			t.Errorf("%s should be flagged: %s", name, server)
		}
	}
	clean := map[string]string{
		"uvx --python value":   `{"command":"uvx","args":["--python","3.12","pkg==1.0.0"]}`,
		"npx --package=":       `{"command":"npx","args":["--package=foo@1.0.0","foo"]}`,
		"npx --package value":  `{"command":"npx","args":["--package","foo@1.0.0","foo"]}`,
		"uvx --from":           `{"command":"uvx","args":["--from","foo==1.0.0","foo"]}`,
		"cmd /c pinned":        `{"command":"cmd","args":["/c","npx","-y","pkg@1.0.0"]}`,
		"single string pinned": `{"command":"npx -y pkg@1.0.0"}`,
		"path positional":      `{"command":"npx","args":["-y","pkg@1.0.0","/work/task"]}`,
		"not a launcher":       `{"command":"node","args":["npx","server.js"]}`,
	}
	for name, server := range clean {
		if hasID(evalBody(t, wrap(server)), "MCP-UNPINNED-PACKAGE") {
			t.Errorf("%s should not be flagged: %s", name, server)
		}
	}
	for name, body := range map[string]string{
		"args string":      wrap(`{"command":"npx","args":"-y evil"}`),
		"args number item": wrap(`{"command":"npx","args":["-y",5]}`),
		"env array":        wrap(`{"command":"node","env":["A=b"]}`),
		"env non-string":   wrap(`{"command":"node","env":{"A":5}}`),
		"command number":   wrap(`{"command":5}`),
	} {
		if _, err := config.Parse("t.json", []byte(body)); err == nil {
			t.Errorf("%s: want parse error", name)
		}
	}
}

func TestRootTable(t *testing.T) {
	roots := []string{`/`, `//`, `/.`, `~`, `~/`, `$HOME`, `$HOME/`, `${HOME}`, `${HOME}/`, `%USERPROFILE%`, `%USERPROFILE%\\`,
		`C:\\`, `C:/`, `c:`, `/home/alice`, `/home/alice/`, `/Users/alice`, `file:///`, `file:///home/alice`, ` / `, `C:\\Users\\alice`}
	for _, root := range roots {
		for _, args := range []string{`["` + root + `"]`, `["--root=` + root + `"]`, `["--root","` + root + `"]`, `["--allowed-directory","` + root + `"]`} {
			if !hasID(evalBody(t, wrap(`{"command":"node","args":`+args+`}`)), "MCP-BROAD-ROOT") {
				t.Errorf("root %q in %s should be flagged", root, args)
			}
		}
	}
	for _, args := range []string{
		`["run","-v","/:/host","img"]`, `["run","--volume=/:/host","img"]`, `["run","-v","/home/alice:/h","img"]`,
		`["run","--mount","type=bind,source=/,target=/host","img"]`, `["run","-v","$HOME:/h","img"]`,
	} {
		if !hasID(evalBody(t, wrap(`{"command":"docker","args":`+args+`}`)), "MCP-BROAD-ROOT") {
			t.Errorf("docker %s should be flagged", args)
		}
	}
	for _, ok := range []string{`/srv/task`, `/work/task`, `./data`, `/home/alice/project`, `/Users/alice/code`, `C:\\work`, `~/project`, `$HOME/project`} {
		if hasID(evalBody(t, wrap(`{"command":"node","args":["`+ok+`"]}`)), "MCP-BROAD-ROOT") {
			t.Errorf("%q should not be flagged", ok)
		}
	}
	if hasID(evalBody(t, wrap(`{"command":"docker","args":["run","-v","/srv/task:/work","img"]}`)), "MCP-BROAD-ROOT") {
		t.Error("narrow docker mount should not be flagged")
	}
}

func TestPlainHTTPTable(t *testing.T) {
	flagged := []string{
		`{"url":"http://h.example/mcp"}`, `{"serverUrl":"http://h.example/mcp"}`, `{"httpUrl":"http://h.example/mcp"}`,
		`{"url":"ws://h.example/mcp"}`, `{"url":"  http://h.example/mcp"}`, `{"url":"HTTP://h.example/mcp"}`,
		`{"command":"npx","args":["mcp-remote@1.0.0","http://evil.example/mcp"]}`,
		`{"command":"npx","args":["mcp-remote@1.0.0 http://evil.example/mcp"]}`,
		`{"command":"node","args":["s.js","--url=ws://evil.example/mcp"]}`,
	}
	for _, server := range flagged {
		if !hasID(evalBody(t, wrap(server)), "MCP-PLAIN-HTTP") {
			t.Errorf("should flag %s", server)
		}
	}
	for _, server := range []string{
		`{"url":"https://h.example/mcp"}`, `{"url":"wss://h.example/mcp"}`, `{"serverUrl":"https://h.example"}`,
		`{"command":"npx","args":["mcp-remote@1.0.0","https://h.example/mcp"]}`, `{"command":"node","args":["http-server.js"]}`,
	} {
		if hasID(evalBody(t, wrap(server)), "MCP-PLAIN-HTTP") {
			t.Errorf("should not flag %s", server)
		}
	}
}

func TestShellTable(t *testing.T) {
	flagged := []string{
		`{"command":"sh"}`, `{"command":"bash"}`, `{"command":"zsh"}`, `{"command":"dash"}`, `{"command":"ksh"}`,
		`{"command":"fish"}`, `{"command":"csh"}`, `{"command":"tcsh"}`, `{"command":"bash.exe"}`, `{"command":"pwsh.exe"}`,
		`{"command":"PowerShell.exe"}`, `{"command":"BASH"}`, `{"command":"/usr/bin/bash"}`, `{"command":"cmd.exe"}`,
		`{"command":"env","args":["bash","-c","x"]}`, `{"command":"/usr/bin/env","args":["-i","FOO=1","sh","-c","x"]}`,
		`{"command":"node","args":["-e","require('x')"]}`, `{"command":"node","args":["--eval","x"]}`,
		`{"command":"python","args":["-c","import x"]}`, `{"command":"python3","args":["-c","import x"]}`,
		`{"command":"bash -c 'x'"}`,
	}
	for _, server := range flagged {
		if !hasID(evalBody(t, wrap(server)), "MCP-SHELL") {
			t.Errorf("should flag %s", server)
		}
	}
	for _, server := range []string{
		`{"command":"node","args":["server.js"]}`, `{"command":"python","args":["app.py"]}`, `{"command":"python3","args":["-m","server"]}`,
		`{"command":"env","args":["FOO=1","node","server.js"]}`, `{"command":"bashful"}`,
	} {
		if hasID(evalBody(t, wrap(server)), "MCP-SHELL") {
			t.Errorf("should not flag %s", server)
		}
	}
}

func TestSecretReferencesAndBenignNames(t *testing.T) {
	for _, env := range []string{
		`{"API_TOKEN":"${API_TOKEN}"}`, `{"API_TOKEN":"$API_TOKEN"}`, `{"API_TOKEN":"%API_TOKEN%"}`, `{"API_TOKEN":""}`,
		`{"MAX_TOKENS":"100"}`, `{"TOKEN_COUNT":"3"}`,
	} {
		if hasID(evalBody(t, wrap(`{"command":"node","env":`+env+`}`)), "MCP-SECRET") {
			t.Errorf("env %s should not be a secret", env)
		}
	}
	for _, server := range []string{
		`{"command":"node","env":{"API_TOKEN":5}}`, `{"command":"node","env":{"API_TOKEN":true}}`,
		`{"command":"node","args":["--token","${TOKEN}"]}`, `{"command":"node","args":["--token=${TOKEN}"]}`,
		`{"url":"https://h.example/mcp","headers":{"Authorization":"Bearer ${TOKEN}"}}`,
		`{"url":"https://u:${PASS}@h.example/mcp"}`,
	} {
		file, err := config.Parse("t.json", []byte(wrap(server)))
		if err != nil {
			continue // wrong-typed env is a parse error; also acceptable for non-string values
		}
		if hasID(Evaluate(file), "MCP-SECRET") {
			t.Errorf("%s should not be a secret", server)
		}
	}
	if !hasID(evalBody(t, wrap(`{"command":"node","env":{"API_TOKEN":"real-value-1"}}`)), "MCP-SECRET") {
		t.Error("a literal API_TOKEN value must still be a secret")
	}
}

func TestSecretKeyAndServerNamesRedacted(t *testing.T) {
	token := "ghp_PLANTEDKEYNAMEPLANTED"
	body := `{"permissions":{"deny":["mcp__` + token + `"]},"mcpServers":{"` + token + `":{"command":"bash","args":["` + token + `"],"env":{"` + token + `":"v"}}}}`
	raw, err := json.Marshal(evalBody(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) {
		t.Fatalf("findings leak a secret-looking name: %s", raw)
	}
	if !strings.Contains(string(raw), "[REDACTED]") {
		t.Fatalf("expected [REDACTED]: %s", raw)
	}
}

func TestLocationBracketNotation(t *testing.T) {
	body := wrap(`{"command":"node","env":{"a.b":"x","c[0]":"y","API_TOKEN":"z"}}`)
	var locs []string
	for _, f := range evalBody(t, body) {
		if f.ID == "MCP-SECRET" {
			locs = append(locs, f.Location)
		}
	}
	if len(locs) != 1 || locs[0] != `$.mcpServers.s.env.API_TOKEN` {
		t.Fatalf("locations: %v", locs)
	}
	body = wrap(`{"command":"node","env":{"a.b_TOKEN":"x"}}`)
	for _, f := range evalBody(t, body) {
		if f.ID == "MCP-SECRET" && f.Location != `$.mcpServers.s.env["a.b_TOKEN"]` {
			t.Fatalf("dotted key location: %q", f.Location)
		}
	}
}
