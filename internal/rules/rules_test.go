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
	}{
		{"pass.json", nil, nil},
		{"unpinned.json", []string{"MCP-UNPINNED-PACKAGE", "MCP-BROAD-ROOT", "MCP-NO-DENY"}, nil},
		{"secret.json", []string{"MCP-SECRET"}, []string{"ghp_EXAMPLEEXAMPLEEXAMPLEEX", "super-secret-value"}},
		{"unknown-shape.json", []string{"MCP-UNKNOWN-SHAPE"}, nil},
		{"http-shell.json", []string{"MCP-PLAIN-HTTP", "MCP-SHELL"}, nil},
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
			for _, id := range tc.want {
				if !got[id] {
					t.Fatalf("missing %s in %s", id, raw)
				}
			}
		})
	}
}
