package report

import (
	"bytes"
	"strings"
	"testing"

	"mcp-audit/internal/rules"
)

func TestTextAndJSON(t *testing.T) {
	findings := []rules.Finding{{ID: "MCP-SHELL", Severity: "high", File: "a.json", Server: "sh", Fix: "Do not use a shell."}}
	var text bytes.Buffer
	if err := Text(&text, findings); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "MCP-SHELL") {
		t.Fatal(text.String())
	}
	var js bytes.Buffer
	if err := JSON(&js, nil, "low"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"findings": []`) {
		t.Fatal(js.String())
	}
	if !Exceeds(findings, "low") || Exceeds([]rules.Finding{{Severity: "medium"}}, "high") {
		t.Fatal("severity gate")
	}
}

func TestTextEscapesUntrustedFields(t *testing.T) {
	findings := []rules.Finding{{
		ID: "MCP-SHELL", Severity: "high", File: "a\nhigh FORGED x.json",
		Server: "s\x1b[2Jrv", Location: "$.a\nb", Fix: "Do not use a shell.",
	}}
	var text bytes.Buffer
	if err := Text(&text, findings); err != nil {
		t.Fatal(err)
	}
	out := text.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("escape byte reached the terminal: %q", out)
	}
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 2 {
		t.Fatalf("a control character split the output into %d lines: %q", len(lines), out)
	}
}
