package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"mcp-audit/internal/rules"
)

func Rank(severity string) int {
	switch strings.ToLower(severity) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 3
	}
}

func Exceeds(findings []rules.Finding, failOn string) bool {
	limit := Rank(failOn)
	for _, finding := range findings {
		if Rank(finding.Severity) >= limit {
			return true
		}
	}
	return false
}

func Text(w io.Writer, findings []rules.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "no findings")
		return err
	}
	for _, finding := range findings {
		// File, server and location come from untrusted input: quote them so control
		// characters cannot forge lines or move the cursor.
		line := fmt.Sprintf("%s %s %q", finding.Severity, finding.ID, finding.File)
		if finding.Server != "" {
			line += fmt.Sprintf(" server %q", finding.Server)
		}
		if finding.Location != "" {
			line += fmt.Sprintf(" at %q", finding.Location)
		}
		if finding.Detail != "" {
			line += " " + finding.Detail
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  fix: %s\n", finding.Fix); err != nil {
			return err
		}
	}
	return nil
}

func JSON(w io.Writer, findings []rules.Finding, failOn string) error {
	if findings == nil {
		findings = []rules.Finding{}
	}
	payload := struct {
		FailOn   string          `json:"fail_on"`
		Findings []rules.Finding `json:"findings"`
	}{FailOn: failOn, Findings: findings}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
