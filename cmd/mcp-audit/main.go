package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"mcp-audit/internal/config"
	"mcp-audit/internal/report"
	"mcp-audit/internal/rules"
)

const usage = "usage: mcp-audit [--format text|json] [--fail-on low|medium|high] file...\nflags must come before the files; pass a file whose name starts with - as ./name"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the whole program on one goroutine. It returns the exit code: 0 clean, 1 findings at or
// above --fail-on, 2 usage error or a file that could not be read.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "text", "text or json")
	failOn := fs.String("fail-on", "low", "exit non-zero at this severity or above: low, medium, high")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "%v\n%s\n", err, usage)
		return 2
	}
	files := fs.Args()
	if len(files) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	for _, file := range files {
		if strings.HasPrefix(file, "-") {
			fmt.Fprintf(stderr, "unexpected flag %q after a file name\n%s\n", file, usage)
			return 2
		}
	}
	switch *failOn {
	case "low", "medium", "high":
	default:
		fmt.Fprintln(stderr, "fail-on must be low, medium, or high")
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(stderr, "format must be text or json")
		return 2
	}
	var findings []rules.Finding
	failed := false
	for _, path := range files {
		file, err := config.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "read %q: %v\n", path, err)
			failed = true
			continue
		}
		findings = append(findings, rules.Evaluate(file)...)
	}
	rules.Sort(findings)
	var err error
	if *format == "json" {
		err = report.JSON(stdout, findings, *failOn)
	} else {
		err = report.Text(stdout, findings)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if failed {
		return 2
	}
	if report.Exceeds(findings, *failOn) {
		return 1
	}
	return 0
}
