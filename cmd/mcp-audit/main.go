package main

import (
	"flag"
	"fmt"
	"os"

	"mcp-audit/internal/config"
	"mcp-audit/internal/report"
	"mcp-audit/internal/rules"
)

func main() {
	format := flag.String("format", "text", "text or json")
	failOn := flag.String("fail-on", "low", "exit non-zero at this severity or above: low, medium, high")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: mcp-audit [--format text|json] [--fail-on low|medium|high] file...")
		os.Exit(2)
	}
	switch *failOn {
	case "low", "medium", "high":
	default:
		fmt.Fprintln(os.Stderr, "fail-on must be low, medium, or high")
		os.Exit(2)
	}
	var findings []rules.Finding
	for _, path := range flag.Args() {
		file, err := config.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
			os.Exit(2)
		}
		findings = append(findings, rules.Evaluate(file)...)
	}
	var err error
	if *format == "json" {
		err = report.JSON(os.Stdout, findings, *failOn)
	} else if *format == "text" {
		err = report.Text(os.Stdout, findings)
	} else {
		fmt.Fprintln(os.Stderr, "format must be text or json")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if report.Exceeds(findings, *failOn) {
		os.Exit(1)
	}
}
