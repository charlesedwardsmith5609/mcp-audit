package rules

import (
	"regexp"
	"strings"

	"mcp-audit/internal/config"
)

// launchSpec is a server's command after unwrapping env and cmd /c and splitting a command that
// was written as one string. chain holds the normalized basename of every wrapper and the final
// executable, so a shell hidden behind env is still seen.
type launchSpec struct {
	cmd   string
	args  []string
	chain []string
}

func baseName(token string) string {
	token = strings.Trim(strings.TrimSpace(token), `"'`)
	if i := strings.LastIndexAny(token, `/\`); i >= 0 {
		token = token[i+1:]
	}
	token = strings.ToLower(token)
	for _, suffix := range []string{".exe", ".cmd", ".bat"} {
		token = strings.TrimSuffix(token, suffix)
	}
	return token
}

func fieldsUnquoted(s string) []string {
	fields := strings.Fields(s)
	for i, f := range fields {
		fields[i] = strings.Trim(f, `"'`)
	}
	return fields
}

func knownExecutable(base string) bool {
	return launchers[base] || shells[base] || base == "env"
}

var launchers = map[string]bool{"npx": true, "uvx": true}

var shells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true, "csh": true,
	"tcsh": true, "ash": true, "pwsh": true, "powershell": true, "cmd": true,
}

func resolve(server config.Server) launchSpec {
	var tokens []string
	command := strings.TrimSpace(server.Command)
	if command != "" {
		if strings.ContainsAny(command, " \t") && !knownExecutable(baseName(command)) {
			tokens = fieldsUnquoted(command)
		} else {
			tokens = []string{command}
		}
	}
	tokens = append(tokens, server.Args...)
	var spec launchSpec
	for range 8 {
		if len(tokens) == 0 {
			break
		}
		base := baseName(tokens[0])
		spec.chain = append(spec.chain, base)
		if base == "env" {
			i := 1
			for i < len(tokens) {
				switch {
				case tokens[i] == "-u" || tokens[i] == "-C":
					i += 2
				case strings.HasPrefix(tokens[i], "-") || strings.Contains(tokens[i], "="):
					i++
				default:
					goto done
				}
			}
		done:
			if i > len(tokens) {
				i = len(tokens)
			}
			tokens = tokens[i:]
			continue
		}
		if base == "cmd" && len(tokens) >= 3 {
			switch strings.ToLower(tokens[1]) {
			case "/c", "/k", "/s":
				rest := tokens[2:]
				if len(rest) == 1 {
					rest = fieldsUnquoted(rest[0])
				}
				tokens = rest
				continue
			}
		}
		break
	}
	if len(tokens) > 0 {
		spec.cmd, spec.args = tokens[0], tokens[1:]
	}
	return spec
}

// valueFlags take a separate value token (or --flag=value). pkgFlags name the package to run.
var valueFlags = map[string]bool{
	"-p": true, "--package": true, "--from": true, "--with": true, "-w": true, "--python": true,
	"--index": true, "--index-url": true, "-i": true, "--extra-index-url": true,
	"--with-requirements": true, "--env-file": true, "--directory": true, "--project": true,
	"--cache-dir": true, "-c": true, "--call": true, "--registry": true, "--node-options": true,
	"--prefix": true, "--cwd": true, "--config": true,
}

var pkgFlags = map[string]bool{"-p": true, "--package": true, "--from": true}

var exactSemver = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

var driveRe = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

// localPath reports a positional that names a directory or script, not a package.
func localPath(arg string) bool {
	switch {
	case arg == "." || arg == "..", strings.HasPrefix(arg, "./"), strings.HasPrefix(arg, "../"),
		strings.HasPrefix(arg, "/"), strings.HasPrefix(arg, "~"), strings.HasPrefix(arg, `.\`),
		driveRe.MatchString(arg):
		return true
	}
	return strings.ContainsAny(arg, `/\`) && !strings.HasPrefix(arg, "@") && !strings.Contains(arg, ":")
}

// pinned accepts only an exact version: name@X.Y.Z (npm) or name==X.Y.Z (pip).
func pinned(spec string) bool {
	spec = strings.TrimSpace(spec)
	if i := strings.Index(spec, "=="); i > 0 {
		return exactSemver.MatchString(spec[i+2:])
	}
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return false
	}
	return exactSemver.MatchString(spec[at+1:])
}

// unpinned reports an npx or uvx launch whose package is not an exact version. The launcher must
// be the executable itself, not a word that happens to appear in args.
func unpinned(spec launchSpec) bool {
	if !launchers[baseName(spec.cmd)] {
		return false
	}
	var specs []string
	explicit := false
	positional, found := "", false
	for i := 0; i < len(spec.args); i++ {
		arg := spec.args[i]
		if arg == "--" {
			if i+1 < len(spec.args) {
				positional, found = spec.args[i+1], true
			}
			break
		}
		if strings.HasPrefix(arg, "-") {
			name, value, hasValue := strings.Cut(arg, "=")
			if !valueFlags[name] {
				continue
			}
			if !hasValue && i+1 < len(spec.args) {
				value = spec.args[i+1]
				i++
			}
			if pkgFlags[name] {
				explicit = true
				specs = append(specs, value)
			} else if name == "--with" || name == "-w" {
				specs = append(specs, value)
			}
			continue
		}
		if localPath(arg) {
			continue
		}
		positional, found = arg, true
		break
	}
	if !explicit {
		if !found {
			return true
		}
		specs = append(specs, positional)
	}
	for _, s := range specs {
		if !pinned(s) {
			return true
		}
	}
	return false
}

var pythonRe = regexp.MustCompile(`^python[0-9.]*$`)

// shell reports a shell wrapper or an interpreter running inline code.
func shell(spec launchSpec) bool {
	for _, base := range spec.chain {
		if shells[base] {
			return true
		}
	}
	base := baseName(spec.cmd)
	for _, arg := range spec.args {
		switch {
		case base == "node" || base == "nodejs" || base == "ruby" || base == "perl":
			if arg == "-e" || arg == "--eval" {
				return true
			}
		case pythonRe.MatchString(base):
			if arg == "-c" {
				return true
			}
		}
	}
	return false
}
