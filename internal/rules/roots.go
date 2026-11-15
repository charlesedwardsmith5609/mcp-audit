package rules

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

var (
	homeVarRe  = regexp.MustCompile(`(?i)^(?:\$\{HOME\}|\$HOME|\$\{USERPROFILE\}|\$USERPROFILE|%USERPROFILE%|%HOME%)`)
	driveRoot  = regexp.MustCompile(`(?i)^/?[a-z]:/*$`)
	homeDirRe  = regexp.MustCompile(`(?i)^/(?:home|users)/[^/]+$|^/?[a-z]:/users/[^/]+$|^/root$`)
	fileDriveR = regexp.MustCompile(`^/[A-Za-z]:`)
)

// isRoot reports a path that is the filesystem root, a drive root or a home directory, after
// normalizing separators, environment variables, "." and "//" segments and file:// prefixes.
func isRoot(value string) bool {
	s := strings.Trim(strings.TrimSpace(value), `"'`)
	s = strings.ReplaceAll(s, `\`, "/")
	if len(s) >= 7 && strings.EqualFold(s[:7], "file://") {
		s = s[7:]
		if fileDriveR.MatchString(s) {
			s = s[1:]
		}
	}
	s = homeVarRe.ReplaceAllString(s, "~")
	if driveRoot.MatchString(s) {
		return true
	}
	clean := path.Clean(s)
	if clean == "/" || clean == "~" {
		return true
	}
	return homeDirRe.MatchString(clean)
}

// tokens flattens args, splitting any arg that holds whitespace ("-v /:/host", "mcp-remote http://x").
func tokens(args []string) []string {
	var out []string
	for _, arg := range args {
		if strings.ContainsAny(arg, " \t") {
			out = append(out, fieldsUnquoted(arg)...)
		} else {
			out = append(out, arg)
		}
	}
	return out
}

func afterEquals(arg string) (string, bool) {
	_, value, ok := strings.Cut(arg, "=")
	return value, ok
}

// volumeSource returns the host side of a docker -v value (src:dst[:opts]).
func volumeSource(v string) string {
	if driveRe.MatchString(v) {
		if i := strings.Index(v[2:], ":"); i >= 0 {
			return v[:i+2]
		}
		return v
	}
	src, _, _ := strings.Cut(v, ":")
	return src
}

func mountSource(v string) string {
	for _, pair := range strings.Split(v, ",") {
		key, value, _ := strings.Cut(pair, "=")
		if key == "source" || key == "src" {
			return value
		}
	}
	return ""
}

func broadRoot(args []string) bool {
	toks := tokens(args)
	for i, arg := range toks {
		if isRoot(arg) {
			return true
		}
		if value, ok := afterEquals(arg); ok {
			if isRoot(value) {
				return true
			}
			switch {
			case strings.HasPrefix(arg, "--volume="), strings.HasPrefix(arg, "-v="):
				if isRoot(volumeSource(value)) {
					return true
				}
			case strings.HasPrefix(arg, "--mount="):
				if isRoot(mountSource(value)) {
					return true
				}
			}
		}
		if i+1 >= len(toks) {
			continue
		}
		switch arg {
		case "-v", "--volume":
			if isRoot(volumeSource(toks[i+1])) {
				return true
			}
		case "--mount":
			if isRoot(mountSource(toks[i+1])) {
				return true
			}
		}
	}
	return false
}

// plainHTTP reports a url field or an http:// or ws:// URL anywhere in the launch arguments.
func plainHTTP(urls []string, args []string) bool {
	candidates := append([]string{}, urls...)
	for _, arg := range tokens(args) {
		candidates = append(candidates, arg)
		if value, ok := afterEquals(arg); ok {
			candidates = append(candidates, value)
		}
	}
	for _, c := range candidates {
		c = strings.Trim(strings.TrimSpace(c), `"'`)
		if !strings.Contains(c, "://") {
			continue
		}
		scheme := strings.ToLower(c[:strings.Index(c, "://")])
		if u, err := url.Parse(c); err == nil {
			scheme = u.Scheme
		}
		if scheme == "http" || scheme == "ws" {
			return true
		}
	}
	return false
}
