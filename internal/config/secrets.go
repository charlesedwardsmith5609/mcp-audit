package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// tokenRe matches well-known credential prefixes. The prefix must start the string or follow a
// non-alphanumeric character, so "disk-tool" does not match "sk-".
var tokenRe = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,}|glpat-[A-Za-z0-9_-]{12,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})`)

var (
	headerRe = regexp.MustCompile(`(?i)^(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token)\s*[:=]\s*\S+`)
	bearerRe = regexp.MustCompile(`(?i)^bearer\s+\S{8,}`)
	assignRe = regexp.MustCompile(`^-{0,2}([A-Za-z][A-Za-z0-9_.-]*)=(.+)$`)
)

var secretWords = []string{
	"secret", "token", "password", "passwd", "passphrase", "api_key", "apikey",
	"private_key", "privatekey", "access_key", "credential", "authorization", "bearer",
}

// benignSuffixes name counts and limits, not credentials (MAX_TOKENS, --token-count).
var benignSuffixes = []string{"_count", "_tokens", "_limit", "_len", "_length", "_size", "_ttl", "_expiry", "_file", "_path"}

func normalizeName(name string) string {
	name = strings.ToLower(strings.TrimLeft(name, "-"))
	return strings.NewReplacer("-", "_", ".", "_").Replace(name)
}

// secretName reports whether a key or flag name holds a credential.
func secretName(name string) bool {
	n := normalizeName(name)
	if n == "tokens" {
		return false
	}
	for _, suffix := range benignSuffixes {
		if strings.HasSuffix(n, suffix) {
			return false
		}
	}
	for _, word := range secretWords {
		if strings.Contains(n, word) {
			return true
		}
	}
	for _, segment := range strings.Split(n, "_") {
		if segment == "pat" {
			return true
		}
	}
	return false
}

// secretString reports whether a string value carries a credential in any supported form.
func secretString(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if tokenRe.MatchString(s) || headerRe.MatchString(s) || bearerRe.MatchString(s) {
		return true
	}
	if m := assignRe.FindStringSubmatch(s); m != nil {
		if secretName(m[1]) || secretString(m[2]) {
			return true
		}
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			if u.User != nil {
				if pw, ok := u.User.Password(); ok && pw != "" {
					return true
				}
			}
			for key, values := range u.Query() {
				if !secretName(key) {
					continue
				}
				for _, v := range values {
					if v != "" {
						return true
					}
				}
			}
		}
	}
	if fields := strings.Fields(s); len(fields) > 1 {
		for _, field := range fields {
			if secretString(field) {
				return true
			}
		}
	}
	return false
}

// walkSecrets visits every object, array and string in the decoded tree. Sites record the JSON
// path only; the value is never copied.
func walkSecrets(path string, v any) []SecretSite {
	switch t := v.(type) {
	case string:
		if secretString(t) {
			return []SecretSite{{Path: path}}
		}
	case map[string]any:
		var out []SecretSite
		for key, value := range t {
			if secretName(key) {
				out = append(out, SecretSite{Path: path + "." + key})
				continue
			}
			out = append(out, walkSecrets(path+"."+key, value)...)
		}
		return out
	case []any:
		var out []SecretSite
		valueOf := -1
		for i, value := range t {
			here := fmt.Sprintf("%s[%d]", path, i)
			if i == valueOf {
				out = append(out, SecretSite{Path: here})
				continue
			}
			if s, ok := value.(string); ok && strings.HasPrefix(s, "-") && !strings.Contains(s, "=") && secretName(s) && i+1 < len(t) {
				if next, ok := t[i+1].(string); ok && next != "" && !strings.HasPrefix(next, "-") {
					valueOf = i + 1
				}
			}
			out = append(out, walkSecrets(here, value)...)
		}
		return out
	}
	return nil
}
