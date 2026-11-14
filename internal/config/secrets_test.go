package config

import "testing"

func TestSecretStrings(t *testing.T) {
	yes := []string{
		"--token=ghp_ABCDEFGHIJKLMNOP",
		"Authorization: Bearer abcdef123456",
		"X-API-Key: abcdef123456",
		"https://user:hunter2@h.example/mcp",
		"https://h.example/mcp?api_key=abc123",
		"https://h.example/mcp?x=1&access-token=abc123",
		"DATABASE_URL=postgres://u:p@db/app",
		"postgres://u:p@db/app",
		"sk-abcdefghijklmnopqrstuv",
		"xoxb-123456789-abcdef",
		"glpat-abcdefghijklmnop",
		"ghs_abcdefghijklmnop",
		"github_pat_abcdefghijkl",
		"prefix ghp_ABCDEFGHIJKLMNOP suffix",
		"AKIAABCDEFGHIJKLMNOP",
		"GITHUB_PAT=abc123",
	}
	no := []string{
		"--token-count=5",
		"--token-count",
		"https://h.example/mcp",
		"https://user@h.example/mcp",
		"disk-tool-runner-for-things",
		"server.js",
		"task-runner-abcdefghijklmnopqrstuvwxyz",
		"--port=8080",
		"MAX_TOKENS=100",
		"",
	}
	for _, s := range yes {
		if !secretString(s) {
			t.Errorf("%q should be a secret", s)
		}
	}
	for _, s := range no {
		if secretString(s) {
			t.Errorf("%q should not be a secret", s)
		}
	}
}

func TestSecretName(t *testing.T) {
	for _, n := range []string{"API_TOKEN", "x-api-key", "GITHUB_PAT", "PRIVATE_KEY", "Authorization", "password", "client_secret", "apiKey"} {
		if !secretName(n) {
			t.Errorf("%q should be secret-named", n)
		}
	}
	for _, n := range []string{"token-count", "MAX_TOKENS", "PORT", "path", "patch", "tokens"} {
		if secretName(n) {
			t.Errorf("%q should not be secret-named", n)
		}
	}
}
