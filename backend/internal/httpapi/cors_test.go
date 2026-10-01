package httpapi

import "testing"

func TestOriginAllowed(t *testing.T) {
	pats := []string{"http://localhost:5173", "https://prahari-*.vercel.app", "https://prahari.vercel.app"}
	for origin, want := range map[string]bool{
		"http://localhost:5173":                    true,
		"https://prahari.vercel.app":               true,
		"https://prahari-git-main-team.vercel.app": true,
		"https://prahari-abc123.vercel.app":        true,
		"https://prahari-.vercel.app":              false, // empty wildcard
		"https://prahari-x.evil.com/.vercel.app":   false, // wildcard may not cross '.' or '/'
		"https://prahari-a.b.vercel.app":           false,
		"https://evil.com":                         false,
		"http://prahari-x.vercel.app":              false, // scheme is part of the pattern
	} {
		if got := originAllowed(pats, origin); got != want {
			t.Errorf("%s: got %v, want %v", origin, got, want)
		}
	}
}
