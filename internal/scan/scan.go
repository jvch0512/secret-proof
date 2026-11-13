// Package scan finds secrets in text and judges how likely each one is to be real, offline.
package scan

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Verdict string

const (
	Confirmed Verdict = "structure-confirmed" // an offline check only the real format passes (checksum)
	Plausible Verdict = "plausible"            // right shape and entropy, nothing offline can confirm it
	Fake      Verdict = "likely-fake"          // checksum fails, placeholder or low entropy
)

type Finding struct {
	File    string  `json:"file"`
	Line    int     `json:"line"`
	Kind    string  `json:"kind"`
	Verdict Verdict `json:"verdict"`
	Preview string  `json:"preview"`
	Why     string  `json:"why"`
}

type Item struct{ Name, Text string }

const b62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Base62CRC encodes the CRC32 of s as 6 base62 characters, the scheme used by GitHub and npm tokens.
func Base62CRC(s string) string {
	n := crc32.ChecksumIEEE([]byte(s))
	out := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		out[i] = b62[n%62]
		n /= 62
	}
	return string(out)
}

// ForgeGitHubToken builds a checksum-valid token. Used by tests and the demo, never to attack anything.
func ForgeGitHubToken(prefix, body30 string) string { return prefix + "_" + body30 + Base62CRC(body30) }

func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	c := map[rune]float64{}
	for _, r := range s {
		c[r]++
	}
	var h float64
	for _, n := range c {
		p := n / float64(len([]rune(s)))
		h -= p * math.Log2(p)
	}
	return h
}

func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6) + s[len(s)-2:]
}

var (
	reGH     = regexp.MustCompile(`\b(gh[pousr]|npm)_([A-Za-z0-9]{36})\b`)
	reAWS    = regexp.MustCompile(`\b(AKIA|ASIA)[A-Z2-7]{16}\b`)
	rePEM    = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----`)
	reJWT    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*\b`)
	reSlack  = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)
	reAssign = regexp.MustCompile(`(?i)(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key)\w*["']?\s*[:=]\s*["']([^"'\s]{16,})["']`)
	placeholder = regexp.MustCompile(`(?i)(example|changeme|placeholder|your[_-]|xxxx|dummy|sample|test|\*\*\*|<.*>|\$\{)`)
)

func Scan(items []Item, now time.Time) []Finding {
	var out []Finding
	for _, it := range items {
		for i, ln := range strings.Split(it.Text, "\n") {
			add := func(kind string, v Verdict, tok, why string) {
				out = append(out, Finding{File: it.Name, Line: i + 1, Kind: kind, Verdict: v, Preview: redact(tok), Why: why})
			}
			for _, m := range reGH.FindAllStringSubmatch(ln, -1) {
				body, sum := m[2][:30], m[2][30:]
				name := map[string]string{"ghp": "GitHub personal access token", "gho": "GitHub OAuth token", "ghu": "GitHub user-to-server token", "ghs": "GitHub server-to-server token", "ghr": "GitHub refresh token", "npm": "npm access token"}[m[1]]
				if Base62CRC(body) == sum {
					add(name, Confirmed, m[0], "the 6-character CRC32 checksum matches: this is a real-format token, treat it as live and revoke it")
				} else {
					add(name, Fake, m[0], "checksum does not match: fabricated, truncated or mistyped")
				}
			}
			for _, m := range reAWS.FindAllString(ln, -1) {
				kind := "AWS access key ID"
				if strings.HasPrefix(m, "ASIA") {
					kind = "AWS temporary access key ID"
				}
				if placeholder.MatchString(ln) || strings.Contains(m, "EXAMPLE") {
					add(kind, Fake, m, "placeholder or documentation value")
				} else {
					add(kind, Plausible, m, "valid shape; check CloudTrail and rotate. An ID alone is not a secret key, look for the paired secret nearby")
				}
			}
			if rePEM.MatchString(ln) {
				add("private key block", Plausible, "-----BEGIN KEY", "a private key is committed: rotate anything it protects")
			}
			for _, m := range reJWT.FindAllString(ln, -1) {
				v, why := judgeJWT(m, now)
				add("JWT", v, m, why)
			}
			for _, m := range reSlack.FindAllString(ln, -1) {
				if placeholder.MatchString(ln) {
					add("Slack token", Fake, m, "placeholder value")
				} else {
					add("Slack token", Plausible, m, "valid shape; revoke in the Slack admin console")
				}
			}
			for _, m := range reAssign.FindAllStringSubmatch(ln, -1) {
				val := m[1]
				switch {
				case reGH.MatchString(val) || reAWS.MatchString(val) || reSlack.MatchString(val):
					continue // reported by a specific detector
				case placeholder.MatchString(val):
					add("hard-coded secret", Fake, val, "looks like a placeholder")
				case Entropy(val) >= 3.5:
					add("hard-coded secret", Plausible, val, fmt.Sprintf("high-entropy value (%.1f bits per character) assigned to a secret-like name", Entropy(val)))
				default:
					add("hard-coded secret", Fake, val, fmt.Sprintf("low entropy (%.1f bits per character)", Entropy(val)))
				}
			}
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return rank(out[a].Verdict) < rank(out[b].Verdict) })
	return out
}

func rank(v Verdict) int {
	switch v {
	case Confirmed:
		return 0
	case Plausible:
		return 1
	}
	return 2
}

func judgeJWT(tok string, now time.Time) (Verdict, string) {
	parts := strings.Split(tok, ".")
	dec := func(s string) map[string]any {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return nil
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return nil
		}
		return m
	}
	h, p := dec(parts[0]), dec(parts[1])
	if h == nil || p == nil {
		return Fake, "not a decodable JWT"
	}
	alg, _ := h["alg"].(string)
	if strings.EqualFold(alg, "none") {
		return Plausible, "alg=none token: any claim set is accepted by a vulnerable verifier"
	}
	if exp, ok := p["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(now) {
			return Fake, fmt.Sprintf("expired on %s: harmless unless the signing key leaked too", time.Unix(int64(exp), 0).UTC().Format("2006-01-02"))
		}
		return Plausible, fmt.Sprintf("unexpired (valid until %s): revoke and rotate the signing key if it is production", time.Unix(int64(exp), 0).UTC().Format("2006-01-02"))
	}
	return Plausible, "JWT without an expiry claim: it never stops working until the key rotates"
}
