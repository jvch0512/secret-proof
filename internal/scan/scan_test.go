package scan

import (
	"strings"
	"testing"
	"time"
)

func one(t *testing.T, text string) []Finding {
	t.Helper()
	return Scan([]Item{{"f.txt", text}}, time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC))
}

func TestChecksumKnownVector(t *testing.T) {
	// CRC32 of "123456789" is 0xCBF43926 = 3421780262; verify the encoder round-trips through base62
	s := Base62CRC("123456789")
	if len(s) != 6 {
		t.Fatalf("want 6 chars, got %q", s)
	}
	var n uint64
	for _, c := range s {
		n = n*62 + uint64(strings.IndexRune(b62, c))
	}
	if n != 0xCBF43926 {
		t.Fatalf("checksum %x", n)
	}
}

func TestValidGitHubTokenIsConfirmed(t *testing.T) {
	tok := ForgeGitHubToken("ghp", "aB3dE5gH7jK9mN1pQ3sT5vX7zC9eF1")
	f := one(t, "x="+tok)
	if len(f) != 1 || f[0].Verdict != Confirmed {
		t.Fatalf("%+v", f)
	}
}

func TestBadChecksumIsFake(t *testing.T) {
	f := one(t, "ghp_aB3dE5gH7jK9mN1pQ3sT5vX7zC9eF1AAAAAA")
	if len(f) != 1 || f[0].Verdict != Fake {
		t.Fatalf("%+v", f)
	}
}

func TestNpmTokenUsesSameScheme(t *testing.T) {
	f := one(t, ForgeGitHubToken("npm", "aB3dE5gH7jK9mN1pQ3sT5vX7zC9eF1"))
	if len(f) != 1 || f[0].Verdict != Confirmed || f[0].Kind != "npm access token" {
		t.Fatalf("%+v", f)
	}
}

func TestAWSExampleKeyIsFakeButRealShapeIsPlausible(t *testing.T) {
	if f := one(t, "AKIAIOSFODNN7EXAMPLE"); f[0].Verdict != Fake {
		t.Fatal("documentation key should be fake")
	}
	if f := one(t, "AKIAQ4ZTR7MWNB2KX5HD"); f[0].Verdict != Plausible {
		t.Fatal("real shape should be plausible")
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	if f := one(t, "-----BEGIN OPENSSH PRIVATE KEY-----"); len(f) != 1 || f[0].Kind != "private key block" {
		t.Fatalf("%+v", f)
	}
}

func TestJWTVariants(t *testing.T) {
	now := DemoNow
	live := jwt("HS256", now.Unix()+3600)
	old := jwt("HS256", now.Unix()-3600)
	none := jwt("none", 0)
	if f := one(t, live); f[0].Verdict != Plausible || !strings.Contains(f[0].Why, "unexpired") {
		t.Fatalf("%+v", f)
	}
	if f := one(t, old); f[0].Verdict != Fake {
		t.Fatalf("%+v", f)
	}
	if f := one(t, none); !strings.Contains(f[0].Why, "alg=none") {
		t.Fatalf("%+v", f)
	}
}

func TestHighEntropyAssignmentAndPlaceholders(t *testing.T) {
	if f := one(t, `DB_PASSWORD = "Tr0ub4dor&3xK9#mPq2LwZv"`); len(f) != 1 || f[0].Verdict != Plausible {
		t.Fatalf("%+v", f)
	}
	if f := one(t, `api_key = "changeme-please-1234567890"`); f[0].Verdict != Fake {
		t.Fatal("placeholder")
	}
	if f := one(t, `secret = "aaaaaaaaaaaaaaaaaaaa"`); f[0].Verdict != Fake {
		t.Fatal("low entropy")
	}
}

func TestOutputIsRedacted(t *testing.T) {
	tok := ForgeGitHubToken("ghp", "aB3dE5gH7jK9mN1pQ3sT5vX7zC9eF1")
	f := one(t, tok)
	if strings.Contains(Text(f), tok) || strings.Contains(HTML(f, 1), tok) {
		t.Fatal("secret leaked in report")
	}
}

func TestHTMLEscapes(t *testing.T) {
	h := HTML([]Finding{{File: "<img>", Kind: "k", Verdict: Fake, Preview: "p", Why: "<i>x"}}, 1)
	if strings.Contains(h, "<img>") || strings.Contains(h, "<i>") {
		t.Fatal("not escaped")
	}
}

func TestDemoCoversEveryVerdict(t *testing.T) {
	c, p, f := Counts(Scan(Demo(), DemoNow))
	if c != 2 || p < 4 || f < 4 {
		t.Fatalf("%d %d %d", c, p, f)
	}
}

func TestEntropyOrdering(t *testing.T) {
	if Entropy("aaaa") >= Entropy("aB3$xQ9z") {
		t.Fatal("entropy order")
	}
}
