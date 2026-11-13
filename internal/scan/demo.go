package scan

import (
	"encoding/base64"
	"fmt"
	"time"
)

// DemoNow is fixed so the demo output is reproducible.
var DemoNow = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)

func jwt(alg string, exp int64) string {
	e := base64.RawURLEncoding.EncodeToString
	p := `{"sub":"1234"}`
	if exp != 0 {
		p = fmt.Sprintf(`{"sub":"1234","exp":%d}`, exp)
	}
	return e([]byte(`{"alg":"`+alg+`","typ":"JWT"}`)) + "." + e([]byte(p)) + ".c2lnbmF0dXJl"
}

// Demo returns synthetic files holding secrets of every verdict. Nothing here is a real credential.
func Demo() []Item {
	good := ForgeGitHubToken("ghp", "Zq8Vn3LmT0wKc5RjY7dHbXe2UaPf9s")
	npm := ForgeGitHubToken("npm", "Qm4Tz7Wb1NvXc8LdRk3Jh6YpAe0SgU")
	badsum := "ghp_Zq8Vn3LmT0wKc5RjY7dHbXe2UaPf9s" + "AAAAAA"
	return []Item{
		{"deploy/ci.yml", "env:\n  GH_TOKEN: " + good + "\n  NPM_TOKEN: " + npm + "\n"},
		{"docs/howto.md", "Use a token like " + badsum + " in your settings.\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"},
		{"app/config.py", "AWS_KEY = \"AKIAQ4ZTR7MWNB2KX5HD\"\nDB_PASSWORD = \"Tr0ub4dor&3xK9#mPq2LwZv\"\napi_key = \"changeme-please-1234567890\"\nsecret = \"aaaaaaaaaaaaaaaaaaaa\"\n"},
		{"keys/id_old", "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----\n"},
		{"tests/fixtures.json", `{"live": "` + jwt("HS256", DemoNow.Unix()+86400*30) + `", "old": "` + jwt("HS256", DemoNow.Unix()-86400*90) + `", "evil": "` + jwt("none", 0) + `"}` + "\n"},
	}
}
