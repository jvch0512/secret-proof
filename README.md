# secret-proof

Secret scanners drown teams in false positives. secret-proof tells you which findings are **real-format** and which are fakes, without sending anything anywhere.

**Live demo:** https://jvch0512.github.io/secret-proof/ (a report on synthetic data: every secret is generated in memory)

Go, standard library only, one static binary, offline.

## What makes it different

- **Checksum verification.** GitHub and npm tokens end with a CRC32 checksum of the random part, encoded in Base62 and padded to 6 characters ([GitHub engineering blog](https://github.blog/engineering/behind-githubs-new-authentication-token-formats/)). A token whose checksum matches is a real-format token: **structure-confirmed**. One whose checksum fails is fabricated, truncated or mistyped: **likely-fake**. That removes a large class of false positives with zero network calls.
- **Context for other secrets.** AWS key IDs (documentation keys are flagged fake), private key blocks, Slack tokens, hard-coded assignments with entropy scoring and placeholder detection.
- **JWT triage.** Decodes the header and claims offline: `alg=none`, expired, unexpired, no expiry.
- **Always redacted.** Reports never contain the full secret, in text, JSON or HTML.

Structure-confirmed means the token has a valid format, not that it is still active. Revoke it either way. Confirming that a credential is live needs a call to the provider, which this tool never makes.

## Use

```bash
go build -o secret-proof ./cmd/secret-proof
./secret-proof scan ./my-repo
./secret-proof scan ./my-repo --json
./secret-proof scan ./my-repo --fail-on confirmed    # exit 1 in CI
./secret-proof demo                                  # synthetic secrets of every verdict
```

Skips `.git`, `node_modules`, `vendor`, binaries and files over 1 MB. See [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- Pattern based: it will miss secrets in formats it does not know, and entropy rules are heuristics. Use it to triage and as a pre-commit or CI gate, next to a history-aware scanner for old commits.
- It scans the working tree, not git history.
- Tokens other than GitHub and npm have no offline checksum here, so they top out at "plausible".

## Where it fits

DevSecOps pipelines, M&A and vendor code reviews, incident response ("is this leaked token real?"), and a service line: a fixed-price repository secret audit with triage and a remediation list.

## Tests

```bash
go test ./...   # 12 tests: CRC vector, valid and invalid tokens, npm, AWS, JWT variants, entropy, redaction, escaping
```

MIT.
