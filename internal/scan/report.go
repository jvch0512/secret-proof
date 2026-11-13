package scan

import (
	"fmt"
	"html"
	"strings"
)

func Text(fs []Finding) string {
	if len(fs) == 0 {
		return "No secrets found.\n"
	}
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "%-19s %-30s %s:%d  %s\n    %s\n", f.Verdict, f.Kind, f.File, f.Line, f.Preview, f.Why)
	}
	return b.String()
}

func Counts(fs []Finding) (c, p, f int) {
	for _, x := range fs {
		switch x.Verdict {
		case Confirmed:
			c++
		case Plausible:
			p++
		default:
			f++
		}
	}
	return
}

func HTML(fs []Finding, files int) string {
	c, p, f := Counts(fs)
	var rows strings.Builder
	for _, x := range fs {
		cls := map[Verdict]string{Confirmed: "bad", Plausible: "warn", Fake: "ok"}[x.Verdict]
		fmt.Fprintf(&rows, "<tr><td class=%q>%s</td><td>%s</td><td>%s:%d</td><td><code>%s</code></td><td>%s</td></tr>", cls, html.EscapeString(string(x.Verdict)), html.EscapeString(x.Kind), html.EscapeString(x.File), x.Line, html.EscapeString(x.Preview), html.EscapeString(x.Why))
	}
	return fmt.Sprintf(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>secret-proof report</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}td.bad{color:#f85149;font-weight:700}td.warn{color:#e3b341;font-weight:700}td.ok{color:#3fb950;font-weight:700}code{background:#161d26;padding:1px 5px;border-radius:4px}</style></head><body><h1>secret-proof</h1><p class="sub">Secret scanning that tells real from fake, offline. Go, zero dependencies. This page comes from <code>secret-proof demo --html</code>: every secret is synthetic and generated in memory.</p><p><b>%d</b> structure-confirmed, <b>%d</b> plausible, <b>%d</b> likely fake, across %d files. Values are redacted.</p><table><tr><th>Verdict</th><th>Kind</th><th>Where</th><th>Value</th><th>Why</th></tr>%s</table></body></html>
`, c, p, f, files, rows.String())
}
