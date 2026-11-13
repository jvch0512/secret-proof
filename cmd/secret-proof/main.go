package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jvch0512/secret-proof/internal/scan"
)

const usage = `secret-proof

  secret-proof scan <dir> [--json] [--fail-on confirmed|plausible]
  secret-proof demo [--html]

Offline. Secrets are redacted in every output.
Exit codes: 0 ok, 1 findings at or above --fail-on, 2 bad input.`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	fl := flag.NewFlagSet(args[0], flag.ContinueOnError)
	asJSON := fl.Bool("json", false, "JSON output")
	asHTML := fl.Bool("html", false, "HTML output (demo)")
	failOn := fl.String("fail-on", "", "confirmed or plausible")
	var items []scan.Item
	now := time.Now()
	switch args[0] {
	case "demo":
		if fl.Parse(args[1:]) != nil {
			return 2
		}
		items, now = scan.Demo(), scan.DemoNow
	case "scan":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		if fl.Parse(args[2:]) != nil {
			return 2
		}
		var err error
		if items, err = load(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
	default:
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	if *failOn != "" && *failOn != "confirmed" && *failOn != "plausible" {
		fmt.Fprintln(os.Stderr, "error: --fail-on must be confirmed or plausible")
		return 2
	}
	res := scan.Scan(items, now)
	switch {
	case *asHTML:
		fmt.Print(scan.HTML(res, len(items)))
	case *asJSON:
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	default:
		fmt.Print(scan.Text(res))
	}
	c, p, _ := scan.Counts(res)
	if (*failOn == "confirmed" && c > 0) || (*failOn == "plausible" && c+p > 0) {
		return 1
	}
	return 0
}

func load(root string) ([]scan.Item, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	var items []scan.Item
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" || n == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() > 1<<20 {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil || strings.ContainsRune(string(b[:min(len(b), 512)]), 0) {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		items = append(items, scan.Item{Name: rel, Text: string(b)})
		return nil
	})
	return items, err
}
