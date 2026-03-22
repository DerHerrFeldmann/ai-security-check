package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/wp-plugin-insight/api/ai"
	"github.com/wp-plugin-insight/api/scanner"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
)

type jsonOutput struct {
	Slug    string         `json:"slug"`
	Score   int            `json:"score"`
	Scan    scanner.Result `json:"scan"`
	Summary string         `json:"summary"`
}

func main() {
	args := os.Args[1:]
	jsonMode := false

	// Parse flags
	filtered := []string{}
	for _, a := range args {
		if a == "-json" || a == "--json" {
			jsonMode = true
		} else {
			filtered = append(filtered, a)
		}
	}

	if len(filtered) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: wpinsight [-json] <plugin-slug>")
		fmt.Fprintln(os.Stderr, "       wpinsight wapuugotchi")
		fmt.Fprintln(os.Stderr, "       wpinsight -json wapuugotchi > reports/wapuugotchi.json")
		os.Exit(1)
	}

	slug := strings.TrimSpace(filtered[0])

	if !jsonMode {
		fmt.Printf("\n%s Analyzing plugin: %s%s%s\n\n", cyan+"→"+reset, bold, slug, reset)
	}

	// Scan
	if !jsonMode {
		fmt.Printf("%s Downloading & scanning...%s\n", gray, reset)
	}
	result, err := scanner.Analyze(slug)
	if err != nil {
		if jsonMode {
			json.NewEncoder(os.Stderr).Encode(map[string]string{"error": err.Error()})
		} else {
			fmt.Printf("%s Error: %v%s\n", red, err, reset)
		}
		os.Exit(1)
	}

	score := scanner.Score(result)

	if jsonMode {
		// AI Summary
		summary, aiErr := ai.Summarize(slug, result, score)
		if aiErr != nil {
			fmt.Fprintf(os.Stderr, "AI warning: %v\n", aiErr)
		}
		out := jsonOutput{
			Slug:    slug,
			Score:   score,
			Scan:    result,
			Summary: summary,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
		return
	}

	// Pretty-print output
	grade := scanner.Grade(score)
	scoreColor := green
	if grade == "C" {
		scoreColor = yellow
	} else if grade == "D" || grade == "F" {
		scoreColor = red
	}
	fmt.Printf("\n%s%s Grade: %s  (score %d/100)%s\n", bold, scoreColor, grade, score, reset)
	fmt.Printf("%s %d PHP files scanned · min PHP %s%s\n\n", gray, result.FilesScanned, result.MinPHPVersion, reset)

	if len(result.SecurityFlags) > 0 {
		fmt.Printf("%s%s Security Issues:%s\n", bold, red, reset)
		for _, f := range result.SecurityFlags {
			fmt.Printf("  %s✗ %s%s\n", red, f, reset)
		}
		fmt.Println()
	} else {
		fmt.Printf("  %s✓ No security issues found%s\n\n", green, reset)
	}

	if len(result.DeprecatedFuncs) > 0 {
		fmt.Printf("%s%s Deprecated Functions:%s\n", bold, yellow, reset)
		for _, f := range result.DeprecatedFuncs {
			fmt.Printf("  %s⚠ %s%s\n", yellow, f, reset)
		}
		fmt.Println()
	}

	if len(result.SemgrepFindings) > 0 {
		fmt.Printf("%s%s Semgrep (%d findings):%s\n", bold, red, len(result.SemgrepFindings), reset)
		for _, f := range result.SemgrepFindings {
			if f.PossibleFP {
				fmt.Printf("  %s~ %s:%d — %s [likely false positive: %s]%s\n", gray, f.File, f.Line, f.Rule, f.FPReason, reset)
			} else {
				fmt.Printf("  %s✗ %s:%d — %s%s\n", red, f.File, f.Line, f.Rule, reset)
			}
		}
		fmt.Println()
	}

	if len(result.PHPCSFindings) > 0 {
		fmt.Printf("%s%s PHPCS (%d findings):%s\n", bold, yellow, len(result.PHPCSFindings), reset)
		shown := result.PHPCSFindings
		if len(shown) > 5 {
			shown = shown[:5]
		}
		for _, f := range shown {
			fmt.Printf("  %s⚠ %s:%d — %s%s\n", yellow, f.File, f.Line, f.Rule, reset)
		}
		if len(result.PHPCSFindings) > 5 {
			fmt.Printf("  %s… and %d more%s\n", gray, len(result.PHPCSFindings)-5, reset)
		}
		fmt.Println()
	}

	if len(result.CVEFindings) > 0 {
		fmt.Printf("%s%s Known CVEs (%d affecting v%s):%s\n", bold, red, len(result.CVEFindings), result.Version, reset)
		for _, c := range result.CVEFindings {
			label := "LOW"
			col := yellow
			switch {
			case c.CVSSScore >= 9.0:
				label, col = "CRITICAL", red
			case c.CVSSScore >= 7.0:
				label, col = "HIGH", red
			case c.CVSSScore >= 4.0:
				label, col = "MEDIUM", yellow
			}
			fixInfo := ""
			if c.Unfixed {
				fixInfo = " · no fix available"
			} else if c.FixedIn != "" {
				fixInfo = fmt.Sprintf(" · fixed in %s", c.FixedIn)
			}
			fmt.Printf("  %s[%s %.1f] %s%s%s\n", col, label, c.CVSSScore, c.Title, fixInfo, reset)
		}
		fmt.Println()
	} else {
		fmt.Printf("  %s✓ No known CVEs%s\n\n", green, reset)
	}

	if len(result.DepVulns) > 0 {
		fmt.Printf("%s%s Vulnerable Dependencies (%d):%s\n", bold, red, len(result.DepVulns), reset)
		for _, d := range result.DepVulns {
			cveInfo := ""
			if d.CVE != "" {
				cveInfo = " · " + d.CVE
			}
			fixInfo := ""
			if len(d.FixedIn) > 0 {
				fixInfo = fmt.Sprintf(" → fix: %s", strings.Join(d.FixedIn, ", "))
			}
			fmt.Printf("  %s✗ %s@%s [%s]%s%s%s\n", red, d.Package, d.Version, strings.ToUpper(d.Severity), cveInfo, fixInfo, reset)
		}
		fmt.Println()
	} else {
		fmt.Printf("  %s✓ No vulnerable dependencies%s\n\n", green, reset)
	}

	fmt.Printf("%s%s Stats:%s\n", bold, cyan, reset)
	fmt.Printf("  External HTTP calls : %d\n", result.ExternalCalls)
	fmt.Printf("  Direct DB access    : %v\n", result.DirectDBAccess)
	fmt.Printf("  Missing i18n samples: %d\n", len(result.MissingI18nSamples))
	fmt.Println()

	fmt.Printf("%s Generating AI summary...%s\n", gray, reset)
	summary, err := ai.Summarize(slug, result, score)
	if err != nil {
		fmt.Printf("%s AI unavailable: %v%s\n", yellow, err, reset)
	} else {
		fmt.Printf("\n%s%s AI Assessment:%s\n", bold, cyan, reset)
		words := strings.Fields(summary)
		line := ""
		for _, w := range words {
			if len(line)+len(w)+1 > 72 {
				fmt.Printf("  %s\n", line)
				line = w
			} else {
				if line == "" {
					line = w
				} else {
					line += " " + w
				}
			}
		}
		if line != "" {
			fmt.Printf("  %s\n", line)
		}
	}
	fmt.Println()
}
