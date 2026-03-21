package main

import (
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wpinsight <plugin-slug>")
		fmt.Println("       wpinsight wapuugotchi")
		os.Exit(1)
	}

	slug := strings.TrimSpace(os.Args[1])
	fmt.Printf("\n%s Analyzing plugin: %s%s%s\n\n", cyan+"→"+reset, bold, slug, reset)

	// Scan
	fmt.Printf("%s Downloading & scanning...%s\n", gray, reset)
	result, err := scanner.Analyze(slug)
	if err != nil {
		fmt.Printf("%s Error: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	score := scanner.Score(result)

	// Score
	scoreColor := green
	if score < 70 {
		scoreColor = yellow
	}
	if score < 40 {
		scoreColor = red
	}
	fmt.Printf("\n%s%s Score: %d/100%s\n", bold, scoreColor, score, reset)
	fmt.Printf("%s %d PHP files scanned · min PHP %s%s\n\n", gray, result.FilesScanned, result.MinPHPVersion, reset)

	// Security flags
	if len(result.SecurityFlags) > 0 {
		fmt.Printf("%s%s Security Issues:%s\n", bold, red, reset)
		for _, f := range result.SecurityFlags {
			fmt.Printf("  %s✗ %s%s\n", red, f, reset)
		}
		fmt.Println()
	} else {
		fmt.Printf("  %s✓ No security issues found%s\n\n", green, reset)
	}

	// Deprecated functions
	if len(result.DeprecatedFuncs) > 0 {
		fmt.Printf("%s%s Deprecated Functions:%s\n", bold, yellow, reset)
		for _, f := range result.DeprecatedFuncs {
			fmt.Printf("  %s⚠ %s%s\n", yellow, f, reset)
		}
		fmt.Println()
	}

	// Semgrep findings
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

	// PHPCS findings
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

	// Stats
	fmt.Printf("%s%s Stats:%s\n", bold, cyan, reset)
	fmt.Printf("  External HTTP calls : %d\n", result.ExternalCalls)
	fmt.Printf("  Direct DB access    : %v\n", result.DirectDBAccess)
	fmt.Printf("  Missing i18n samples: %d\n", len(result.MissingI18nSamples))
	fmt.Println()

	// AI Summary
	fmt.Printf("%s Generating AI summary...%s\n", gray, reset)
	summary, err := ai.Summarize(slug, result, score)
	if err != nil {
		fmt.Printf("%s AI unavailable: %v%s\n", yellow, err, reset)
	} else {
		fmt.Printf("\n%s%s AI Assessment:%s\n", bold, cyan, reset)
		// Word-wrap at 72 chars
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
