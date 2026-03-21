package scanner

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const downloadURL = "https://downloads.wordpress.org/plugin/%s.latest-stable.zip"

// CodeSnippet holds a suspicious file's name and truncated content.
type CodeSnippet struct {
	File    string `json:"file"`
	Content string `json:"content"`
}

// Finding is a single issue from Semgrep or PHPCS.
type Finding struct {
	Tool       string `json:"tool"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	Rule       string `json:"rule"`
	PossibleFP bool   `json:"possible_false_positive"`
	FPReason   string `json:"fp_reason,omitempty"`
}

// WordPress-specific sanitization functions that indicate safe code
var wpSanitizationFuncs = []string{
	"absint", "intval", "floatval",
	"sanitize_text_field", "sanitize_email", "sanitize_key",
	"sanitize_url", "sanitize_user", "sanitize_file_name",
	"esc_sql", "esc_url", "esc_attr", "esc_html", "esc_js",
	"wp_verify_nonce", "check_admin_referer", "check_ajax_referer",
	`\$wpdb->prepare`,
}

// Result holds everything found during a scan.
type Result struct {
	FilesScanned       int           `json:"files_scanned"`
	DeprecatedFuncs    []string      `json:"deprecated_functions"`
	SecurityFlags      []string      `json:"security_flags"`
	ExternalCalls      int           `json:"external_calls"`
	DirectDBAccess     bool          `json:"direct_db_access"`
	MinPHPVersion      string        `json:"min_php_version"`
	MissingI18nSamples []string      `json:"missing_i18n_samples"`
	SuspiciousFiles    []CodeSnippet `json:"suspicious_files"`
	SemgrepFindings    []Finding     `json:"semgrep_findings"`
	PHPCSFindings      []Finding     `json:"phpcs_findings"`
}

var deprecatedFuncs = []string{
	"wp_get_user_ip", "the_widget", "wp_specialchars",
	"get_user_by_email", "get_userdatabylogin", "wp_login",
	"get_currentuserinfo", "wp_create_thumbnail", "clean_url",
	"wp_dropdown_cats", "wp_list_cats",
}

var securityPatterns = map[string]*regexp.Regexp{
	"eval()":               regexp.MustCompile(`\beval\s*\(`),
	"base64_decode":        regexp.MustCompile(`\bbase64_decode\s*\(`),
	"unescaped $_POST/GET": regexp.MustCompile(`echo\s+\$_(POST|GET|REQUEST)`),
	"SQL without prepare":  regexp.MustCompile(`\$wpdb->(query|get_results)\s*\(\s*["']?\s*SELECT`),
	"shell_exec":           regexp.MustCompile(`\bshell_exec\s*\(`),
	"system()":             regexp.MustCompile(`\bsystem\s*\(`),
}

var phpVersions = []struct {
	version string
	pattern *regexp.Regexp
}{
	{"8.1", regexp.MustCompile(`\benum\s+\w+`)},
	{"8.1", regexp.MustCompile(`\breadonly\s+`)},
	{"8.0", regexp.MustCompile(`\bmatch\s*\(`)},
	{"8.0", regexp.MustCompile(`str_contains|str_starts_with|str_ends_with`)},
	{"7.4", regexp.MustCompile(`\bfn\s*\(`)},
}

var (
	externalCallPattern = regexp.MustCompile(`wp_remote_(get|post|request)|curl_init\s*\(|file_get_contents\s*\(\s*['"]https?://`)
	directDBPattern     = regexp.MustCompile(`\$wpdb->(query|get_results|get_var|get_row)\s*\(`)
	plainEchoPattern    = regexp.MustCompile(`echo\s+["']([^"']{15,})["']`)
)

// Analyze downloads, extracts and fully scans a plugin by slug.
func Analyze(slug string) (Result, error) {
	data, err := downloadPlugin(slug)
	if err != nil {
		return Result{}, fmt.Errorf("download failed: %w", err)
	}

	// Extract to temp dir so Semgrep + PHPCS can run on real files
	tmpDir, err := os.MkdirTemp("", "wpinsight-*")
	if err != nil {
		return Result{}, fmt.Errorf("temp dir failed: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := extractZip(data, tmpDir); err != nil {
		return Result{}, fmt.Errorf("extract failed: %w", err)
	}

	result, err := scanDir(tmpDir)
	if err != nil {
		return Result{}, err
	}

	// Run external tools in parallel
	semgrepCh := make(chan []Finding, 1)
	phpcsСh := make(chan []Finding, 1)

	go func() { semgrepCh <- runSemgrep(tmpDir) }()
	go func() { phpcsСh <- runPHPCS(tmpDir) }()

	result.SemgrepFindings = <-semgrepCh
	result.PHPCSFindings = <-phpcsСh

	// Check and remove false positives while temp dir still exists
	confirmed := []Finding{}
	for i := range result.SemgrepFindings {
		checkFalsePositive(&result.SemgrepFindings[i], tmpDir)
		if !result.SemgrepFindings[i].PossibleFP {
			confirmed = append(confirmed, result.SemgrepFindings[i])
		}
	}
	result.SemgrepFindings = confirmed

	// Add confirmed findings to score-relevant flags
	seen := map[string]bool{}
	for _, f := range result.SemgrepFindings {
		if f.Severity == "ERROR" || f.Severity == "WARNING" {
			if !seen[f.Rule] {
				result.SecurityFlags = append(result.SecurityFlags, "[semgrep] "+f.Rule)
				seen[f.Rule] = true
			}
		}
	}

	return result, nil
}

func downloadPlugin(slug string) ([]byte, error) {
	url := fmt.Sprintf(downloadURL, slug)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

func extractZip(data []byte, dest string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, f := range r.File {
		path := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(path, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(path), 0755)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := os.Create(path)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	return nil
}

func scanDir(dir string) (Result, error) {
	result := Result{
		MinPHPVersion:      "7.0",
		DeprecatedFuncs:    []string{},
		SecurityFlags:      []string{},
		MissingI18nSamples: []string{},
		SuspiciousFiles:    []CodeSnippet{},
		SemgrepFindings:    []Finding{},
		PHPCSFindings:      []Finding{},
	}
	deprecatedSeen := map[string]bool{}
	securitySeen := map[string]bool{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".php") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(b)
		result.FilesScanned++

		for _, fn := range deprecatedFuncs {
			re := regexp.MustCompile(`\b` + regexp.QuoteMeta(fn) + `\s*\(`)
			if re.MatchString(content) && !deprecatedSeen[fn] {
				result.DeprecatedFuncs = append(result.DeprecatedFuncs, fn)
				deprecatedSeen[fn] = true
			}
		}

		fileFlagged := false
		for label, re := range securityPatterns {
			if re.MatchString(content) && !securitySeen[label] {
				result.SecurityFlags = append(result.SecurityFlags, label)
				securitySeen[label] = true
				fileFlagged = true
			}
		}

		if fileFlagged && len(result.SuspiciousFiles) < 3 {
			lines := strings.Split(content, "\n")
			if len(lines) > 120 {
				lines = lines[:120]
			}
			rel, _ := filepath.Rel(dir, path)
			result.SuspiciousFiles = append(result.SuspiciousFiles, CodeSnippet{
				File:    rel,
				Content: strings.Join(lines, "\n"),
			})
		}

		result.ExternalCalls += len(externalCallPattern.FindAllString(content, -1))
		if !result.DirectDBAccess && directDBPattern.MatchString(content) {
			result.DirectDBAccess = true
		}
		for _, v := range phpVersions {
			if v.version > result.MinPHPVersion && v.pattern.MatchString(content) {
				result.MinPHPVersion = v.version
			}
		}
		if len(result.MissingI18nSamples) < 5 {
			for _, m := range plainEchoPattern.FindAllStringSubmatch(content, -1) {
				if len(result.MissingI18nSamples) >= 5 {
					break
				}
				result.MissingI18nSamples = append(result.MissingI18nSamples, m[1])
			}
		}
		return nil
	})

	return result, err
}

// checkFalsePositive checks whether a finding is likely a false positive
// by looking for WordPress sanitization functions near the flagged line.
func checkFalsePositive(f *Finding, tmpDir string) {
	// Reconstruct the full path
	fullPath := filepath.Join(tmpDir, f.File)
	b, err := os.ReadFile(fullPath)
	if err != nil {
		return
	}

	lines := strings.Split(string(b), "\n")
	// Check ±8 lines around the finding
	start := f.Line - 9
	end := f.Line + 8
	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}

	context := strings.Join(lines[start:end], "\n")
	for _, fn := range wpSanitizationFuncs {
		if strings.Contains(context, fn) {
			f.PossibleFP = true
			f.FPReason = fmt.Sprintf("WordPress sanitization function '%s' found near this line", strings.TrimPrefix(fn, `\$`))
			return
		}
	}
}

// runSemgrep runs semgrep with PHP security rules against the extracted plugin dir.
func runSemgrep(dir string) []Finding {
	cmd := exec.Command("semgrep",
		"--config", "p/php",
		"--config", "p/security-audit",
		"--json",
		"--no-git-ignore",
		"--quiet",
		dir,
	)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return []Finding{}
	}

	var result struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
			} `json:"extra"`
		} `json:"results"`
	}

	if err := json.Unmarshal(out, &result); err != nil {
		return []Finding{}
	}

	realDir, _ := filepath.EvalSymlinks(dir)
	findings := []Finding{}
	for _, r := range result.Results {
		realPath, _ := filepath.EvalSymlinks(r.Path)
		rel, err := filepath.Rel(realDir, realPath)
		if err != nil {
			rel = filepath.Base(r.Path)
		}
		findings = append(findings, Finding{
			Tool:     "semgrep",
			File:     rel,
			Line:     r.Start.Line,
			Severity: r.Extra.Severity,
			Message:  r.Extra.Message,
			Rule:     r.CheckID,
		})
	}
	return findings
}

// runPHPCS runs PHPCS with WordPress security standards — errors only.
func runPHPCS(dir string) []Finding {
	phpcs := os.Getenv("PHPCS_BIN")
	if phpcs == "" {
		phpcs = "phpcs"
	}
	cmd := exec.Command(phpcs,
		"--standard=WordPress-Security",
		"--report=json",
		"--extensions=php",
		"--ignore=*/vendor/*,*/node_modules/*",
		"-q",
		dir,
	)
	out, _ := cmd.Output()
	if len(out) == 0 {
		return []Finding{}
	}

	var result struct {
		Files map[string]struct {
			Messages []struct {
				Message  string `json:"message"`
				Source   string `json:"source"`
				Severity int    `json:"severity"`
				Type     string `json:"type"`
				Line     int    `json:"line"`
			} `json:"messages"`
		} `json:"files"`
	}

	if err := json.Unmarshal(out, &result); err != nil {
		return []Finding{}
	}

	findings := []Finding{}
	// Resolve real path to handle macOS /private/var symlinks
	realDir, _ := filepath.EvalSymlinks(dir)

	for path, file := range result.Files {
		realPath, _ := filepath.EvalSymlinks(path)
		rel, err := filepath.Rel(realDir, realPath)
		if err != nil {
			rel = filepath.Base(path)
		}
		for _, m := range file.Messages {
			findings = append(findings, Finding{
				Tool:     "phpcs",
				File:     rel,
				Line:     m.Line,
				Severity: m.Type,
				Message:  m.Message,
				Rule:     m.Source,
			})
		}
	}
	return findings
}

// Score calculates a quality score 0–100.
func Score(r Result) int {
	score := 100
	score -= len(r.DeprecatedFuncs) * 5
	score -= len(r.SecurityFlags) * 15
	if r.DirectDBAccess {
		score -= 10
	}
	score -= min(len(r.MissingI18nSamples)*2, 20)
	score -= min(len(r.SemgrepFindings)*3, 20)
	score -= min(len(r.PHPCSFindings)/10, 10)
	if score < 0 {
		return 0
	}
	return score
}
