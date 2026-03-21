package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	openai "github.com/sashabaranov/go-openai"
	"github.com/wp-plugin-insight/api/scanner"
)

type provider struct {
	client *openai.Client
	model  string
}

// newProvider auto-detects which LLM to use:
//   - GITHUB_TOKEN set → GitHub Models (used in GitHub Actions)
//   - otherwise        → Ollama at localhost:11434
func newProvider() provider {
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		cfg := openai.DefaultConfig(token)
		cfg.BaseURL = "https://models.inference.ai.azure.com"
		return provider{
			client: openai.NewClientWithConfig(cfg),
			model:  "gpt-4o",
		}
	}

	baseURL := os.Getenv("OLLAMA_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:11434/v1"
	}
	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "glm-4.7-flash:latest"
	}

	cfg := openai.DefaultConfig("ollama")
	cfg.BaseURL = baseURL
	return provider{
		client: openai.NewClientWithConfig(cfg),
		model:  model,
	}
}

// Summarize sends scan results to the LLM and returns a plain-English summary.
func Summarize(slug string, result scanner.Result, score int) (string, error) {
	p := newProvider()

	// Build a compact summary for the AI — avoid sending huge finding lists
	type compactResult struct {
		FilesScanned    int      `json:"files_scanned"`
		MinPHPVersion   string   `json:"min_php_version"`
		SecurityFlags   []string `json:"security_flags"`
		DeprecatedFuncs []string `json:"deprecated_functions"`
		ExternalCalls   int      `json:"external_calls"`
		DirectDBAccess  bool     `json:"direct_db_access"`
		SemgrepCount    int      `json:"semgrep_findings_count"`
		PHPCSCount      int      `json:"phpcs_findings_count"`
		TopSemgrep      []string `json:"top_semgrep_rules,omitempty"`
		TopPHPCS        []string `json:"top_phpcs_rules,omitempty"`
	}

	// Build detailed findings grouped by type
	type issueSummary struct {
		Type  string   `json:"type"`
		Count int      `json:"count"`
		Files []string `json:"example_locations"`
	}

	issueMap := map[string]*issueSummary{}
	for _, f := range result.SemgrepFindings {
		key := f.Rule
		if _, ok := issueMap[key]; !ok {
			issueMap[key] = &issueSummary{Type: key}
		}
		issueMap[key].Count++
		if len(issueMap[key].Files) < 3 {
			issueMap[key].Files = append(issueMap[key].Files, fmt.Sprintf("%s:%d", f.File, f.Line))
		}
	}
	issues := []issueSummary{}
	for _, v := range issueMap {
		issues = append(issues, *v)
	}
	for _, f := range result.PHPCSFindings {
		key := f.Rule
		if _, ok := issueMap[key]; !ok {
			issueMap[key] = &issueSummary{Type: key}
		}
		issueMap[key].Count++
		if len(issueMap[key].Files) < 3 {
			issueMap[key].Files = append(issueMap[key].Files, fmt.Sprintf("%s:%d", f.File, f.Line))
		}
	}

	compact := compactResult{
		FilesScanned:    result.FilesScanned,
		MinPHPVersion:   result.MinPHPVersion,
		SecurityFlags:   result.SecurityFlags,
		DeprecatedFuncs: result.DeprecatedFuncs,
		ExternalCalls:   result.ExternalCalls,
		DirectDBAccess:  result.DirectDBAccess,
		SemgrepCount:    len(result.SemgrepFindings),
		PHPCSCount:      len(result.PHPCSFindings),
	}
	scanJSON, _ := json.MarshalIndent(compact, "", "  ")
	issuesJSON, _ := json.MarshalIndent(issues, "", "  ")

	// Add suspicious code snippets
	codeSection := ""
	for _, snippet := range result.SuspiciousFiles {
		codeSection += fmt.Sprintf("\n--- %s ---\n```php\n%s\n```\n", snippet.File, snippet.Content)
	}
	if codeSection != "" {
		codeSection = "\nSuspicious PHP files:\n" + codeSection
	}

	prompt := fmt.Sprintf(`You are a WordPress security expert reviewing a plugin for a site administrator.

Plugin: %s
Score: %d/100

Scan overview:
%s

Confirmed security issues (grouped by type):
%s
%s
Write a detailed report in plain English with these sections:

## Overall Assessment
2-3 sentences: is it safe to install and why?

## Issues Found
For each issue type found, write a paragraph explaining:
- What the vulnerability is in simple terms
- Why it's dangerous for a WordPress site
- Which files/lines are affected
- How severe it is (critical / high / medium)

## Recommendation
Concrete steps the admin should take. Be specific — e.g. "Do not install", "Update to version X", "Safe to use but monitor".

No jargon. Write as if explaining to a non-technical website owner.`, slug, score, string(scanJSON), string(issuesJSON), codeSection)

	resp, err := p.client.CreateChatCompletion(context.Background(),
		openai.ChatCompletionRequest{
			Model: p.model,
			Messages: []openai.ChatCompletionMessage{
				{Role: openai.ChatMessageRoleUser, Content: prompt},
			},
			MaxTokens: 4000, // thinking models need room to reason before answering
		},
	)
	if err != nil {
		return "", fmt.Errorf("LLM error: %w", err)
	}

	content := resp.Choices[0].Message.Content
	// qwen3 thinking mode: content is empty, reasoning holds the actual response
	if content == "" {
		content = resp.Choices[0].Message.ReasoningContent
	}
	if content == "" {
		return "", fmt.Errorf("empty response from model")
	}
	return content, nil
}
