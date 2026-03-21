package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/wp-plugin-insight/api/ai"
	"github.com/wp-plugin-insight/api/scanner"
)

func cors(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

// POST /api/analyze — fast: download + scan only
func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		return
	}

	var req struct {
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Slug == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "slug required"})
		return
	}

	log.Printf("Scanning: %s", req.Slug)
	result, err := scanner.Analyze(req.Slug)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"slug":  req.Slug,
		"score": scanner.Score(result),
		"scan":  result,
	})
}

// POST /api/summarize — slow: AI summary
func handleSummarize(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		return
	}

	var req struct {
		Slug  string         `json:"slug"`
		Score int            `json:"score"`
		Scan  scanner.Result `json:"scan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"})
		return
	}

	log.Printf("Summarizing: %s", req.Slug)
	summary, err := ai.Summarize(req.Slug, req.Scan, req.Score)
	if err != nil {
		summary = fmt.Sprintf("AI unavailable: %v", err)
	}

	json.NewEncoder(w).Encode(map[string]string{"summary": summary})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/analyze", handleAnalyze)
	mux.HandleFunc("/api/summarize", handleSummarize)

	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
