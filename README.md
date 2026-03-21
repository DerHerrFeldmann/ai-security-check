# WP Plugin Insight

AI-powered quality & security analyzer for WordPress plugins. Enter a plugin slug and get a security score, Semgrep findings, PHPCS violations, and a plain-English AI assessment.

![Stack](https://img.shields.io/badge/Go-API-00ADD8?logo=go) ![Stack](https://img.shields.io/badge/React-Frontend-61DAFB?logo=react) ![Stack](https://img.shields.io/badge/Ollama-LLM-black)

---

## How it works

1. Downloads the plugin ZIP from wordpress.org
2. Runs **Semgrep** (`p/php` + `p/security-audit`) and **PHPCS** (`WordPress-Security`) on the extracted PHP files
3. Filters out false positives (WordPress sanitization functions detected near flagged lines)
4. Calculates a score (0–100) based on findings
5. Sends a compact summary to an LLM for a plain-English security report

---

## Requirements

| Tool | Version |
|------|---------|
| Go | 1.21+ |
| Node.js | 18+ |
| Semgrep | latest (`pip install semgrep`) |
| PHPCS | via Composer (see below) |
| Ollama | running locally **or** `GITHUB_TOKEN` set |

### Install PHPCS with WordPress standards

```bash
composer require --dev squizlabs/php_codesniffer wp-coding-standards/wpcs
vendor/bin/phpcs --config-set installed_paths vendor/wp-coding-standards/wpcs
```

> The PHPCS binary path in `api/scanner/scanner.go` defaults to the plugin-check vendor path.
> Update `phpcs` variable in `runPHPCS()` to match your local path.

---

## Start the API

```bash
cd api

# Optional: configure Ollama (defaults to localhost:11434, model glm-4.7-flash:latest)
export OLLAMA_BASE_URL=http://localhost:11434/v1
export OLLAMA_MODEL=llama3.1:8b

# Or use GitHub Models (no local Ollama needed)
export GITHUB_TOKEN=your_token_here

go run main.go
# → Server running at http://localhost:8080
```

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/analyze` | Download & scan a plugin, returns score + findings |
| `POST` | `/api/summarize` | Generate AI summary for a scan result |

Example:
```bash
curl -s -X POST http://localhost:8080/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"slug":"woocommerce"}' | jq .score
```

---

## Start the Frontend

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

---

## CLI usage

```bash
cd api
go build -o wpinsight ./cmd/cli
./wpinsight woocommerce
./wpinsight wp-file-manager
```

Output: score, security flags, Semgrep findings, PHPCS findings, stats, AI summary.

---

## LLM configuration

The API auto-detects which LLM to use:

| Environment variable | Effect |
|----------------------|--------|
| `GITHUB_TOKEN` set | Uses GitHub Models (`gpt-4o`) — no local Ollama needed |
| `OLLAMA_BASE_URL` | Custom Ollama endpoint (default: `http://localhost:11434/v1`) |
| `OLLAMA_MODEL` | Custom model (default: `glm-4.7-flash:latest`) |

Recommended local models: `llama3.1:8b` (fast), `llama3.1:70b` (better quality).

---

## Scoring

Starts at 100, deductions:

| Issue | Penalty |
|-------|---------|
| Each deprecated function | −5 |
| Each security flag | −15 |
| Direct DB access | −10 |
| Missing i18n samples (max 20) | −2 each |
| Semgrep findings (max 20) | −3 each |
| PHPCS findings / 10 (max 10) | −1 each |

---

## Project structure

```
.
├── api/
│   ├── main.go              # HTTP server (2 endpoints)
│   ├── ai/ai.go             # LLM provider + summarize
│   ├── scanner/scanner.go   # Download, scan, score
│   └── cmd/cli/main.go      # CLI tool
├── frontend/
│   └── src/App.tsx          # React UI
├── .github/
│   └── workflows/analyze.yml
└── CONCEPT.md
```
