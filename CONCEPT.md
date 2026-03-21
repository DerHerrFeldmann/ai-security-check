# WP Plugin Insight – Concept

**Stack:** GitHub Pages + GitHub Actions + GitHub Models API

> Zero hosting costs. No server. Entirely on GitHub.

---

## Architecture

```
[GitHub Pages]          [GitHub Actions]         [GitHub Models]
Static Frontend    →    Analysis Engine      →    Free AI (GPT-4o /
(HTML/JS/CSS)           (Python Scanner)          Llama 3.1 70B)
                               ↓
                        Result committed
                        as JSON to repo
                               ↓
                        GitHub Pages serves
                        the finished report
```

---

## Flow

```
1. User enters plugin slug (e.g. "woocommerce")
        ↓
2. Static form triggers GitHub Action
   via repository_dispatch or workflow_dispatch
        ↓
3. Action: download plugin ZIP from WordPress.org
        ↓
4. Action: Python static scanner runs
        ↓
5. Action: GitHub Models API → NL summary
        ↓
6. Action: report committed as JSON + HTML to repo
        ↓
7. GitHub Pages: report available at /reports/{slug}
```

---

## Static Scanner (Python, runs in GitHub Action)

| Check | Method |
|---|---|
| Deprecated WP Functions | Static lookup list (e.g. `wp_get_user_ip`, `the_widget`) |
| Min. PHP Version | Regex on syntax (`match`, `named args`, `enum`, `readonly`) |
| Min. WP Version | Lookups against WP changelog data |
| Direct DB Access | `$wpdb->query`, raw SQL patterns |
| External Calls | `wp_remote_get`, `curl_*`, `file_get_contents(http` |
| Security Flags | `eval()`, `base64_decode`, unescaped output |
| i18n | `__()` / `_e()` coverage vs. user-facing strings |

---

## Security Analysis: Two-Layer Approach

LLMs guess — for security you want deterministic analysis. Best results come from combining both:

```
Static Scanner (deterministic)       GitHub Models (LLM)
──────────────────────────────        ─────────────────────────────
eval() found         → FACT          "What does this mean
base64_decode        → FACT           for a site admin?"  → EXPLANATION
unescaped $POST      → FACT          "How critical is it?" → ASSESSMENT
SQL without prepare() → FACT         "What to do?"        → RECOMMENDATION
```

The scanner finds the problems reliably. The LLM explains them in plain language.

Reference: `plugin-check/` (already cloned) contains existing security checks and can serve as a baseline for our scanner rules.

---

## AI Feature via GitHub Models (free)

Scanner JSON → GitHub Models API:

```python
# Available in every GitHub Action via GITHUB_TOKEN — no separate API key needed
from openai import OpenAI

client = OpenAI(
    base_url="https://models.inference.ai.azure.com",
    api_key=os.environ["GITHUB_TOKEN"],  # injected automatically
)
```

The provider is auto-detected — no config needed:

| Environment | Provider | Model |
|---|---|---|
| GitHub Actions | GitHub Models | `gpt-4o` |
| Local | Ollama | `qwen2.5-coder:7b` |

```
GITHUB_TOKEN set?  →  GitHub Models (automatic in Actions)
otherwise          →  Ollama at localhost:11434
```

Optional env overrides:
```bash
OLLAMA_BASE_URL=http://localhost:11434/v1  # default
OLLAMA_MODEL=qwen2.5-coder:7b             # default
```

No OpenAI account. No Azure account. No credit card. GitHub handles everything in CI.

---

## GitHub Actions Workflow

```yaml
# .github/workflows/analyze.yml
on:
  workflow_dispatch:
    inputs:
      plugin_slug:
        description: 'WordPress Plugin Slug'
        required: true

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -r requirements.txt
      - run: python scanner/analyze.py ${{ inputs.plugin_slug }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - run: |
          git config user.name "WP Plugin Insight Bot"
          git add reports/
          git commit -m "Report: ${{ inputs.plugin_slug }}"
          git push
```

---

## Frontend (GitHub Pages)

Purely static — no framework needed:

```
index.html           # Search form + plugin slug input
reports/
  woocommerce.html   # Generated report
  contact-form-7.html
  ...
assets/
  style.css
  app.js             # Form → workflow_dispatch API call
```

---

## Repo Structure

```
/
├── .github/
│   └── workflows/
│       └── analyze.yml
├── scanner/
│   ├── analyze.py        # Main entry point
│   ├── checks/           # Individual check modules
│   └── deprecated.json   # WP deprecated function list
├── plugin-check/         # WordPress/plugin-check (reference)
├── reports/              # Generated reports (committed)
├── index.html            # GitHub Pages frontend
└── CONCEPT.md
```

---

## Why This Approach

| | |
|---|---|
| Cost | €0 — everything free |
| Hosting | GitHub Pages |
| AI | GitHub Models (GITHUB_TOKEN is enough) |
| Maintenance | No server, no Docker, no deployment |
| Community | Fork & use — anyone can run their own instance |

---

## Limitations

- Analysis takes ~1-2 min (Action runtime)
- GitHub Actions free tier: 2,000 min/month (sufficient for demo)
- Not real-time — pull-based via commits

---

## Build Order

1. **Scanner module** (`scanner/analyze.py`) — core logic
2. **GitHub Action** — wire up scanner + GitHub Models
3. **Report template** — HTML output
4. **Frontend** (`index.html`) — form + report list
