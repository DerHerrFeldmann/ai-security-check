#!/usr/bin/env python3
"""
WP Plugin Insight – Static Scanner
Downloads a WordPress plugin by slug, scans all PHP files,
and generates a JSON + HTML report.
"""

import os
import sys
import json
import re
import zipfile
import tempfile
import requests
from pathlib import Path
from datetime import datetime
from openai import OpenAI

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────

WP_API_URL = "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug={slug}"
WP_DOWNLOAD_URL = "https://downloads.wordpress.org/plugin/{slug}.latest-stable.zip"

CHECKS_DIR = Path(__file__).parent / "checks"
REPORTS_DIR = Path(__file__).parent.parent / "reports"

# ──────────────────────────────────────────────
# Download
# ──────────────────────────────────────────────

def fetch_plugin_meta(slug: str) -> dict:
    """Fetch plugin metadata from WordPress.org API."""
    response = requests.get(WP_API_URL.format(slug=slug), timeout=15)
    if response.status_code != 200:
        return {}
    return response.json()


def download_plugin(slug: str, dest: Path) -> Path:
    """Download and extract plugin ZIP to a temp directory."""
    url = WP_DOWNLOAD_URL.format(slug=slug)
    print(f"Downloading {url}...")
    response = requests.get(url, timeout=60)
    response.raise_for_status()

    zip_path = dest / f"{slug}.zip"
    zip_path.write_bytes(response.content)

    extract_path = dest / slug
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extract_path)

    return extract_path


# ──────────────────────────────────────────────
# Scanner
# ──────────────────────────────────────────────

def load_checks() -> dict:
    return {
        "deprecated": json.loads((CHECKS_DIR / "deprecated.json").read_text()),
        "php_versions": json.loads((CHECKS_DIR / "php_versions.json").read_text()),
    }


def scan_file(file_path: Path, checks: dict) -> dict:
    """Scan a single PHP file and return findings."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {}

    findings = {
        "deprecated_functions": [],
        "deprecated_hooks": [],
        "security_flags": [],
        "external_calls": [],
        "direct_db": [],
        "missing_i18n": [],
        "php_features": {},
    }

    # Deprecated function calls
    for func in checks["deprecated"]["functions"]:
        if re.search(rf'\b{re.escape(func)}\s*\(', content):
            findings["deprecated_functions"].append(func)

    # Deprecated hooks
    for hook in checks["deprecated"]["hooks"]:
        if hook in content:
            findings["deprecated_hooks"].append(hook)

    # Security flags
    security_patterns = {
        "eval()": r'\beval\s*\(',
        "base64_decode": r'\bbase64_decode\s*\(',
        "unescaped $_POST": r'echo\s+\$_(?:POST|GET|REQUEST)',
        "SQL without prepare": r'\$wpdb->(query|get_results|get_var)\s*\(\s*["\']?\s*SELECT',
        "shell_exec": r'\bshell_exec\s*\(',
        "system()": r'\bsystem\s*\(',
        "passthru()": r'\bpassthru\s*\(',
    }
    for label, pattern in security_patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            findings["security_flags"].append(label)

    # External calls
    external_patterns = [
        r'wp_remote_(get|post|request)',
        r'curl_init\s*\(',
        r'file_get_contents\s*\(\s*["\']https?://',
    ]
    for pattern in external_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings["external_calls"].extend(matches)

    # Direct DB access
    if re.search(r'\$wpdb->(query|get_results|get_var|get_row)\s*\(', content):
        findings["direct_db"].append(str(file_path.name))

    # PHP version features
    for version, patterns in checks["php_versions"].items():
        for pattern in patterns:
            if re.search(re.escape(pattern), content):
                if version not in findings["php_features"]:
                    findings["php_features"][version] = []
                findings["php_features"][version].append(pattern)

    # i18n: plain strings echoed without translation
    plain_echo = re.findall(r'echo\s+["\']([^"\']{10,})["\']', content)
    findings["missing_i18n"] = plain_echo[:5]  # limit to first 5 per file

    return findings


def scan_plugin(plugin_dir: Path) -> dict:
    """Scan all PHP files in a plugin directory."""
    checks = load_checks()
    results = {
        "files_scanned": 0,
        "deprecated_functions": set(),
        "deprecated_hooks": set(),
        "security_flags": set(),
        "external_calls": set(),
        "direct_db_files": set(),
        "missing_i18n_samples": [],
        "min_php_version": "7.0",
        "php_features_found": {},
    }

    for php_file in plugin_dir.rglob("*.php"):
        results["files_scanned"] += 1
        findings = scan_file(php_file, checks)

        results["deprecated_functions"].update(findings.get("deprecated_functions", []))
        results["deprecated_hooks"].update(findings.get("deprecated_hooks", []))
        results["security_flags"].update(findings.get("security_flags", []))
        results["external_calls"].update(str(m) for m in findings.get("external_calls", []))
        results["direct_db_files"].update(findings.get("direct_db", []))
        results["missing_i18n_samples"].extend(findings.get("missing_i18n", []))

        for version, patterns in findings.get("php_features", {}).items():
            if version not in results["php_features_found"]:
                results["php_features_found"][version] = []
            results["php_features_found"][version].extend(patterns)

    # Determine minimum PHP version required
    version_order = ["8.3", "8.2", "8.1", "8.0", "7.4", "7.3", "7.2"]
    for version in version_order:
        if version in results["php_features_found"]:
            results["min_php_version"] = version
            break

    # Convert sets to lists for JSON serialization
    results["deprecated_functions"] = list(results["deprecated_functions"])
    results["deprecated_hooks"] = list(results["deprecated_hooks"])
    results["security_flags"] = list(results["security_flags"])
    results["external_calls"] = list(results["external_calls"])
    results["direct_db_files"] = list(results["direct_db_files"])
    results["missing_i18n_samples"] = results["missing_i18n_samples"][:10]

    return results


# ──────────────────────────────────────────────
# Scoring
# ──────────────────────────────────────────────

def calculate_score(scan: dict) -> int:
    """Calculate a quality score from 0–100."""
    score = 100
    score -= len(scan["deprecated_functions"]) * 5
    score -= len(scan["deprecated_hooks"]) * 5
    score -= len(scan["security_flags"]) * 15
    score -= len(scan["direct_db_files"]) * 3
    score -= min(len(scan["missing_i18n_samples"]) * 2, 20)
    return max(0, score)


# ──────────────────────────────────────────────
# AI Summary via GitHub Models
# ──────────────────────────────────────────────

def get_llm_client() -> tuple:
    """
    Auto-detect which LLM provider to use.
    - GITHUB_TOKEN present → GitHub Models (used in GitHub Actions)
    - otherwise            → Ollama (local development)
    Returns (client, model_name).
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")

    if github_token:
        print("Using GitHub Models (cloud)")
        client = OpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=github_token,
        )
        return client, "gpt-4o"
    else:
        print("Using Ollama (local)")
        client = OpenAI(
            base_url=ollama_url,
            api_key="ollama",  # Ollama ignores this but OpenAI client requires it
        )
        return client, os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")


def generate_ai_summary(slug: str, scan: dict, score: int) -> str:
    """Generate a plain-language summary using GitHub Models or Ollama."""
    try:
        client, model = get_llm_client()
    except Exception as e:
        return f"AI summary unavailable ({e})."

    prompt = f"""You are a WordPress security and quality expert.
Analyze this plugin scan result and write a short, plain-English summary for a non-technical WordPress site admin.

Plugin: {slug}
Quality Score: {score}/100
Scan Results:
{json.dumps(scan, indent=2)}

Write 3–5 sentences covering:
1. Overall assessment (is it safe to install?)
2. The most important issues found
3. What the admin should do

Be direct and avoid technical jargon."""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI summary unavailable ({e})."


# ──────────────────────────────────────────────
# Report generation
# ──────────────────────────────────────────────

def build_report(slug: str, meta: dict, scan: dict, score: int, summary: str) -> dict:
    return {
        "slug": slug,
        "name": meta.get("name", slug),
        "version": meta.get("version", "unknown"),
        "author": meta.get("author", "unknown"),
        "last_updated": meta.get("last_updated", "unknown"),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "score": score,
        "ai_summary": summary,
        "scan": scan,
    }


def save_json_report(report: dict) -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)
    path = REPORTS_DIR / f"{report['slug']}.json"
    path.write_text(json.dumps(report, indent=2))
    print(f"JSON report saved: {path}")
    return path


def save_html_report(report: dict) -> Path:
    score = report["score"]
    score_color = "#2ecc71" if score >= 70 else "#f39c12" if score >= 40 else "#e74c3c"

    issues_html = ""
    if report["scan"]["security_flags"]:
        issues_html += f"<li><strong>Security:</strong> {', '.join(report['scan']['security_flags'])}</li>"
    if report["scan"]["deprecated_functions"]:
        issues_html += f"<li><strong>Deprecated functions:</strong> {', '.join(report['scan']['deprecated_functions'])}</li>"
    if report["scan"]["deprecated_hooks"]:
        issues_html += f"<li><strong>Deprecated hooks:</strong> {', '.join(report['scan']['deprecated_hooks'])}</li>"
    if report["scan"]["direct_db_files"]:
        issues_html += f"<li><strong>Direct DB access in:</strong> {', '.join(report['scan']['direct_db_files'])}</li>"
    if not issues_html:
        issues_html = "<li>No major issues found.</li>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WP Plugin Insight – {report['name']}</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #333; }}
    .score {{ font-size: 4rem; font-weight: bold; color: {score_color}; }}
    .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
    .meta {{ color: #666; font-size: 0.9rem; }}
    ul {{ line-height: 2; }}
    h2 {{ border-bottom: 2px solid #eee; padding-bottom: 8px; }}
  </style>
</head>
<body>
  <h1>{report['name']}</h1>
  <p class="meta">Version {report['version']} · {report['author']} · Analyzed {report['analyzed_at'][:10]}</p>

  <h2>Quality Score</h2>
  <div class="score">{score}/100</div>

  <h2>AI Summary</h2>
  <div class="summary">{report['ai_summary']}</div>

  <h2>Issues Found</h2>
  <ul>{issues_html}</ul>

  <h2>Details</h2>
  <ul>
    <li><strong>Files scanned:</strong> {report['scan']['files_scanned']}</li>
    <li><strong>Min. PHP required:</strong> {report['scan']['min_php_version']}</li>
    <li><strong>External calls:</strong> {len(report['scan']['external_calls'])}</li>
  </ul>

  <p class="meta">Generated by <a href="..">WP Plugin Insight</a></p>
</body>
</html>"""

    REPORTS_DIR.mkdir(exist_ok=True)
    path = REPORTS_DIR / f"{report['slug']}.html"
    path.write_text(html)
    print(f"HTML report saved: {path}")
    return path


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze.py <plugin-slug>")
        sys.exit(1)

    slug = sys.argv[1].strip().lower()
    print(f"Analyzing plugin: {slug}")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        meta = fetch_plugin_meta(slug)
        plugin_dir = download_plugin(slug, tmp_path)

        print("Scanning...")
        scan = scan_plugin(plugin_dir)

        score = calculate_score(scan)
        print(f"Score: {score}/100")

        print("Generating AI summary...")
        summary = generate_ai_summary(slug, scan, score)

        report = build_report(slug, meta, scan, score, summary)
        save_json_report(report)
        save_html_report(report)

        print("Done.")


if __name__ == "__main__":
    main()
