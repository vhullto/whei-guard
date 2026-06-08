# Whei Guard — Upgrade Plan v2.0
# Bug Bounty Platform Roadmap

## Overview

Upgrading Whei Guard from a static SAST tool to a full bug bounty hunting platform.

```
Current:  Semgrep (Web2) + Slither (Web3) + Groq AI triage + HTML reports

Target:   Recon → SAST → Active Scan → AI Triage → Submission-ready report
          whei recon target.com          → attack surface mapping
          whei scan ./repo --target web2 → existing SAST (unchanged)
          whei hunt target.com           → recon + active scan + AI (full pipeline)
          whei report                    → HackerOne/Intigriti submission pack
```

---

## Phase 1 — Recon Module ✅ IMPLEMENTED

**New file:** `whei_recon.py`
**Modified:** `whei.py` (adds `recon` subcommand)
**New dependency:** `requests`

### Classes

| Class | Purpose |
|-------|---------|
| `SubdomainEnumerator` | crt.sh certificate transparency + HackerTarget passive DNS + parallel DNS resolution |
| `JSEndpointExtractor` | Crawl target for `<script>` tags, fetch JS bundles, regex-extract API paths |
| `TechFingerprinter` | Server/cookie/header/HTML fingerprinting (Wappalyzer-style, no external tools) |
| `WaybackFetcher` | CDX API query for archived URLs, categorized: api / admin / params / sensitive |
| `ReconRunner` | Orchestrator — runs all modules, prints summary, saves JSON |

### CLI
```
whei recon example.com
whei recon example.com --url https://app.example.com --json out.json
```

### Output JSON
```json
{
  "meta": { "domain", "started_at", "duration_seconds" },
  "subdomains": [{ "subdomain", "ip", "alive" }],
  "tech_fingerprint": { "technologies", "missing_security_headers", "headers" },
  "js_endpoints": { "js_files", "endpoints", "total_endpoints" },
  "wayback": { "total", "urls", "categories", "summary" }
}
```

### Complexity: M
No external tools needed — pure Python + requests. Uses crt.sh, HackerTarget, and
web.archive.org CDX API (all free, no API key needed).

---

## Phase 2 — DeepSeek Integration ✅ IMPLEMENTED

**Modified:** `whei_ai.py`, `whei.py`
**New env var:** `DEEPSEEK_API_KEY`

### Models added

| Key | Model ID | Notes |
|-----|----------|-------|
| `chat` | `deepseek-chat` | Fast, JSON mode supported, good for SAST triage |
| `reasoner` | `deepseek-reasoner` | Chain-of-thought, best accuracy, no JSON mode |

### Usage
```
whei scan ./repo --target web2 --ai --provider deepseek
whei scan ./repo --target web2 --ai --provider deepseek --model reasoner
whei scan ./repo --target web2 --ai --provider deepseek --model chat
```

### Fallback chain
DeepSeek → Groq → offline (graceful degradation, each step tried on failure)
Configured automatically when `--provider deepseek` is used.

### .env additions
```
DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx
```

### Complexity: S

---

## Phase 3 — Active Scanner (whei_scan_active.py)

**New file:** `whei_scan_active.py`
**Modified:** `whei.py` (adds `hunt` subcommand)
**New dependencies:** none (uses requests, already added)

### Modules

| Class | Purpose | Complexity |
|-------|---------|-----------|
| `ParameterFuzzer` | HTTP param fuzzing: SQLi, XSS, SSTI basic payloads | M |
| `CORSChecker` | CORS misconfiguration: wildcard origin, null origin, subdomain reflection | S |
| `OpenRedirectDetector` | Tests redirect params with external URL payloads | S |
| `HeaderInjectionTester` | Host header injection, CRLF injection | S |
| `SSRFDetector` | SSRF via Burp Collaborator / interactsh callback (requires setup) | L |

### Rate limiting
- Default: 2 req/s (configurable via `--rate-limit`)
- Configurable via `~/.whei/config.yaml`
- Respects `X-RateLimit-Remaining` headers

### Files to create
- `whei_scan_active.py` — active scanner modules
- Update `whei.py` — add `hunt` subcommand

### CLI
```
whei hunt example.com --scope https://app.example.com --ai
# runs: recon + active scan + AI triage on all findings
```

### Output
Extends existing normalized finding format with `source: "active"` field.
Merges with SAST findings for unified HTML report.

---

## Phase 4 — Workflow Integration

**New file:** `whei_hunt.py`
**Modified:** `whei.py`, `whei_report.py`

### New commands

| Command | What it does |
|---------|-------------|
| `whei recon target.com` | ✅ Full recon (implemented) |
| `whei scan ./repo --target web2 --ai` | ✅ Existing SAST (unchanged) |
| `whei hunt target.com` | Recon + active scan + AI triage (full pipeline) |
| `whei report --from out.json` | Generate HackerOne/Intigriti submission pack |

### SARIF output
```
whei scan ./repo --target web2 --sarif results.sarif
```
Maps Whei findings to SARIF `result` objects for CI/CD integration (GitHub Actions, GitLab CI).

### Burp proxy log import
```
whei scan --burp burp_traffic.xml --target web2 --ai
```
Parses Burp Suite XML export, extracts HTTP history, runs SAST rules on request/response bodies.

### Files to create
- `whei_sarif.py` — SARIF formatter
- `whei_burp.py` — Burp XML parser
- Update `whei_report.py` — add HackerOne submission template

---

## Phase 5 — Quality of Life

**New files:** `whei_config.py`, `whei_session.py`, `~/.whei/config.yaml`

### Config file (`~/.whei/config.yaml`)
```yaml
default_provider: deepseek
default_model: chat
fallback_providers:
  - groq
  - offline
rate_limit: 2      # req/s for active scanning
max_subdomains: 500
wayback_limit: 5000

api_keys:
  # loaded from env vars if not here
  groq: ~
  deepseek: ~
  anthropic: ~

notifications:
  webhook: ~       # Slack/Discord webhook on critical finding
  email: ~
```

### Session management
```
whei hunt --session my-bb-session target.com   # start/resume session
whei sessions list                              # list saved sessions
whei sessions resume my-bb-session
```

### Plugin architecture
```python
# ~/.whei/plugins/my_detector.py
from whei_plugins import BaseDetector

class MyCustomDetector(BaseDetector):
    name = "my-check"
    def detect(self, response) -> list[Finding]: ...
```

### Notifications
```python
# Webhook fired when CVSS >= 7.0 finding detected
webhook_payload = {
    "text": f"🔴 High finding: {finding['titulo']}",
    "cvss": finding['cvss_score'],
    "url": target,
}
```

### Files to create
- `whei_config.py` — YAML config loader with env var fallback
- `whei_session.py` — session state persistence
- `whei_notify.py` — webhook/email notifications
- `~/.whei/config.yaml` — user config template

### Complexity: M

---

## Dependency Map

| Dependency | Phase | Use |
|-----------|-------|-----|
| `requests` | 1 | HTTP for recon (crt.sh, CDX, JS fetching) |
| `requests` | 3 | Active scanner HTTP requests |
| `anthropic` | current | Anthropic Claude provider |
| `groq` | current | Groq LLM provider |
| `pyyaml` | 5 | Config file parsing |
| *(deepseek uses requests, no extra package)* | 2 | |

---

## Architecture Update

```
whei-guard/
├── whei.py              # CLI + orchestrator (+ recon/hunt subcommands)
├── whei_ai.py           # AI: Groq + Anthropic + DeepSeek
├── whei_report.py       # HTML report generator
├── whei_recon.py        # ✅ NEW: recon module
├── whei_scan_active.py  # PLANNED: active HTTP scanner
├── whei_hunt.py         # PLANNED: full pipeline orchestrator
├── whei_sarif.py        # PLANNED: SARIF formatter
├── whei_config.py       # PLANNED: config file loader
├── whei_session.py      # PLANNED: session management
├── requirements.txt     # updated with requests
├── setup.py             # updated with requests
└── whei_rules/          # Web3 detectors (unchanged)
```

---

## Immediate Next Steps (after Phase 1+2)

1. Run `pip install requests` or `pip install -e .` to pick up new dependency
2. Set `DEEPSEEK_API_KEY` in `.env` for DeepSeek support
3. Test: `whei recon hackerone.com --json test_recon.json`
4. Test: `whei scan . --target web2 --ai --provider deepseek`

## Bug Bounty Workflow (today)

```bash
# 1. Recon the target
whei recon target.com --json target_recon.json

# 2. Clone any open-source repo or extract JS
git clone https://github.com/company/app && whei scan ./app --target web2 --ai --provider deepseek

# 3. Review findings and generate report
whei scan ./app --target web2 --ai --html report.html --json findings.json

# 4. Submit to HackerOne/Intigriti using template from AI output
```
