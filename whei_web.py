#!/usr/bin/env python3
"""
whei_web.py — Web dashboard for Whei Guard bug bounty platform.

Usage:
    python whei_web.py              → http://localhost:1337
    python whei_web.py --port 8080  → custom port
"""

import json
import os
import queue
import re
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ── optional yaml ─────────────────────────────────────────────────────────────
try:
    import yaml
    _YAML = True
except ImportError:
    _YAML = False

# ── flask check ───────────────────────────────────────────────────────────────
try:
    from flask import Flask, Response, jsonify, request, stream_with_context
except ImportError:
    print("Flask not installed.  Run:  pip install flask", file=sys.stderr)
    sys.exit(1)

# ── paths ─────────────────────────────────────────────────────────────────────
WHEI_DIR     = Path.home() / ".whei"
CONFIG_FILE  = WHEI_DIR / "config.yaml"
HISTORY_FILE = WHEI_DIR / "history.json"
RESULTS_DIR  = WHEI_DIR / "results"
PORT         = 1337

for _d in (WHEI_DIR, RESULTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════════
# Config I/O
# ═══════════════════════════════════════════════════════════════════════════════

_DEFAULT_RECON_CFG: dict = {
    "mode": "passive",
    "modules": {
        "subdomains":       True,
        "tech_fingerprint": True,
        "js_endpoints":     True,
        "wayback":          True,
        "dns_resolve":      True,
    },
    "subdomain_sources": {
        "crtsh":        True,
        "hackertarget": True,
    },
    "limits": {
        "max_subs":      500,
        "wayback_limit": 5000,
        "max_js":        30,
        "timeout":       15,
        "dns_threads":   60,
    },
    "output": {
        "auto_save":  True,
        "output_dir": "",
    },
}

_DEFAULT_ACTIVE_CFG: dict = {
    "rate_limit":   2.0,
    "scan_timeout": 300,
    "scanners": {
        "cors":             True,
        "open_redirect":    True,
        "security_headers": True,
        "header_injection": True,
        "param_fuzz":       True,
    },
    "limits": {
        "timeout":  15,
        "max_urls": 200,
    },
}

_DEFAULT_CFG: dict = {
    "default_provider": "groq",
    "default_model":    "scout",
    "rate_limit":       2,
    "api_keys":         {"groq": "", "deepseek": "", "anthropic": ""},
    "recon":            _DEFAULT_RECON_CFG,
    "active":           _DEFAULT_ACTIVE_CFG,
}


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return dict(_DEFAULT_CFG)
    try:
        with open(CONFIG_FILE) as f:
            raw = yaml.safe_load(f) if _YAML else json.load(f)
        raw = raw or {}
        cfg = dict(_DEFAULT_CFG)
        cfg.update(raw)
        cfg["api_keys"] = {**_DEFAULT_CFG["api_keys"], **raw.get("api_keys", {})}
        # Deep-merge recon sub-dict
        dr = _DEFAULT_RECON_CFG
        rr = raw.get("recon", {})
        cfg["recon"] = {
            "mode":               rr.get("mode", dr["mode"]),
            "modules":            {**dr["modules"],            **rr.get("modules",            {})},
            "subdomain_sources":  {**dr["subdomain_sources"],  **rr.get("subdomain_sources",  {})},
            "limits":             {**dr["limits"],             **rr.get("limits",             {})},
            "output":             {**dr["output"],             **rr.get("output",             {})},
        }
        da = _DEFAULT_ACTIVE_CFG
        ra = raw.get("active", {})
        cfg["active"] = {
            "rate_limit":   ra.get("rate_limit",   da["rate_limit"]),
            "scan_timeout": ra.get("scan_timeout", da["scan_timeout"]),
            "scanners":     {**da["scanners"],  **ra.get("scanners", {})},
            "limits":       {**da["limits"],    **ra.get("limits",   {})},
        }
        return cfg
    except Exception:
        return dict(_DEFAULT_CFG)


def save_config(cfg: dict) -> None:
    with open(CONFIG_FILE, "w") as f:
        if _YAML:
            yaml.dump(cfg, f, default_flow_style=False)
        else:
            json.dump(cfg, f, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# History I/O
# ═══════════════════════════════════════════════════════════════════════════════

def load_history() -> list:
    if not HISTORY_FILE.exists():
        return []
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def add_history_entry(summary: dict, full_results: dict | None = None) -> None:
    history = load_history()
    history.insert(0, summary)
    history = history[:200]
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2, ensure_ascii=False, default=str)
    if full_results is not None:
        rp = RESULTS_DIR / f"{summary['id']}.json"
        with open(rp, "w") as f:
            json.dump(full_results, f, indent=2, ensure_ascii=False, default=str)


def get_result(job_id: str) -> dict | None:
    p = RESULTS_DIR / f"{job_id}.json"
    if not p.exists():
        return None
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# API key validation
# ═══════════════════════════════════════════════════════════════════════════════

def test_api_key(provider: str, key: str) -> tuple:
    if not key or len(key) < 8:
        return False, "Key too short"
    try:
        import requests as _req
    except ImportError:
        fmt = (
            (provider == "groq"      and key.startswith("gsk_")) or
            (provider == "anthropic" and key.startswith("sk-ant-")) or
            (provider == "deepseek"  and key.startswith("sk-"))
        )
        return (True, "Format valid") if fmt else (False, "Invalid format")

    try:
        if provider == "groq":
            r = _req.get("https://api.groq.com/openai/v1/models",
                         headers={"Authorization": f"Bearer {key}"}, timeout=8)
            if r.status_code == 200:
                return True, f"Valid — {len(r.json().get('data', []))} models"
            return False, f"HTTP {r.status_code}"

        if provider == "deepseek":
            r = _req.get("https://api.deepseek.com/v1/models",
                         headers={"Authorization": f"Bearer {key}"}, timeout=8)
            return (True, "Valid") if r.status_code == 200 else (False, f"HTTP {r.status_code}")

        if provider == "anthropic":
            r = _req.get("https://api.anthropic.com/v1/models",
                         headers={"x-api-key": key, "anthropic-version": "2023-06-01"}, timeout=8)
            if r.status_code == 200:
                return True, f"Valid — {len(r.json().get('data', []))} models"
            return False, f"HTTP {r.status_code}"

    except Exception as exc:
        return False, str(exc)[:80]
    return False, "Unknown provider"


# ═══════════════════════════════════════════════════════════════════════════════
# Background job management
# ═══════════════════════════════════════════════════════════════════════════════

_jobs: dict = {}
_jobs_lock  = threading.Lock()


def _make_job(job_type: str, target: str) -> str:
    jid = uuid.uuid4().hex[:12]
    with _jobs_lock:
        _jobs[jid] = {
            "q":          queue.Queue(),
            "status":     "running",
            "result":     None,
            "type":       job_type,
            "target":     target,
            "started_at": datetime.now().isoformat(),
        }
    return jid


def _push(jid: str, event: dict) -> None:
    with _jobs_lock:
        j = _jobs.get(jid)
    if j:
        j["q"].put(event)


def _run_recon(jid: str, domain: str, base_url: str | None,
               overrides: dict | None = None) -> None:
    url = base_url or f"https://{domain}"

    def send(msg: str, level: str = "info") -> None:
        _push(jid, {"type": "progress", "msg": msg, "level": level})

    send(f"[~] Starting recon for {domain} ...")
    try:
        # Load saved config and apply any per-scan overrides on top
        cfg  = load_config()
        rcfg = {
            "mode":              cfg.get("recon", {}).get("mode", "passive"),
            "modules":           dict(cfg.get("recon", {}).get("modules",           {})),
            "subdomain_sources": dict(cfg.get("recon", {}).get("subdomain_sources", {})),
            "limits":            dict(cfg.get("recon", {}).get("limits",            {})),
            "output":            dict(cfg.get("recon", {}).get("output",            {})),
        }
        if overrides:
            for key in ("modules", "subdomain_sources", "limits"):
                if key in overrides and isinstance(overrides[key], dict):
                    rcfg[key].update(overrides[key])

        modules = rcfg["modules"]
        sources = rcfg["subdomain_sources"]
        limits  = rcfg["limits"]

        mod_subs  = modules.get("subdomains",       True)
        mod_tech  = modules.get("tech_fingerprint", True)
        mod_js    = modules.get("js_endpoints",     True)
        mod_wb    = modules.get("wayback",          True)
        mod_dns   = modules.get("dns_resolve",      True)
        src_crtsh = sources.get("crtsh",            True)
        src_ht    = sources.get("hackertarget",     True)

        timeout     = int(limits.get("timeout",       15))
        max_subs    = int(limits.get("max_subs",      500))
        wayback_lim = int(limits.get("wayback_limit", 5000))
        max_js      = int(limits.get("max_js",        30))
        dns_threads = int(limits.get("dns_threads",   60))
        auto_save   = rcfg["output"].get("auto_save", True)

        from whei_recon import (
            SubdomainEnumerator, JSEndpointExtractor,
            TechFingerprinter, WaybackFetcher,
        )

        results: dict = {"meta": {
            "domain": domain, "base_url": url,
            "started_at": datetime.now().isoformat(), "job_id": jid,
        }}

        # ── Subdomains ────────────────────────────────────────────────────────
        if mod_subs:
            srcs_on = ", ".join(filter(None, [
                "crt.sh" if src_crtsh else None,
                "HackerTarget" if src_ht else None,
            ])) or "none"
            send(f"[~] Enumerating subdomains via {srcs_on} ...")
            subs = SubdomainEnumerator(
                domain,
                timeout=timeout,
                max_workers=dns_threads,
                use_crtsh=src_crtsh,
                use_hackertarget=src_ht,
                resolve_dns=mod_dns,
                max_results=max_subs,
            ).enumerate()
            alive_n = sum(1 for s in subs if s.get("alive"))
            send(f"[✓] {len(subs)} subdomains found, {alive_n} alive", "success")
        else:
            subs = []
            send("[~] Subdomain enumeration disabled", "warn")
        results["subdomains"] = subs

        # ── Tech fingerprint ──────────────────────────────────────────────────
        if mod_tech:
            send(f"[~] Fingerprinting {url} ...")
            tech    = TechFingerprinter(url, timeout=timeout).fingerprint()
            techs   = tech.get("technologies", [])
            missing = tech.get("missing_security_headers", [])
            send(f"[✓] Tech: {', '.join(techs[:6]) or 'none detected'}", "success")
            if missing:
                send(f"[!] Missing security headers: {', '.join(missing)}", "warn")
        else:
            tech    = {"technologies": [], "missing_security_headers": []}
            techs   = []
            missing = []
            send("[~] Tech fingerprinting disabled", "warn")
        results["tech_fingerprint"] = tech

        # ── JS endpoints ──────────────────────────────────────────────────────
        if mod_js:
            send("[~] Extracting JS endpoints (cross-origin CDN included) ...")
            js = JSEndpointExtractor(url, timeout=timeout, max_js=max_js).extract()
            n_files = len(js.get("js_files", []))
            n_eps   = js.get("total_endpoints", 0)
            send(f"[✓] {n_eps} endpoints from {n_files} JS files", "success")
            for jf in js.get("js_files", []):
                if jf.get("endpoint_count", 0) > 0:
                    send(f"    {jf['url'].split('/')[-1]}: {jf['endpoint_count']} endpoints", "info")
                elif jf.get("skipped"):
                    send(f"    {jf['url'].split('/')[-1]}: skipped ({jf['skipped']})", "warn")
        else:
            js = {"total_endpoints": 0, "js_files": [], "endpoints": []}
            send("[~] JS endpoint extraction disabled", "warn")
        results["js_endpoints"] = js

        # ── Wayback Machine ───────────────────────────────────────────────────
        if mod_wb:
            send(f"[~] Querying Wayback Machine (limit {wayback_lim:,}) ...")
            wb = WaybackFetcher(domain, limit=wayback_lim,
                                timeout=max(timeout * 3, 45)).fetch()
            s  = wb.get("summary", {})
            send(
                f"[✓] {wb.get('total', 0):,} archived URLs — "
                f"api:{s.get('api',0)} admin:{s.get('admin',0)} "
                f"sensitive:{s.get('sensitive',0)} params:{s.get('params',0)}",
                "success",
            )
        else:
            wb = {"total": 0, "urls": [], "categories": {}, "summary": {}}
            send("[~] Wayback Machine disabled", "warn")
        results["wayback"] = wb

        results["meta"]["completed_at"] = datetime.now().isoformat()
        summary = {
            "id":  jid, "type": "recon", "target": domain, "base_url": url,
            "date": datetime.now().isoformat(), "status": "completed",
            "subdomains":  len(subs),
            "alive":       sum(1 for s in subs if s.get("alive")),
            "technologies": techs[:8],
            "wayback_total": wb.get("total", 0),
            "js_endpoints":  js.get("total_endpoints", 0),
            "missing_security_headers": missing,
        }
        if auto_save:
            add_history_entry(summary, results)

        with _jobs_lock:
            _jobs[jid]["status"] = "completed"
            _jobs[jid]["result"] = results

        send("[✓] Recon complete.", "success")
        _push(jid, {"type": "done", "results": results})

    except ImportError as exc:
        msg = f"Missing dependency: {exc} — pip install requests"
        send(f"[x] {msg}", "error")
        with _jobs_lock:
            _jobs[jid]["status"] = "error"
        _push(jid, {"type": "error", "msg": msg})
    except Exception as exc:
        msg = str(exc)
        send(f"[x] {msg}", "error")
        with _jobs_lock:
            _jobs[jid]["status"] = "error"
        _push(jid, {"type": "error", "msg": msg})


def start_recon(domain: str, base_url: str | None, overrides: dict | None = None) -> str:
    jid = _make_job("recon", domain)
    threading.Thread(target=_run_recon, args=(jid, domain, base_url, overrides), daemon=True).start()
    return jid


def _run_active(jid: str, domain: str, urls: list | None,
                recon_job_id: str | None = None) -> None:
    def send(msg: str, level: str = "info") -> None:
        _push(jid, {"type": "progress", "msg": msg, "level": level})

    try:
        from whei_scan_active import ActiveScanRunner
    except ImportError as exc:
        msg = f"Missing dependency: {exc} — pip install requests"
        send(f"[x] {msg}", "error")
        with _jobs_lock:
            _jobs[jid]["status"] = "error"
        _push(jid, {"type": "error", "msg": msg})
        return

    try:
        cfg = load_config()

        runner = ActiveScanRunner(domain, config=cfg, verbose=False)

        # Populate URLs: from explicit list, or from stored recon result
        if urls:
            runner.set_urls(urls)
        elif recon_job_id:
            recon_data = get_result(recon_job_id)
            if recon_data:
                runner.load_recon_dict(recon_data)
            else:
                send(f"[!] Recon result {recon_job_id!r} not found — using domain base URL", "warn")
                runner.set_urls([f"https://{domain}"])
        else:
            # Try to find the most recent completed recon for this domain
            hist = load_history()
            recent = next(
                (e for e in hist if e.get("type") == "recon"
                 and e.get("target") == domain
                 and e.get("status") == "completed"), None
            )
            if recent:
                recon_data = get_result(recent["id"])
                if recon_data:
                    runner.load_recon_dict(recon_data)
                    send(f"[~] Using recon from {recent['date'][:10]}", "info")
                else:
                    runner.set_urls([f"https://{domain}"])
            else:
                runner.set_urls([f"https://{domain}"])

        results = runner.run(progress_cb=send)

        summary = {
            "id":            jid,
            "type":          "active",
            "target":        domain,
            "date":          datetime.now().isoformat(),
            "status":        "completed",
            "total_findings": results.get("total_findings", 0),
            "scanned_urls":  results.get("meta", {}).get("scanned_urls", 0),
            "severity_counts": results.get("severity_counts", {}),
        }
        add_history_entry(summary, results)

        with _jobs_lock:
            _jobs[jid]["status"] = "completed"
            _jobs[jid]["result"] = results

        _push(jid, {"type": "done", "results": results})

    except Exception as exc:
        msg = str(exc)
        send(f"[x] {msg}", "error")
        with _jobs_lock:
            _jobs[jid]["status"] = "error"
        _push(jid, {"type": "error", "msg": msg})


def start_active_scan(domain: str, urls: list | None = None,
                      recon_job_id: str | None = None) -> str:
    jid = _make_job("active", domain)
    threading.Thread(
        target=_run_active, args=(jid, domain, urls, recon_job_id), daemon=True
    ).start()
    return jid


# ═══════════════════════════════════════════════════════════════════════════════
# Flask app + routes
# ═══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)


@app.route("/")
def page_dashboard():
    return Response(_page_dashboard(), mimetype="text/html")


@app.route("/settings")
def page_settings():
    return Response(_page_settings(), mimetype="text/html")


@app.route("/recon")
def page_recon():
    return Response(_page_recon(), mimetype="text/html")


@app.route("/active-scan")
def page_active_scan():
    return Response(_page_active_scan(), mimetype="text/html")


@app.route("/history")
def page_history():
    return Response(_page_history(), mimetype="text/html")


# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    hist    = load_history()
    domains = {e.get("target", "") for e in hist}
    return jsonify({
        "total_scans":    len(hist),
        "domains":        len(domains),
        "last_scan":      hist[0].get("date", "") if hist else "",
        "recent":         hist[:5],
    })


@app.route("/api/settings/load")
def api_settings_load():
    cfg = load_config()
    return jsonify({
        "default_provider": cfg.get("default_provider", "groq"),
        "default_model":    cfg.get("default_model", "scout"),
        "rate_limit":       cfg.get("rate_limit", 2),
        "api_keys": {
            p: ("set" if v else "")
            for p, v in cfg.get("api_keys", {}).items()
        },
        "recon":   cfg.get("recon",   _DEFAULT_RECON_CFG),
        "active":  cfg.get("active",  _DEFAULT_ACTIVE_CFG),
    })


@app.route("/api/settings/save", methods=["POST"])
def api_settings_save():
    data = request.get_json(force=True) or {}
    cfg  = load_config()
    cfg["default_provider"] = data.get("default_provider", cfg.get("default_provider", "groq"))
    cfg["default_model"]    = data.get("default_model",    cfg.get("default_model",    "scout"))
    cfg["rate_limit"]       = int(data.get("rate_limit",   cfg.get("rate_limit", 2)))
    for p in ("groq", "deepseek", "anthropic"):
        raw = data.get(f"api_key_{p}", "")
        if raw and raw != "set":
            cfg.setdefault("api_keys", {})[p] = raw
    # Recon config
    if "recon" in data:
        r = data["recon"]
        recon = cfg.setdefault("recon", {})
        if "mode" in r:
            recon["mode"] = r["mode"]
        for key in ("modules", "subdomain_sources", "limits", "output"):
            if key in r and isinstance(r[key], dict):
                recon.setdefault(key, {}).update(r[key])
    # Active scanner config
    if "active" in data:
        a = data["active"]
        active = cfg.setdefault("active", {})
        for scalar in ("rate_limit", "scan_timeout"):
            if scalar in a:
                active[scalar] = a[scalar]
        for key in ("scanners", "limits"):
            if key in a and isinstance(a[key], dict):
                active.setdefault(key, {}).update(a[key])
    save_config(cfg)

    # Sync to .env so CLI tools pick up keys
    env_path = Path(__file__).parent / ".env"
    existing: list = []
    skip = {"GROQ_API_KEY=", "DEEPSEEK_API_KEY=", "ANTHROPIC_API_KEY="}
    if env_path.exists():
        for line in env_path.read_text().splitlines(keepends=True):
            if not any(line.startswith(k) for k in skip):
                existing.append(line)
    keys_map = {"groq": "GROQ_API_KEY", "deepseek": "DEEPSEEK_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
    for p, env_name in keys_map.items():
        k = cfg.get("api_keys", {}).get(p, "")
        if k:
            existing.append(f"{env_name}={k}\n")
    env_path.write_text("".join(existing))

    return jsonify({"ok": True, "message": "Saved to ~/.whei/config.yaml and .env"})


@app.route("/api/settings/test_key", methods=["POST"])
def api_settings_test_key():
    data     = request.get_json(force=True) or {}
    provider = data.get("provider", "")
    key      = data.get("key", "")
    if not key or key == "set":
        key = load_config().get("api_keys", {}).get(provider, "")
    if not key:
        return jsonify({"valid": False, "message": "No key configured"})
    valid, msg = test_api_key(provider, key)
    return jsonify({"valid": valid, "message": msg})


@app.route("/api/recon/start", methods=["POST"])
def api_recon_start():
    data      = request.get_json(force=True) or {}
    domain    = (data.get("domain") or "").strip().lower()
    base_url  = (data.get("base_url") or "").strip() or None
    overrides = data.get("overrides") or None
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    if not re.match(r'^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$', domain):
        return jsonify({"error": "Invalid domain format"}), 400
    jid = start_recon(domain, base_url, overrides)
    return jsonify({"job_id": jid, "status": "started"})


@app.route("/api/active/start", methods=["POST"])
def api_active_start():
    data         = request.get_json(force=True) or {}
    domain       = (data.get("domain") or "").strip().lower()
    urls_raw     = data.get("urls") or []
    recon_job_id = data.get("recon_job_id") or None
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    if not re.match(r'^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$', domain):
        return jsonify({"error": "Invalid domain format"}), 400
    urls = [u.strip() for u in urls_raw if u.strip().startswith("http")] if urls_raw else None
    jid  = start_active_scan(domain, urls=urls, recon_job_id=recon_job_id)
    return jsonify({"job_id": jid, "status": "started"})


@app.route("/api/events/<job_id>")
def api_events(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)

    if not job:
        def _nf():
            yield 'data: ' + json.dumps({"type": "error", "msg": "Job not found"}) + '\n\n'
        return Response(stream_with_context(_nf()), mimetype="text/event-stream")

    def _gen():
        q = job["q"]
        while True:
            try:
                ev = q.get(timeout=25)
                yield 'data: ' + json.dumps(ev, default=str) + '\n\n'
                if ev.get("type") in ("done", "error"):
                    break
            except queue.Empty:
                yield 'data: ' + json.dumps({"type": "keepalive"}) + '\n\n'

    return Response(
        stream_with_context(_gen()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/history")
def api_history():
    return jsonify(load_history())


@app.route("/api/history/<job_id>")
def api_history_detail(job_id: str):
    d = get_result(job_id)
    return jsonify(d) if d else (jsonify({"error": "Not found"}), 404)


# ═══════════════════════════════════════════════════════════════════════════════
# CSS
# ═══════════════════════════════════════════════════════════════════════════════

_CSS = """
:root {
  --bg:      #0a0a0f;
  --bg2:     #0f0f1a;
  --bg3:     #13131f;
  --card:    #0f0f1a;
  --card2:   #13131f;
  --border:  #1e1e3a;
  --border2: #2a2a4a;
  --amber:   #ffaa00;
  --amber2:  #cc8800;
  --amber3:  #6a4400;
  --green:   #00ff88;
  --green2:  #00cc66;
  --green3:  #004d28;
  --red:     #ff4d4d;
  --blue:    #4daaff;
  --purple:  #aa88ff;
  --dim:     #555577;
  --dim2:    #333355;
  --text:    #c8c8e8;
  --text2:   #9090b0;
  --glow-a:  rgba(255,170,0,.12);
  --glow-a2: rgba(255,170,0,.28);
  --glow-g:  rgba(0,255,136,.12);
  --mono:    'Share Tech Mono', 'Courier New', monospace;
  --display: 'Orbitron', 'Share Tech Mono', monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:13px;
     line-height:1.6;min-height:100vh}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,
    rgba(0,0,0,.055) 2px,rgba(0,0,0,.055) 4px)}

/* ── Nav ── */
nav{background:var(--bg2);padding:0 1.5rem;display:flex;align-items:center;
    height:50px;position:sticky;top:0;z-index:200;gap:0;
    border-bottom:1px solid var(--border);position:relative}
nav::after{content:'';position:absolute;bottom:-1px;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent 5%,var(--amber) 50%,transparent 95%);
  opacity:.22;pointer-events:none}
.nav-logo{font-family:var(--display);font-size:.9rem;font-weight:700;color:var(--green);
  letter-spacing:.2em;margin-right:2rem;text-decoration:none;
  text-shadow:0 0 12px rgba(0,255,136,.35)}
.nav-logo span{color:var(--amber);text-shadow:0 0 12px rgba(255,170,0,.4)}
nav a{color:var(--dim);text-decoration:none;padding:0 .9rem;height:50px;
  display:flex;align-items:center;font-size:10px;letter-spacing:.18em;
  border-bottom:2px solid transparent;transition:.15s all}
nav a:hover{color:var(--text2);border-bottom-color:var(--amber3)}
nav a.active{color:var(--amber);border-bottom-color:var(--amber);
  text-shadow:0 0 8px var(--glow-a2)}
.nav-space{flex:1}
.nav-clock{font-size:10px;color:var(--dim);letter-spacing:.06em}

/* ── Layout ── */
.container{max-width:1100px;margin:0 auto;padding:1.75rem 1.5rem}
.page-title{font-size:10px;letter-spacing:.35em;color:var(--dim);
  text-transform:uppercase;margin-bottom:1.5rem;
  border-bottom:1px solid var(--border);padding-bottom:.6rem;font-family:var(--display)}
.page-title .acc{color:var(--amber)}

/* ── Cards ── */
.card{background:var(--card);border:1px solid var(--border);border-radius:3px;padding:1.25rem}
.card-label{font-size:10px;letter-spacing:.2em;color:var(--dim);text-transform:uppercase;
  margin-bottom:.5rem}

/* ── Stat cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));
  gap:1rem;margin-bottom:2rem}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:3px;
  padding:1.25rem 1.4rem;transition:.2s all;position:relative;overflow:hidden}
.stat-card::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--amber),transparent);
  opacity:0;transition:.2s}
.stat-card:hover{border-color:var(--amber3);box-shadow:0 0 22px var(--glow-a)}
.stat-card:hover::after{opacity:.55}
.stat-label{font-size:9px;letter-spacing:.28em;color:var(--dim);text-transform:uppercase;
  font-family:var(--display)}
.stat-val{font-size:2rem;font-weight:700;color:var(--amber);font-family:var(--display);
  text-shadow:0 0 16px var(--glow-a2);line-height:1.1;margin:.3rem 0}
.stat-val.green{color:var(--green);text-shadow:0 0 16px var(--glow-g)}
.stat-sub{font-size:11px;color:var(--dim)}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:.45rem;padding:.45rem 1.1rem;
  border:1px solid var(--amber3);background:transparent;color:var(--amber);
  font-family:var(--mono);font-size:12px;letter-spacing:.1em;cursor:pointer;
  border-radius:2px;transition:.15s all;text-decoration:none}
.btn:hover{background:var(--glow-a);box-shadow:0 0 12px var(--glow-a);border-color:var(--amber2)}
.btn:disabled{opacity:.35;cursor:not-allowed}
.btn-primary{background:rgba(255,170,0,.07);border-color:var(--amber2)}
.btn-primary:hover{background:rgba(255,170,0,.14);box-shadow:0 0 20px var(--glow-a2)}
.btn-sm{padding:.28rem .7rem;font-size:11px}
.btn-danger{border-color:var(--red);color:var(--red)}
.btn-danger:hover{background:rgba(255,77,77,.1);border-color:var(--red)}
.btn-group{display:flex;gap:.75rem;flex-wrap:wrap}

/* ── Forms ── */
.form-group{margin-bottom:1.1rem}
.form-label{display:block;font-size:10px;letter-spacing:.15em;color:var(--dim);
  text-transform:uppercase;margin-bottom:.35rem}
.form-input,.form-select{width:100%;background:var(--bg2);border:1px solid var(--border);
  color:var(--text);font-family:var(--mono);font-size:13px;padding:.45rem .7rem;
  border-radius:2px;outline:none;transition:.15s all;-webkit-appearance:none;appearance:none}
.form-input:focus,.form-select:focus{border-color:var(--amber3);box-shadow:0 0 8px var(--glow-a)}
.form-input::placeholder{color:var(--dim2)}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.form-hint{font-size:11px;color:var(--dim);margin-top:.25rem}

/* ── Key status ── */
.key-row{display:flex;align-items:center;gap:.6rem;margin-top:.4rem}
.key-dot{width:8px;height:8px;border-radius:50%;background:var(--dim);flex-shrink:0;
  transition:.2s all}
.key-dot.valid{background:var(--green);box-shadow:0 0 8px var(--green)}
.key-dot.invalid{background:var(--red);box-shadow:0 0 8px var(--red)}
.key-msg{font-size:11px;color:var(--dim)}

/* ── Table ── */
.table-wrap{overflow-x:auto;margin-top:.75rem}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:.45rem .7rem;color:var(--dim);font-size:9px;
  letter-spacing:.22em;text-transform:uppercase;border-bottom:1px solid var(--border);
  cursor:pointer;user-select:none;white-space:nowrap;font-family:var(--display)}
th:hover{color:var(--text2)}
td{padding:.4rem .7rem;border-bottom:1px solid rgba(255,255,255,.025);
  color:var(--text);vertical-align:middle}
tr:hover td{background:var(--bg3)}
.td-amber{color:var(--amber)}
.td-green{color:var(--green)}
.td-red{color:var(--red)}
.td-dim{color:var(--dim)}
.td-ip{font-size:11px;color:var(--dim)}

/* ── Terminal ── */
.terminal{background:#060609;border:1px solid var(--border);border-radius:3px;
  padding:.9rem 1rem;min-height:100px;max-height:380px;overflow-y:auto;
  font-family:var(--mono);font-size:12px;line-height:1.55;scrollbar-width:thin;
  scrollbar-color:var(--border) transparent}
.terminal::-webkit-scrollbar{width:5px}
.terminal::-webkit-scrollbar-thumb{background:var(--border)}
.t-line{margin:1px 0}
.t-info{color:var(--amber)}
.t-success{color:var(--green)}
.t-warn{color:#ffcc44}
.t-error{color:var(--red)}
.t-dim{color:var(--dim)}

/* ── Badges ── */
.badge{display:inline-block;padding:2px 7px;border-radius:2px;font-size:10px;
  letter-spacing:.08em;border:1px solid;white-space:nowrap}
.badge-green{color:var(--green);border-color:var(--green3);background:rgba(0,255,136,.07)}
.badge-amber{color:var(--amber);border-color:var(--amber3);background:rgba(255,170,0,.07)}
.badge-red{color:var(--red);border-color:#551111;background:rgba(255,77,77,.07)}
.badge-yellow{color:#ffcc44;border-color:#554400;background:rgba(255,204,68,.07)}
.badge-blue{color:var(--blue);border-color:#113355;background:rgba(77,170,255,.07)}
.badge-dim{color:var(--dim);border-color:var(--dim2);background:rgba(85,85,119,.06)}

/* ── Sections ── */
.section{margin-bottom:1.75rem}
.section-title{font-size:9px;letter-spacing:.28em;color:var(--dim);text-transform:uppercase;
  border-bottom:1px solid var(--border);padding-bottom:.4rem;margin-bottom:.9rem;
  display:flex;align-items:center;justify-content:space-between;font-family:var(--display)}
.section-title .acc{color:var(--amber)}
.section-count{font-size:11px;color:var(--amber)}

/* ── Result panels ── */
#results-section{display:none;margin-top:1.5rem}
.result-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;
  margin-bottom:1.5rem}
.result-card{background:var(--card2);border:1px solid var(--border);border-radius:3px;
  padding:.9rem 1rem;text-align:center;transition:.15s all}
.result-card:hover{border-color:var(--amber3)}
.result-card .rc-val{font-size:1.75rem;font-weight:700;color:var(--amber);
  font-family:var(--display);text-shadow:0 0 12px var(--glow-a2)}
.result-card .rc-lbl{font-size:9px;color:var(--dim);letter-spacing:.18em;
  text-transform:uppercase;margin-top:.2rem;font-family:var(--display)}
.result-card.rc-warn .rc-val{color:#ffcc44}
.result-card.rc-alert .rc-val{color:var(--red)}

/* ── Search bar ── */
.search-wrap{position:relative;max-width:280px}
.search-wrap input{padding-left:1.75rem}
.search-icon{position:absolute;left:.6rem;top:50%;transform:translateY(-50%);
  color:var(--dim);font-size:12px;pointer-events:none}

/* ── Collapsible ── */
.collap-hdr{cursor:pointer;user-select:none;display:flex;align-items:center;gap:.5rem;
  font-size:9px;letter-spacing:.25em;text-transform:uppercase;color:var(--dim);
  padding:.5rem 0;border-bottom:1px solid var(--border);margin-bottom:.5rem;
  font-family:var(--display)}
.collap-hdr:hover{color:var(--text2)}
.collap-arrow{transition:transform .2s;display:inline-block}
.collap-hdr.open .collap-arrow{transform:rotate(90deg)}
.collap-body{display:none}
.collap-body.open{display:block}

/* ── History ── */
.hist-row{cursor:pointer}
.hist-row:hover td{background:var(--bg3)}
.detail-panel{background:#060609;border:1px solid var(--border);border-radius:3px;
  padding:1rem;margin-top:.5rem;font-size:12px;max-height:340px;overflow-y:auto;
  display:none;line-height:1.7}
.detail-panel.open{display:block}
.detail-panel strong{color:var(--amber2)}

/* ── Misc ── */
.flex{display:flex}.flex-between{display:flex;justify-content:space-between;align-items:center}
.flex-center{display:flex;align-items:center}.gap-1{gap:.5rem}.gap-2{gap:1rem}
.mt-1{margin-top:.5rem}.mt-2{margin-top:1rem}.mt-3{margin-top:1.5rem}
.mb-1{margin-bottom:.5rem}.mb-2{margin-bottom:1rem}
.text-amber{color:var(--amber)}.text-green{color:var(--green)}.text-red{color:var(--red)}
.text-dim{color:var(--dim)}.text-sm{font-size:11px}.text-right{text-align:right}
.mono{font-family:var(--mono)}.display{font-family:var(--display)}
.loading{animation:pulse 1.4s infinite}
.spinner{display:inline-block;width:11px;height:11px;border:2px solid var(--border);
  border-top-color:var(--amber);border-radius:50%;animation:spin .7s linear infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
@keyframes spin{to{transform:rotate(360deg)}}
a{color:var(--amber2);text-decoration:none}
a:hover{color:var(--amber);text-decoration:underline}
.pill-wrap{display:flex;flex-wrap:wrap;gap:.35rem}
code{background:#080810;border:1px solid var(--border2);padding:1px 5px;
  border-radius:2px;font-size:11px;color:var(--amber2)}
@media(max-width:700px){.form-row{grid-template-columns:1fr}.container{padding:1rem}
  .stats-grid{grid-template-columns:1fr 1fr}}
"""


# ═══════════════════════════════════════════════════════════════════════════════
# HTML builders
# ═══════════════════════════════════════════════════════════════════════════════

def _nav(active: str) -> str:
    items = [("/", "dashboard", "DASHBOARD"),
             ("/recon", "recon", "RECON"),
             ("/active-scan", "active-scan", "ACTIVE"),
             ("/history", "history", "HISTORY"),
             ("/settings", "settings", "SETTINGS")]
    links = "".join(
        f'<a href="{h}" class="{"active" if a == active else ""}">{l}</a>'
        for h, a, l in items
    )
    return (
        '<nav>'
        '<a class="nav-logo" href="/">WHEI<span>GUARD</span></a>'
        + links +
        '<div class="nav-space"></div>'
        '<span class="nav-clock" id="nclock"></span>'
        '</nav>'
        '<script>setInterval(function(){'
        'var e=document.getElementById("nclock");'
        'if(e)e.textContent=new Date().toLocaleTimeString();},1000);</script>'
    )


def _base(title: str, active: str, content: str) -> str:
    return (
        '<!DOCTYPE html><html lang="en"><head>'
        '<meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
        '<title>WheiGuard // ' + title + '</title>'
        '<link rel="preconnect" href="https://fonts.googleapis.com">'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        '<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono'
        '&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">'
        '<style>' + _CSS + '</style>'
        '</head><body>'
        + _nav(active) +
        '<div class="container">' + content + '</div>'
        '</body></html>'
    )


# ── Dashboard ─────────────────────────────────────────────────────────────────

_DASHBOARD_JS = """
(function(){
  function fmtDate(iso){
    if(!iso)return'—';
    var d=new Date(iso);
    return d.toLocaleDateString()+' '+d.toLocaleTimeString().slice(0,5);
  }
  function sev(s){
    var m={'High':'badge-red','Medium':'badge-yellow','Low':'badge-blue'};
    return '<span class="badge '+(m[s]||'badge-dim')+'">'+s+'</span>';
  }
  fetch('/api/status').then(function(r){return r.json();}).then(function(d){
    document.getElementById('s-scans').textContent=d.total_scans||0;
    document.getElementById('s-domains').textContent=d.domains||0;
    document.getElementById('s-last').textContent=fmtDate(d.last_scan);

    var tb=document.getElementById('recent-tbody');
    if(!d.recent||!d.recent.length){
      tb.innerHTML='<tr><td colspan="5" style="color:var(--dim);text-align:center;padding:1.5rem">No scans yet — run a recon to get started</td></tr>';
      return;
    }
    tb.innerHTML='';
    d.recent.forEach(function(e,i){
      var tgt=e.target||'';
      var typ=e.type||'recon';
      var dt=fmtDate(e.date);
      var sub=e.subdomains!=null?e.subdomains:'—';
      var wb=e.wayback_total!=null?e.wayback_total:'—';
      var st=e.status==='completed'?'<span class="badge badge-green">done</span>':'<span class="badge badge-yellow">'+e.status+'</span>';
      tb.innerHTML+='<tr><td>'+dt+'</td><td><a href="/history">'+tgt+'</a></td><td>'+typ+'</td><td>'+sub+' subs / '+wb+' wb</td><td>'+st+'</td></tr>';
    });
  }).catch(function(e){
    document.getElementById('s-scans').textContent='—';
    document.getElementById('s-domains').textContent='—';
  });
})();
"""

def _page_dashboard() -> str:
    content = (
        '<p class="page-title"><span class="acc">// </span>DASHBOARD</p>'
        '<div class="stats-grid">'
        '<div class="stat-card"><div class="stat-label">Total Scans</div>'
        '<div class="stat-val" id="s-scans"><span class="spinner"></span></div></div>'
        '<div class="stat-card"><div class="stat-label">Domains Reconned</div>'
        '<div class="stat-val" id="s-domains"><span class="spinner"></span></div></div>'
        '<div class="stat-card"><div class="stat-label">Last Scan</div>'
        '<div class="stat-val" style="font-size:1rem;margin-top:.4rem" id="s-last">—</div></div>'
        '</div>'
        '<div class="section">'
        '<div class="section-title"><span class="acc">// </span>Recent Activity</div>'
        '<div class="table-wrap"><table>'
        '<thead><tr><th>Date</th><th>Target</th><th>Type</th><th>Findings</th><th>Status</th></tr></thead>'
        '<tbody id="recent-tbody"><tr><td colspan="5" style="color:var(--dim);text-align:center">Loading...</td></tr></tbody>'
        '</table></div></div>'
        '<div class="btn-group mt-2">'
        '<a href="/recon" class="btn btn-primary">+ New Recon</a>'
        '<a href="/history" class="btn">View History</a>'
        '</div>'
        '<script>' + _DASHBOARD_JS + '</script>'
    )
    return _base("Dashboard", "dashboard", content)


# ── Settings ──────────────────────────────────────────────────────────────────

_SETTINGS_JS = """
(function(){
  var models={
    groq:['scout','versatile','qwen'],
    anthropic:['sonnet','haiku'],
    deepseek:['chat','reasoner']
  };

  function updateModelDropdown(provider,selected){
    var sel=document.getElementById('default_model');
    sel.innerHTML='';
    (models[provider]||[]).forEach(function(m){
      var o=document.createElement('option');
      o.value=m; o.textContent=m;
      if(m===selected)o.selected=true;
      sel.appendChild(o);
    });
  }

  function setDot(provider,valid,msg){
    var dot=document.getElementById('dot_'+provider);
    var lbl=document.getElementById('msg_'+provider);
    if(dot){dot.className='key-dot '+(valid?'valid':'invalid');}
    if(lbl)lbl.textContent=msg||'';
  }

  function loadReconConfig(recon){
    if(!recon)return;
    var modeEl=document.getElementById('recon_mode');
    if(modeEl&&recon.mode)modeEl.value=recon.mode;
    var mods=recon.modules||{};
    ['subdomains','tech_fingerprint','js_endpoints','wayback','dns_resolve'].forEach(function(m){
      var el=document.getElementById('mod_'+m);
      if(el)el.checked=mods[m]!==false;
    });
    var srcs=recon.subdomain_sources||{};
    ['crtsh','hackertarget'].forEach(function(s){
      var el=document.getElementById('src_'+s);
      if(el)el.checked=srcs[s]!==false;
    });
    var lims=recon.limits||{};
    var limMap={'lim_max_subs':'max_subs','lim_wayback':'wayback_limit',
                'lim_max_js':'max_js','lim_timeout':'timeout','lim_dns_threads':'dns_threads'};
    Object.keys(limMap).forEach(function(id){
      var el=document.getElementById(id);
      if(el&&lims[limMap[id]]!=null)el.value=lims[limMap[id]];
    });
    var out=recon.output||{};
    var asel=document.getElementById('out_auto_save');
    if(asel)asel.checked=out.auto_save!==false;
    var odir=document.getElementById('out_dir');
    if(odir)odir.value=out.output_dir||'';
  }

  function collectReconConfig(){
    function chk(id){var e=document.getElementById(id);return e?e.checked:true;}
    function num(id,def){var e=document.getElementById(id);return e?parseInt(e.value)||def:def;}
    return{
      mode:(document.getElementById('recon_mode')||{value:'passive'}).value,
      modules:{
        subdomains:      chk('mod_subdomains'),
        tech_fingerprint:chk('mod_tech_fingerprint'),
        js_endpoints:    chk('mod_js_endpoints'),
        wayback:         chk('mod_wayback'),
        dns_resolve:     chk('mod_dns_resolve'),
      },
      subdomain_sources:{
        crtsh:       chk('src_crtsh'),
        hackertarget:chk('src_hackertarget'),
      },
      limits:{
        max_subs:     num('lim_max_subs',500),
        wayback_limit:num('lim_wayback',5000),
        max_js:       num('lim_max_js',30),
        timeout:      num('lim_timeout',15),
        dns_threads:  num('lim_dns_threads',60),
      },
      output:{
        auto_save: chk('out_auto_save'),
        output_dir:(document.getElementById('out_dir')||{value:''}).value,
      },
    };
  }

  function loadActiveConfig(active){
    if(!active)return;
    var sc=active.scanners||{};
    ['cors','open_redirect','security_headers','header_injection','param_fuzz'].forEach(function(s){
      var el=document.getElementById('asc_'+s);
      if(el)el.checked=sc[s]!==false;
    });
    var lims=active.limits||{};
    var el=document.getElementById('a_timeout');
    if(el&&lims.timeout!=null)el.value=lims.timeout;
    el=document.getElementById('a_max_urls');
    if(el&&lims.max_urls!=null)el.value=lims.max_urls;
    el=document.getElementById('a_rate_limit');
    if(el&&active.rate_limit!=null)el.value=active.rate_limit;
    el=document.getElementById('a_scan_timeout');
    if(el&&active.scan_timeout!=null)el.value=active.scan_timeout;
  }

  function collectActiveConfig(){
    function chk(id){var e=document.getElementById(id);return e?e.checked:true;}
    function num(id,def){var e=document.getElementById(id);return e?parseFloat(e.value)||def:def;}
    return{
      rate_limit:   num('a_rate_limit',2),
      scan_timeout: num('a_scan_timeout',300),
      scanners:{
        cors:             chk('asc_cors'),
        open_redirect:    chk('asc_open_redirect'),
        security_headers: chk('asc_security_headers'),
        header_injection: chk('asc_header_injection'),
        param_fuzz:       chk('asc_param_fuzz'),
      },
      limits:{
        timeout:  num('a_timeout',15),
        max_urls: num('a_max_urls',200),
      },
    };
  }

  // Load existing config
  fetch('/api/settings/load').then(function(r){return r.json();}).then(function(d){
    var prov=d.default_provider||'groq';
    document.getElementById('default_provider').value=prov;
    updateModelDropdown(prov, d.default_model||'scout');
    document.getElementById('rate_limit').value=d.rate_limit||2;
    ['groq','deepseek','anthropic'].forEach(function(p){
      if(d.api_keys[p]==='set'){
        document.getElementById('key_'+p).placeholder='••••••••••••••••••• (set)';
        setDot(p,true,'Configured');
      }
    });
    loadReconConfig(d.recon);
    loadActiveConfig(d.active);
  });

  document.getElementById('default_provider').addEventListener('change',function(){
    updateModelDropdown(this.value,'');
  });

  // Test key buttons
  ['groq','deepseek','anthropic'].forEach(function(p){
    document.getElementById('test_'+p).addEventListener('click',function(){
      var key=document.getElementById('key_'+p).value;
      var btn=this;
      btn.disabled=true;
      btn.textContent='Testing...';
      setDot(p,false,'');
      fetch('/api/settings/test_key',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({provider:p,key:key||'set'})})
      .then(function(r){return r.json();})
      .then(function(d){
        setDot(p,d.valid,d.message);
        btn.disabled=false; btn.textContent='Test';
      }).catch(function(){btn.disabled=false;btn.textContent='Test';});
    });
  });

  // Save
  document.getElementById('settings-form').addEventListener('submit',function(e){
    e.preventDefault();
    var payload={
      default_provider:document.getElementById('default_provider').value,
      default_model:document.getElementById('default_model').value,
      rate_limit:document.getElementById('rate_limit').value,
      api_key_groq:document.getElementById('key_groq').value,
      api_key_deepseek:document.getElementById('key_deepseek').value,
      api_key_anthropic:document.getElementById('key_anthropic').value,
      recon:collectReconConfig(),
      active:collectActiveConfig(),
    };
    var btn=document.getElementById('save-btn');
    btn.disabled=true; btn.textContent='Saving...';
    fetch('/api/settings/save',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)})
    .then(function(r){return r.json();})
    .then(function(d){
      var fb=document.getElementById('save-feedback');
      fb.textContent=d.message||'Saved';
      fb.style.color=d.ok?'var(--green)':'var(--red)';
      btn.disabled=false; btn.textContent='Save Settings';
      setTimeout(function(){fb.textContent='';},4000);
    }).catch(function(){btn.disabled=false;btn.textContent='Save Settings';});
  });
})();
"""

def _page_settings() -> str:
    def key_row(provider: str, label: str) -> str:
        return (
            '<div class="form-group">'
            '<label class="form-label">' + label + '</label>'
            '<div class="flex gap-1">'
            '<input id="key_' + provider + '" class="form-input" type="password" '
            'placeholder="Enter key..." autocomplete="off">'
            '<button type="button" id="test_' + provider + '" class="btn btn-sm">Test</button>'
            '</div>'
            '<div class="key-row">'
            '<span class="key-dot" id="dot_' + provider + '"></span>'
            '<span class="key-msg" id="msg_' + provider + '"></span>'
            '</div></div>'
        )

    content = (
        '<p class="page-title"><span class="acc">// </span>SETTINGS</p>'
        '<form id="settings-form">'
        '<div class="section">'
        '<div class="section-title"><span class="acc">// </span>AI Provider</div>'
        '<div class="form-row">'
        '<div class="form-group">'
        '<label class="form-label">Default Provider</label>'
        '<select id="default_provider" class="form-select">'
        '<option value="groq">Groq (free)</option>'
        '<option value="deepseek">DeepSeek (low cost)</option>'
        '<option value="anthropic">Anthropic (paid)</option>'
        '</select></div>'
        '<div class="form-group">'
        '<label class="form-label">Default Model</label>'
        '<select id="default_model" class="form-select"></select>'
        '</div></div>'
        '<div class="form-group" style="max-width:200px">'
        '<label class="form-label">Rate Limit (req/s)</label>'
        '<input id="rate_limit" class="form-input" type="number" min="1" max="10" value="2">'
        '<p class="form-hint">Active scanner only — 2 recommended for bug bounty</p>'
        '</div></div>'
        '<div class="section mt-2">'
        '<div class="section-title"><span class="acc">// </span>API Keys</div>'
        + key_row("groq", "Groq API Key (GROQ_API_KEY)")
        + key_row("deepseek", "DeepSeek API Key (DEEPSEEK_API_KEY)")
        + key_row("anthropic", "Anthropic API Key (ANTHROPIC_API_KEY)") +
        '</div>'

        # ── Recon Configuration ──────────────────────────────────────────────
        '<div class="section mt-2">'
        '<div class="section-title"><span class="acc">// </span>Recon Configuration</div>'

        # Mode
        '<div class="form-row">'
        '<div class="form-group">'
        '<label class="form-label">Recon Mode</label>'
        '<select id="recon_mode" class="form-select">'
        '<option value="passive">passive — no active probing (default)</option>'
        '<option value="active">active — port scan + dir brute (Phase 3, coming soon)</option>'
        '</select>'
        '<p class="form-hint">Active mode requires Phase 3 scanner</p>'
        '</div></div>'

        # Modules + Sources side-by-side
        '<div class="form-row" style="grid-template-columns:1fr 1fr">'
        '<div class="form-group">'
        '<p class="form-label">Module Toggles</p>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="mod_subdomains" checked> Subdomain Enumeration</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="mod_tech_fingerprint" checked> Tech Fingerprinting</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="mod_js_endpoints" checked> JS Endpoint Extraction</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="mod_wayback" checked> Wayback Machine URLs</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="mod_dns_resolve" checked> DNS Resolution</label>'
        '</div>'
        '<div class="form-group">'
        '<p class="form-label">Subdomain Sources</p>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="src_crtsh" checked> crt.sh (Certificate Transparency)</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="src_hackertarget" checked> HackerTarget (Passive DNS)</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer;opacity:.4">'
        '<input type="checkbox" disabled> SecurityTrails <span class="badge badge-dim" style="font-size:9px">soon</span></label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer;opacity:.4">'
        '<input type="checkbox" disabled> VirusTotal <span class="badge badge-dim" style="font-size:9px">soon</span></label>'
        '</div></div>'

        # Limits (3-column grid)
        '<p class="form-label" style="margin-top:.75rem;margin-bottom:.5rem">Limits</p>'
        '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:.75rem">'
        '<div class="form-group" style="margin:0">'
        '<label class="form-label">Max Subdomains to Resolve</label>'
        '<input id="lim_max_subs" class="form-input" type="number" min="10" max="5000" value="500"></div>'
        '<div class="form-group" style="margin:0">'
        '<label class="form-label">Wayback URL Limit</label>'
        '<input id="lim_wayback" class="form-input" type="number" min="100" max="50000" value="5000"></div>'
        '<div class="form-group" style="margin:0">'
        '<label class="form-label">Max JS Files</label>'
        '<input id="lim_max_js" class="form-input" type="number" min="1" max="200" value="30"></div>'
        '<div class="form-group" style="margin:0">'
        '<label class="form-label">Request Timeout (s)</label>'
        '<input id="lim_timeout" class="form-input" type="number" min="5" max="120" value="15"></div>'
        '<div class="form-group" style="margin:0">'
        '<label class="form-label">DNS Resolution Threads</label>'
        '<input id="lim_dns_threads" class="form-input" type="number" min="5" max="200" value="60"></div>'
        '</div>'

        # Output
        '<p class="form-label" style="margin-top:.9rem;margin-bottom:.5rem">Output</p>'
        '<div class="form-row">'
        '<div class="form-group">'
        '<label style="display:flex;align-items:center;gap:.5rem;cursor:pointer">'
        '<input type="checkbox" id="out_auto_save" checked> Auto-save JSON to disk</label></div>'
        '<div class="form-group">'
        '<label class="form-label">Output Directory</label>'
        '<input id="out_dir" class="form-input" type="text" placeholder="~/.whei/results (default)">'
        '</div></div>'
        '</div>'

        # ── Active Scanner Configuration ─────────────────────────────────────
        '<div class="section mt-2">'
        '<div class="section-title"><span class="acc">// </span>Active Scanner</div>'
        '<div class="form-row" style="grid-template-columns:1fr 1fr">'
        '<div class="form-group">'
        '<p class="form-label">Scanner Modules</p>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="asc_cors" checked> CORS Misconfiguration</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="asc_open_redirect" checked> Open Redirect</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="asc_security_headers" checked> Security Header Audit</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="asc_header_injection" checked> Host / CRLF Injection</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;margin:.3rem 0;cursor:pointer">'
        '<input type="checkbox" id="asc_param_fuzz" checked> Parameter Fuzzing (XSS/SQLi/SSTI)</label>'
        '</div>'
        '<div class="form-group">'
        '<p class="form-label">Limits</p>'
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:.6rem">'
        '<div class="form-group" style="margin:0">'
        '<label class="form-label">Rate Limit (req/s)</label>'
        '<input id="a_rate_limit" class="form-input" type="number" min="0.5" max="20" step="0.5" value="2">'
        '</div>'
        '<div class="form-group" style="margin:0">'
        '<label class="form-label">Request Timeout (s)</label>'
        '<input id="a_timeout" class="form-input" type="number" min="5" max="60" value="15">'
        '</div>'
        '<div class="form-group" style="margin:0">'
        '<label class="form-label">Max URLs to Test</label>'
        '<input id="a_max_urls" class="form-input" type="number" min="10" max="1000" value="200">'
        '</div>'
        '<div class="form-group" style="margin:0">'
        '<label class="form-label">Scan Timeout (s)</label>'
        '<input id="a_scan_timeout" class="form-input" type="number" min="60" max="3600" value="300">'
        '</div>'
        '</div>'
        '<p class="form-hint" style="margin-top:.5rem">Higher rate = faster scan, higher risk of detection</p>'
        '</div></div></div>'

        '<div class="flex-center gap-2" style="margin-top:.5rem">'
        '<button type="submit" id="save-btn" class="btn btn-primary">Save Settings</button>'
        '<span id="save-feedback" class="text-sm"></span>'
        '</div>'
        '</form>'
        '<script>' + _SETTINGS_JS + '</script>'
    )
    return _base("Settings", "settings", content)


# ── Recon ─────────────────────────────────────────────────────────────────────

_RECON_JS = r"""
(function(){
  var jobId=null, es=null;

  function termLine(msg,level){
    var d=document.getElementById('term');
    if(!d)return;
    var cls={'info':'t-info','success':'t-success','warn':'t-warn','error':'t-error'}[level]||'t-info';
    var line=document.createElement('div');
    line.className='t-line '+cls;
    line.textContent=msg;
    d.appendChild(line);
    d.scrollTop=d.scrollHeight;
  }

  function esc(s){
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function renderResults(r){
    var sec=document.getElementById('results-section');
    if(!sec)return;
    sec.style.display='block';

    var subs=r.subdomains||[];
    var alive=subs.filter(function(s){return s.alive;}).length;
    var tech=r.tech_fingerprint||{};
    var techs=tech.technologies||[];
    var missing=tech.missing_security_headers||[];
    var js=r.js_endpoints||{};
    var wb=r.wayback||{};
    var wbs=wb.summary||{};

    // Summary cards
    var cards=[
      {val:subs.length,lbl:'Subdomains',cls:''},
      {val:alive,lbl:'Alive',cls:''},
      {val:js.total_endpoints||0,lbl:'JS Endpoints',cls:''},
      {val:wb.total||0,lbl:'Wayback URLs',cls:''},
      {val:wbs.sensitive||0,lbl:'Sensitive',cls:(wbs.sensitive||0)?'rc-alert':''},
      {val:missing.length,lbl:'Missing Sec Hdrs',cls:missing.length?'rc-warn':''},
    ];
    var ch=document.getElementById('result-cards');
    ch.innerHTML='';
    cards.forEach(function(c){
      ch.innerHTML+='<div class="result-card '+c.cls+'"><div class="rc-val">'+c.val+'</div><div class="rc-lbl">'+c.lbl+'</div></div>';
    });

    // Tech badges
    var tb=document.getElementById('tech-badges');
    if(techs.length){
      tb.innerHTML=techs.map(function(t){return '<span class="badge badge-amber">'+esc(t)+'</span>';}).join(' ');
    } else {
      tb.innerHTML='<span class="text-dim">none detected</span>';
    }
    if(missing.length){
      tb.innerHTML+='<br><span class="text-dim text-sm" style="margin-top:.35rem;display:inline-block">Missing headers: </span> '
        +missing.map(function(h){return '<span class="badge badge-red">'+esc(h)+'</span>';}).join(' ');
    }

    // JS files per-file breakdown
    renderJSFiles(js);

    // Subdomains table
    renderSubsTable(subs);

    // Wayback categories
    renderWayback(wb);

    // Export button
    var expBtn=document.getElementById('export-btn');
    if(expBtn&&jobId){
      expBtn.style.display='';
      expBtn.onclick=function(){window.open('/api/history/'+jobId,'_blank');};
    }
  }

  function renderJSFiles(js){
    var jsList=document.getElementById('js-list');
    if(!jsList)return;
    var files=js.js_files||[];
    var eps=js.endpoints||[];
    if(!files.length&&!eps.length){
      jsList.innerHTML='<span class="text-dim">No JS files found</span>';
      return;
    }
    var html='';
    // Per-file stats
    if(files.length){
      files.forEach(function(f){
        var name=f.url.split('/').pop().split('?')[0]||f.url;
        var cnt=f.endpoint_count||0;
        var skip=f.skipped?'<span class="badge badge-yellow" style="margin-left:.4rem">'+esc(f.skipped)+'</span>':'';
        var err=f.error?'<span class="text-red" style="font-size:11px;margin-left:.4rem">'+esc(f.error.slice(0,60))+'</span>':'';
        var cntBadge=cnt?'<span class="badge badge-amber" style="margin-left:.4rem">'+cnt+' endpoints</span>':'';
        html+='<div class="t-line t-dim">'+esc(name)+skip+cntBadge+err+'</div>';
      });
      html+='<div style="height:.5rem"></div>';
    }
    // All unique endpoints
    if(eps.length){
      eps.forEach(function(e){
        html+='<div class="t-line"><code>'+esc(e)+'</code></div>';
      });
    } else {
      html+='<div class="t-line t-dim">No API endpoints matched — try the full URL in base URL field</div>';
    }
    jsList.innerHTML=html;
  }

  function renderSubsTable(subs){
    var tbody=document.getElementById('subs-tbody');
    if(!tbody)return;
    tbody.innerHTML='';
    if(!subs.length){
      tbody.innerHTML='<tr><td colspan="3" class="text-dim" style="text-align:center;padding:.75rem">No subdomains found</td></tr>';
      return;
    }
    subs.forEach(function(s){
      var badge=s.alive?'<span class="badge badge-green">alive</span>':'<span class="badge badge-dim">dead</span>';
      tbody.innerHTML+='<tr><td class="td-amber">'+esc(s.subdomain||'')+'</td><td class="td-ip">'+esc(s.ip||'—')+'</td><td>'+badge+'</td></tr>';
    });
    var search=document.getElementById('subs-search');
    if(search){
      search.addEventListener('input',function(){
        var q=this.value.toLowerCase();
        tbody.querySelectorAll('tr').forEach(function(tr){
          tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none';
        });
      });
    }
  }

  function renderWayback(wb){
    var cats=wb.categories||{};
    var container=document.getElementById('wb-cats');
    if(!container)return;
    container.innerHTML='';
    var total=wb.total||0;
    var wbs=wb.summary||{};

    if(!total){
      container.innerHTML='<span class="text-dim">No Wayback URLs found for this domain</span>';
      return;
    }

    var order=['api','admin','sensitive','params','json'];
    var hasAny=order.some(function(cat){return (cats[cat]||[]).length>0;});

    if(!hasAny){
      // Show total count but raw sample
      container.innerHTML='<div class="text-dim text-sm" style="margin-bottom:.5rem">'+total.toLocaleString()+' archived URLs — none matched category filters</div>';
      var raw=wb.urls||[];
      if(raw.length){
        container.innerHTML+='<div class="collap-hdr open" onclick="toggleCollap(this)">'
          +'<span class="collap-arrow" style="transform:rotate(90deg)">▶</span>'
          +'<span class="badge badge-dim">all urls</span>'
          +'<span class="text-dim text-sm" style="margin-left:.4rem">('+Math.min(raw.length,100)+' of '+total.toLocaleString()+')</span>'
          +'</div>'
          +'<div class="collap-body open">'
          +raw.slice(0,100).map(function(u){
            return '<div class="t-line text-sm"><a href="'+esc(u.original||'')+'" target="_blank">'+esc(u.original||'')+'</a></div>';
          }).join('')
          +'</div>';
      }
      return;
    }

    // Render category sections — api and sensitive auto-open
    order.forEach(function(cat){
      var items=cats[cat]||[];
      if(!items.length)return;
      var autoOpen=cat==='api'||cat==='sensitive';
      var badgeCls=cat==='sensitive'?'badge-red':cat==='admin'?'badge-yellow':'badge-amber';
      var hdrOpen=autoOpen?' open':'';
      var bodyOpen=autoOpen?' open':'';
      var arrowStyle=autoOpen?' style="transform:rotate(90deg)"':'';
      container.innerHTML+='<div class="collap-hdr'+hdrOpen+'" onclick="toggleCollap(this)">'
        +'<span class="collap-arrow"'+arrowStyle+'>▶</span>'
        +'<span class="badge '+badgeCls+'">'+cat+'</span>'
        +'<span class="text-dim text-sm" style="margin-left:.4rem">('+items.length.toLocaleString()+')</span>'
        +'</div>'
        +'<div class="collap-body'+bodyOpen+'">'
        +items.slice(0,100).map(function(u){
          return '<div class="t-line text-sm"><a href="'+esc(u.original||'')+'" target="_blank">'+esc(u.original||'')+'</a></div>';
        }).join('')
        +(items.length>100?'<div class="text-dim text-sm" style="margin:.3rem 0">...and '+(items.length-100).toLocaleString()+' more</div>':'')
        +'</div>';
    });
  }

  window.toggleCollap=function(hdr){
    hdr.classList.toggle('open');
    var body=hdr.nextElementSibling;
    if(body)body.classList.toggle('open');
  };

  // ── Advanced Options ──────────────────────────────────────────────────────
  window.toggleAdvanced=function(){
    var body=document.getElementById('adv-body');
    var arrow=document.getElementById('adv-arrow');
    if(!body)return;
    var open=body.style.display!=='none';
    body.style.display=open?'none':'block';
    if(arrow)arrow.style.transform=open?'':'rotate(90deg)';
  };

  // Load saved config into advanced options defaults
  fetch('/api/settings/load').then(function(r){return r.json();}).then(function(d){
    var rc=d.recon||{};
    var mods=rc.modules||{};
    var srcs=rc.subdomain_sources||{};
    var lims=rc.limits||{};
    ['subdomains','tech_fingerprint','js_endpoints','wayback','dns_resolve'].forEach(function(m){
      var el=document.getElementById('adv_mod_'+m);
      if(el)el.checked=mods[m]!==false;
    });
    ['crtsh','hackertarget'].forEach(function(s){
      var el=document.getElementById('adv_src_'+s);
      if(el)el.checked=srcs[s]!==false;
    });
    var limMap={adv_max_subs:'max_subs',adv_wayback_limit:'wayback_limit',
                adv_max_js:'max_js',adv_timeout:'timeout',adv_dns_threads:'dns_threads'};
    Object.keys(limMap).forEach(function(id){
      var el=document.getElementById(id);
      if(el&&lims[limMap[id]]!=null)el.value=lims[limMap[id]];
    });
  });

  function collectOverrides(){
    var body=document.getElementById('adv-body');
    if(!body||body.style.display==='none')return null;
    function chk(id){var e=document.getElementById(id);return e?e.checked:true;}
    function num(id,def){var e=document.getElementById(id);return e?parseInt(e.value)||def:def;}
    return{
      modules:{
        subdomains:      chk('adv_mod_subdomains'),
        tech_fingerprint:chk('adv_mod_tech_fingerprint'),
        js_endpoints:    chk('adv_mod_js_endpoints'),
        wayback:         chk('adv_mod_wayback'),
        dns_resolve:     chk('adv_mod_dns_resolve'),
      },
      subdomain_sources:{
        crtsh:       chk('adv_src_crtsh'),
        hackertarget:chk('adv_src_hackertarget'),
      },
      limits:{
        max_subs:     num('adv_max_subs',500),
        wayback_limit:num('adv_wayback_limit',5000),
        max_js:       num('adv_max_js',30),
        timeout:      num('adv_timeout',15),
        dns_threads:  num('adv_dns_threads',60),
      },
    };
  }

  // ── Form submit ───────────────────────────────────────────────────────────
  document.getElementById('recon-form').addEventListener('submit',function(e){
    e.preventDefault();
    var domain=document.getElementById('domain').value.trim();
    var url=document.getElementById('base_url').value.trim();
    if(!domain)return;

    document.getElementById('results-section').style.display='none';
    var term=document.getElementById('term');
    term.innerHTML='';
    document.getElementById('term-section').style.display='block';
    var btn=document.getElementById('start-btn');
    btn.disabled=true;
    btn.innerHTML='<span class="spinner"></span> Running...';

    if(es){es.close();es=null;}

    fetch('/api/recon/start',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({domain:domain,base_url:url||null,overrides:collectOverrides()})
    })
    .then(function(r){return r.json();})
    .then(function(d){
      if(d.error){termLine('[x] '+d.error,'error');btn.disabled=false;btn.textContent='Start Recon';return;}
      jobId=d.job_id;
      es=new EventSource('/api/events/'+jobId);
      es.onmessage=function(ev){
        var data=JSON.parse(ev.data);
        if(data.type==='progress'){
          termLine(data.msg,data.level||'info');
        } else if(data.type==='done'){
          es.close();es=null;
          btn.disabled=false;btn.textContent='Start Recon';
          renderResults(data.results);
        } else if(data.type==='error'){
          es.close();es=null;
          btn.disabled=false;btn.textContent='Start Recon';
          termLine('[x] '+data.msg,'error');
        }
      };
      es.onerror=function(){
        es.close();es=null;
        btn.disabled=false;btn.textContent='Start Recon';
        termLine('[x] Connection lost','error');
      };
    }).catch(function(err){
      btn.disabled=false;btn.textContent='Start Recon';
      termLine('[x] '+err.message,'error');
    });
  });
})();
"""

def _page_recon() -> str:
    def _chk(id_: str, label: str) -> str:
        return (
            '<label style="display:flex;align-items:center;gap:.5rem;'
            'margin:.25rem 0;cursor:pointer;font-size:12px;">'
            '<input type="checkbox" id="' + id_ + '" checked> ' + label + '</label>'
        )

    def _num(id_: str, label: str, val: str, mi: str, ma: str) -> str:
        return (
            '<div style="margin-bottom:.5rem">'
            '<label class="form-label" style="font-size:9px">' + label + '</label>'
            '<input id="' + id_ + '" class="form-input" type="number" '
            'min="' + mi + '" max="' + ma + '" value="' + val + '" '
            'style="width:90px;padding:.3rem .5rem">'
            '</div>'
        )

    content = (
        '<p class="page-title"><span class="acc">// </span>RECON</p>'
        '<div class="card mb-2">'
        '<form id="recon-form">'
        '<div class="form-row">'
        '<div class="form-group">'
        '<label class="form-label">Target Domain *</label>'
        '<input id="domain" class="form-input" type="text" placeholder="example.com" required autocomplete="off">'
        '</div>'
        '<div class="form-group">'
        '<label class="form-label">Base URL (optional)</label>'
        '<input id="base_url" class="form-input" type="text" placeholder="https://app.example.com">'
        '<p class="form-hint">Override for tech fingerprinting and JS extraction</p>'
        '</div>'
        '</div>'

        # Advanced Options collapsible
        '<div style="margin:.75rem 0 .5rem">'
        '<div class="collap-hdr" style="border:0;padding:.3rem 0;margin:0" onclick="toggleAdvanced()">'
        '<span class="collap-arrow" id="adv-arrow">▶</span>'
        '<span style="font-size:10px;letter-spacing:.15em;color:var(--dim)">ADVANCED OPTIONS</span>'
        '<span class="text-dim text-sm" style="margin-left:.5rem">(per-scan overrides)</span>'
        '</div></div>'

        '<div id="adv-body" style="display:none;border:1px solid var(--border);'
        'border-radius:3px;padding:.9rem 1rem;margin-bottom:.75rem;background:var(--bg3)">'

        '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:.5rem 1.5rem">'

        # Module toggles
        '<div>'
        '<p class="form-label" style="font-size:9px;margin-bottom:.3rem">Modules</p>'
        + _chk("adv_mod_subdomains", "Subdomains")
        + _chk("adv_mod_tech_fingerprint", "Tech Fingerprint")
        + _chk("adv_mod_js_endpoints", "JS Endpoints")
        + _chk("adv_mod_wayback", "Wayback Machine")
        + _chk("adv_mod_dns_resolve", "DNS Resolve") +
        '</div>'

        # Sources
        '<div>'
        '<p class="form-label" style="font-size:9px;margin-bottom:.3rem">Subdomain Sources</p>'
        + _chk("adv_src_crtsh", "crt.sh")
        + _chk("adv_src_hackertarget", "HackerTarget") +
        '</div>'

        # Limits
        '<div>'
        '<p class="form-label" style="font-size:9px;margin-bottom:.3rem">Limits</p>'
        + _num("adv_max_subs",      "Max Subdomains", "500",  "10",  "5000")
        + _num("adv_wayback_limit", "Wayback Limit",  "5000", "100", "50000")
        + _num("adv_max_js",        "Max JS Files",   "30",   "1",   "200")
        + _num("adv_timeout",       "Timeout (s)",    "15",   "5",   "120")
        + _num("adv_dns_threads",   "DNS Threads",    "60",   "5",   "200") +
        '</div>'
        '</div></div>'

        '<button type="submit" id="start-btn" class="btn btn-primary">Start Recon</button>'
        '</form></div>'

        # Terminal
        '<div id="term-section" style="display:none" class="section">'
        '<div class="section-title"><span class="acc">// </span>Progress</div>'
        '<div class="terminal" id="term"></div>'
        '</div>'

        # Results
        '<div id="results-section">'
        '<div class="flex-between mb-1">'
        '<div class="section-title" style="border:0;margin:0"><span class="acc">// </span>Results</div>'
        '<button id="export-btn" class="btn btn-sm" style="display:none">Export JSON</button>'
        '</div>'

        '<div class="result-cards" id="result-cards"></div>'

        # Tech stack
        '<div class="section">'
        '<div class="section-title"><span class="acc">// </span>Tech Stack</div>'
        '<div class="pill-wrap" id="tech-badges"></div>'
        '</div>'

        # Subdomains
        '<div class="section">'
        '<div class="section-title"><span class="acc">// </span>Subdomains'
        '<div class="search-wrap"><span class="search-icon">🔍</span>'
        '<input id="subs-search" class="form-input" type="text" placeholder="Filter...">'
        '</div></div>'
        '<div class="table-wrap"><table>'
        '<thead><tr><th>Subdomain</th><th>IP</th><th>Status</th></tr></thead>'
        '<tbody id="subs-tbody"></tbody>'
        '</table></div></div>'

        # JS Endpoints
        '<div class="section">'
        '<div class="section-title"><span class="acc">// </span>JS Endpoints</div>'
        '<div class="terminal" id="js-list" style="min-height:60px"></div>'
        '</div>'

        # Wayback
        '<div class="section">'
        '<div class="section-title"><span class="acc">// </span>Wayback Machine URLs</div>'
        '<div id="wb-cats"></div>'
        '</div>'
        '</div>'

        '<script>' + _RECON_JS + '</script>'
    )
    return _base("Recon", "recon", content)


# ── Active Scan ───────────────────────────────────────────────────────────────

_ACTIVE_JS = r"""
(function(){
  var jobId=null, es=null;

  function esc(s){
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
  function termLine(msg,level){
    var d=document.getElementById('aterm');
    if(!d)return;
    var cls={info:'t-info',success:'t-success',warn:'t-warn',error:'t-error'}[level]||'t-info';
    var line=document.createElement('div');
    line.className='t-line '+cls;
    line.textContent=msg;
    d.appendChild(line);
    d.scrollTop=d.scrollHeight;
  }

  var SEV_CLS={Critical:'badge-red',High:'badge-red',Medium:'badge-yellow',Low:'badge-blue',Info:'badge-dim'};

  function sevBadge(s){
    return '<span class="badge '+(SEV_CLS[s]||'badge-dim')+'">'+esc(s)+'</span>';
  }
  function confBadge(c){
    var m={Confirmed:'badge-green',Likely:'badge-amber',Potential:'badge-dim'};
    return '<span class="badge '+(m[c]||'badge-dim')+'">'+esc(c)+'</span>';
  }

  function renderResults(r){
    var sec=document.getElementById('active-results');
    if(!sec)return;
    sec.style.display='block';

    var findings=r.findings||[];
    var sev=r.severity_counts||{};
    var meta=r.meta||{};

    // Summary cards
    var cardCont=document.getElementById('a-cards');
    cardCont.innerHTML='';
    [
      {v:findings.length,l:'Total Findings',cls:''},
      {v:sev.Critical||0,l:'Critical',cls:(sev.Critical||0)?'rc-alert':''},
      {v:sev.High||0,l:'High',cls:(sev.High||0)?'rc-alert':''},
      {v:sev.Medium||0,l:'Medium',cls:(sev.Medium||0)?'rc-warn':''},
      {v:sev.Low||0,l:'Low',cls:''},
      {v:meta.scanned_urls||0,l:'URLs Tested',cls:''},
    ].forEach(function(c){
      cardCont.innerHTML+='<div class="result-card '+c.cls+'"><div class="rc-val">'+c.v+'</div><div class="rc-lbl">'+c.l+'</div></div>';
    });

    // Findings table
    var tbody=document.getElementById('a-findings-tbody');
    if(!findings.length){
      tbody.innerHTML='<tr><td colspan="5" style="color:var(--dim);text-align:center;padding:1.5rem">No findings — target looks clean for tested vectors</td></tr>';
    } else {
      tbody.innerHTML='';
      var priority=['Critical','High','Medium','Low','Info'];
      findings.slice().sort(function(a,b){
        return priority.indexOf(a.severidade)-priority.indexOf(b.severidade);
      }).forEach(function(f,i){
        var rid='afd_'+i;
        var row='<tr class="hist-row" onclick="toggleFinding(\''+rid+'\')">'
          +'<td>'+sevBadge(f.severidade)+'</td>'
          +'<td>'+confBadge(f.confianca)+'</td>'
          +'<td style="color:var(--text)">'+esc(f.titulo)+'</td>'
          +'<td class="text-dim" style="font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(f.url||'')+'</td>'
          +'<td class="text-dim" style="font-size:10px">'+esc(f.regra||'')+'</td>'
          +'</tr>'
          +'<tr class="detail-tr" id="'+rid+'" style="display:none"><td colspan="5">'
          +'<div class="detail-panel open" style="display:block">'
          +'<div style="margin-bottom:.5rem"><strong>Description:</strong> '+esc(f.descricao||'')+'</div>'
          +(f.trecho?'<div style="margin-bottom:.4rem"><strong>Evidence:</strong> <code>'+esc(f.trecho)+'</code></div>':'')
          +(f.request?'<div style="margin-bottom:.4rem"><strong>Request:</strong><br><pre style="margin:.3rem 0;font-size:11px;color:var(--text2)">'+esc(f.request)+'</pre></div>':'')
          +(f.response?'<div><strong>Response:</strong><br><pre style="margin:.3rem 0;font-size:11px;color:var(--text2)">'+esc(f.response)+'</pre></div>':'')
          +'</div></td></tr>';
        tbody.innerHTML+=row;
      });
    }

    // Export button
    document.getElementById('a-export-btn').style.display='inline-flex';
    document.getElementById('a-export-btn').onclick=function(){
      var blob=new Blob([JSON.stringify(r,null,2)],{type:'application/json'});
      var a=document.createElement('a');
      a.href=URL.createObjectURL(blob);
      a.download='active_'+meta.domain+'_'+new Date().toISOString().slice(0,10)+'.json';
      a.click();
    };
  }

  window.toggleFinding=function(id){
    var el=document.getElementById(id);
    if(el)el.style.display=el.style.display==='none'?'table-row':'none';
  };

  function setRunning(running){
    var btn=document.getElementById('a-start-btn');
    var sp=document.getElementById('a-spinner');
    btn.disabled=running;
    btn.textContent=running?'Scanning...':'Start Active Scan';
    if(sp)sp.style.display=running?'inline-block':'none';
  }

  function startScan(){
    var domain=(document.getElementById('a-domain').value||'').trim().toLowerCase();
    if(!domain){alert('Enter a target domain');return;}

    var src=document.querySelector('input[name="a-src"]:checked');
    var srcVal=src?src.value:'auto';
    var urls=null;
    if(srcVal==='manual'){
      var raw=document.getElementById('a-urls-manual').value||'';
      urls=raw.split('\n').map(function(u){return u.trim();}).filter(Boolean);
      if(!urls.length){alert('Enter at least one URL');return;}
    }

    var term=document.getElementById('aterm');
    term.innerHTML='';
    document.getElementById('active-results').style.display='none';
    setRunning(true);
    termLine('[~] Connecting to active scan engine ...','info');

    var payload={domain:domain};
    if(urls)payload.urls=urls;

    fetch('/api/active/start',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)})
    .then(function(r){return r.json();})
    .then(function(d){
      if(d.error){termLine('[x] '+d.error,'error');setRunning(false);return;}
      jobId=d.job_id;
      es=new EventSource('/api/events/'+jobId);
      es.onmessage=function(ev){
        var evt=JSON.parse(ev.data);
        if(evt.type==='progress'){
          termLine(evt.msg,evt.level||'info');
        } else if(evt.type==='done'){
          es.close();
          setRunning(false);
          termLine('[✓] Scan complete.','success');
          renderResults(evt.results||{});
        } else if(evt.type==='error'){
          es.close();
          setRunning(false);
          termLine('[x] '+evt.msg,'error');
        }
      };
      es.onerror=function(){
        termLine('[!] Connection lost','warn');
        setRunning(false);
        if(es)es.close();
      };
    }).catch(function(e){
      termLine('[x] '+e,'error');
      setRunning(false);
    });
  }

  // Source radio toggle
  document.querySelectorAll('input[name="a-src"]').forEach(function(r){
    r.addEventListener('change',function(){
      var manual=document.getElementById('a-urls-wrap');
      if(manual)manual.style.display=this.value==='manual'?'block':'none';
    });
  });

  document.getElementById('a-start-btn').addEventListener('click',startScan);

  // Pre-fill domain from last recon
  fetch('/api/history').then(function(r){return r.json();}).then(function(d){
    var last=d.find(function(e){return e.type==='recon'&&e.status==='completed';});
    if(last){
      var el=document.getElementById('a-domain');
      if(el&&!el.value)el.value=last.target||'';
      var hint=document.getElementById('a-recon-hint');
      if(hint)hint.textContent='Last recon: '+last.target+' ('+((last.scanned_urls||0)||'?')+' URLs available from '+new Date(last.date).toLocaleDateString()+')';
    }
  }).catch(function(){});
})();
"""


def _page_active_scan() -> str:
    content = (
        '<p class="page-title"><span class="acc">// </span>ACTIVE <span class="acc">SCAN</span></p>'

        '<div class="section">'
        '<div class="section-title"><span class="acc">// </span>Target</div>'
        '<div class="form-row" style="grid-template-columns:2fr 1fr;align-items:end">'
        '<div class="form-group">'
        '<label class="form-label">Domain</label>'
        '<input id="a-domain" class="form-input" type="text" placeholder="example.com" autocomplete="off">'
        '<p class="form-hint" id="a-recon-hint" style="color:var(--amber2)"></p>'
        '</div>'
        '<div class="form-group">'
        '<label class="form-label">URL Source</label>'
        '<div style="display:flex;flex-direction:column;gap:.4rem;margin-top:.2rem">'
        '<label style="display:flex;align-items:center;gap:.5rem;cursor:pointer">'
        '<input type="radio" name="a-src" value="auto" checked> Auto (from last recon)</label>'
        '<label style="display:flex;align-items:center;gap:.5rem;cursor:pointer">'
        '<input type="radio" name="a-src" value="manual"> Manual URL list</label>'
        '</div></div></div>'

        '<div id="a-urls-wrap" style="display:none;margin-top:.5rem">'
        '<label class="form-label">URLs (one per line)</label>'
        '<textarea id="a-urls-manual" class="form-input" rows="5" '
        'placeholder="https://example.com/api/users&#10;https://example.com/api/auth" '
        'style="font-size:12px;resize:vertical"></textarea>'
        '<p class="form-hint">Paste Wayback URLs, JS endpoints, or burp target URLs</p>'
        '</div>'
        '</div>'

        '<div class="section">'
        '<div class="section-title"><span class="acc">// </span>Scan Progress</div>'
        '<div class="terminal" id="aterm"><div class="t-line t-dim">// Ready. Set target and click Start.</div></div>'
        '<div class="btn-group mt-2">'
        '<button id="a-start-btn" class="btn btn-primary"><span id="a-spinner" class="spinner" style="display:none"></span> Start Active Scan</button>'
        '<button id="a-export-btn" class="btn" style="display:none">Export JSON</button>'
        '</div></div>'

        '<div id="active-results" style="display:none">'
        '<div class="result-cards" id="a-cards"></div>'
        '<div class="section">'
        '<div class="section-title"><span class="acc">// </span>Findings'
        '<span class="section-count" id="a-count"></span></div>'
        '<div class="table-wrap"><table>'
        '<thead><tr>'
        '<th style="width:90px">Severity</th>'
        '<th style="width:90px">Confidence</th>'
        '<th>Title</th>'
        '<th>URL</th>'
        '<th style="width:90px">Rule</th>'
        '</tr></thead>'
        '<tbody id="a-findings-tbody">'
        '<tr><td colspan="5" style="color:var(--dim);text-align:center">No results yet</td></tr>'
        '</tbody></table></div></div>'
        '</div>'

        '<script>' + _ACTIVE_JS + '</script>'
    )
    return _base("Active Scan", "active-scan", content)


# ── History ───────────────────────────────────────────────────────────────────

_HISTORY_JS = """
(function(){
  function fmtDate(iso){
    if(!iso)return'—';
    var d=new Date(iso);
    return d.toLocaleDateString()+' '+d.toLocaleTimeString().slice(0,5);
  }
  function esc(s){
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function openDetail(jobId,btn){
    var row=btn.closest('tr');
    // remove any existing detail rows
    var existing=document.querySelectorAll('.detail-tr');
    existing.forEach(function(r){
      if(r!==row._detail)r.remove();
    });
    if(row._detail&&document.contains(row._detail)){
      row._detail.remove();row._detail=null;
      btn.textContent='View';return;
    }
    btn.textContent='Loading...';
    fetch('/api/history/'+jobId).then(function(r){return r.json();}).then(function(d){
      btn.textContent='Close';
      var tr=document.createElement('tr');
      tr.className='detail-tr';
      var td=document.createElement('td');
      td.colSpan=6;
      var subs=d.subdomains||[];
      var alive=subs.filter(function(s){return s.alive;}).length;
      var tech=d.tech_fingerprint||{};
      var js=d.js_endpoints||{};
      var wb=d.wayback||{};
      td.innerHTML='<div class="detail-panel open"><strong>Domain:</strong> '+esc(d.meta&&d.meta.domain||'')+
        ' &nbsp; <strong>Duration:</strong> '+esc(d.meta&&d.meta.duration_seconds?d.meta.duration_seconds.toFixed(1)+'s':'—')+
        '<br><strong>Subdomains:</strong> '+subs.length+' ('+alive+' alive)'+
        ' &nbsp; <strong>JS Endpoints:</strong> '+(js.total_endpoints||0)+
        ' &nbsp; <strong>Wayback:</strong> '+(wb.total||0)+
        '<br><strong>Tech:</strong> '+esc((tech.technologies||[]).join(', ')||'none')+
        '<br><strong>Missing Headers:</strong> '+esc((tech.missing_security_headers||[]).join(', ')||'none')+
        '</div>';
      tr.appendChild(td);
      row._detail=tr;
      row.after(tr);
    }).catch(function(){btn.textContent='View';});
  }

  function renderHistory(data){
    var tbody=document.getElementById('hist-tbody');
    if(!data.length){
      tbody.innerHTML='<tr><td colspan="6" style="color:var(--dim);text-align:center;padding:1.5rem">No history yet</td></tr>';
      return;
    }
    tbody.innerHTML='';
    data.forEach(function(e){
      var st=e.status==='completed'?'<span class="badge badge-green">done</span>':'<span class="badge badge-yellow">'+esc(e.status||'')+'</span>';
      var subs=e.subdomains!=null?e.subdomains:'—';
      var wb=e.wayback_total!=null?e.wayback_total:'—';
      var techs=e.technologies&&e.technologies.length?e.technologies.slice(0,3).join(', '):'—';
      var tr=document.createElement('tr');
      tr.className='hist-row';
      tr.innerHTML='<td class="text-dim text-sm">'+fmtDate(e.date)+'</td>'
        +'<td class="td-amber">'+esc(e.target||'')+'</td>'
        +'<td><span class="badge badge-dim">'+esc(e.type||'recon')+'</span></td>'
        +'<td>'+subs+' subs / '+wb+' wb</td>'
        +'<td>'+esc(techs)+'</td>'
        +'<td>'+st+'</td>'
        +'<td><button class="btn btn-sm" data-jid="'+esc(e.id||'')+'">View</button></td>';
      tbody.appendChild(tr);
    });

    // Bind detail buttons
    tbody.querySelectorAll('button[data-jid]').forEach(function(btn){
      btn.addEventListener('click',function(){
        openDetail(this.dataset.jid,this);
      });
    });

    // Sort
    document.querySelectorAll('#hist-thead th[data-col]').forEach(function(th){
      th.addEventListener('click',function(){
        var col=this.dataset.col;
        var asc=this.dataset.asc!=='1';
        this.dataset.asc=asc?'1':'0';
        data.sort(function(a,b){
          var av=a[col]||'',bv=b[col]||'';
          return asc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
        });
        renderHistory(data);
      });
    });
  }

  // Search
  document.getElementById('hist-search').addEventListener('input',function(){
    var q=this.value.toLowerCase();
    document.querySelectorAll('#hist-tbody tr:not(.detail-tr)').forEach(function(tr){
      tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none';
    });
  });

  fetch('/api/history').then(function(r){return r.json();}).then(function(d){
    renderHistory(d);
  }).catch(function(){
    document.getElementById('hist-tbody').innerHTML='<tr><td colspan="7" style="color:var(--red)">Error loading history</td></tr>';
  });
})();
"""

def _page_history() -> str:
    content = (
        '<div class="flex-between mb-2">'
        '<p class="page-title" style="margin:0"><span class="acc">// </span>SCAN HISTORY</p>'
        '<div class="search-wrap">'
        '<span class="search-icon">🔍</span>'
        '<input id="hist-search" class="form-input" type="text" placeholder="Filter...">'
        '</div></div>'
        '<div class="table-wrap"><table>'
        '<thead id="hist-thead"><tr>'
        '<th data-col="date">Date ↕</th>'
        '<th data-col="target">Target ↕</th>'
        '<th>Type</th>'
        '<th>Findings</th>'
        '<th>Tech</th>'
        '<th>Status</th>'
        '<th></th>'
        '</tr></thead>'
        '<tbody id="hist-tbody">'
        '<tr><td colspan="7" style="color:var(--dim);text-align:center">Loading...</td></tr>'
        '</tbody></table></div>'
        '<script>' + _HISTORY_JS + '</script>'
    )
    return _base("History", "history", content)


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description="Whei Guard Web Dashboard")
    p.add_argument("--port", type=int, default=PORT, help=f"Port (default {PORT})")
    p.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    p.add_argument("--debug", action="store_true", help="Flask debug mode")
    args = p.parse_args()

    print(f"\033[38;5;214m")
    print(f"  ██╗    ██╗██╗  ██╗███████╗██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗")
    print(f"  ██║    ██║██║  ██║██╔════╝██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗")
    print(f"  ██║ █╗ ██║███████║█████╗  ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║")
    print(f"  ██║███╗██║██╔══██║██╔══╝  ██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║")
    print(f"  ╚███╔███╔╝██║  ██║███████╗██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝")
    print(f"   ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ \033[0m")
    print(f"\033[38;5;214m  Web Dashboard  //  Bug Bounty Platform\033[0m")
    print(f"\033[90m  ──────────────────────────────────────────\033[0m")
    print(f"\033[38;5;214m  URL:\033[0m    http://{args.host}:{args.port}")
    print(f"\033[90m  Config: {CONFIG_FILE}")
    print(f"  Logs:   {HISTORY_FILE}")
    print(f"  Press Ctrl+C to stop\033[0m\n")

    app.run(host=args.host, port=args.port, threaded=True, debug=args.debug)


if __name__ == "__main__":
    main()
