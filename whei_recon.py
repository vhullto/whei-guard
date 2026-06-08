#!/usr/bin/env python3
"""
whei_recon.py — Reconnaissance module for Whei Guard bug bounty platform.

Usage (standalone):
    from whei_recon import ReconRunner
    runner = ReconRunner("example.com")
    results = runner.run()
    runner.print_summary()
    path = runner.save_json()

Modules:
    SubdomainEnumerator  — crt.sh certificate transparency + HackerTarget + DNS resolution
    JSEndpointExtractor  — discover JS bundles and regex-extract API paths/endpoints
    TechFingerprinter    — detect tech stack from HTTP headers, cookies, HTML patterns
    WaybackFetcher       — pull archived URLs from Wayback Machine CDX API
    ReconRunner          — orchestrator: runs all modules, prints summary, saves JSON
"""

import json
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


_DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
ORANGE = "\033[38;5;214m"


def _c(text: str, color: str, use_color: bool = True) -> str:
    return f"{color}{text}{RESET}" if use_color else text


def _require_requests():
    if not REQUESTS_AVAILABLE:
        raise RuntimeError(
            "Package 'requests' is required for recon.\n"
            "Install with:  pip install requests\n"
            "          or:  pip install whei-guard[recon]"
        )


def _make_session(retries: int = 2) -> "requests.Session":
    session = requests.Session()
    session.headers.update({"User-Agent": _DEFAULT_UA})
    retry = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ═══════════════════════════════════════════════════════════════════════════════
#  SubdomainEnumerator
# ═══════════════════════════════════════════════════════════════════════════════

class SubdomainEnumerator:
    """
    Discovers subdomains via certificate transparency and passive DNS.

    Sources (all free, no API key required):
      crt.sh       — certificate transparency PostgreSQL JSON API
      HackerTarget — passive DNS hostsearch endpoint
    """

    def __init__(
        self,
        domain:           str,
        timeout:          int  = 20,
        max_workers:      int  = 60,
        use_crtsh:        bool = True,
        use_hackertarget: bool = True,
        resolve_dns:      bool = True,
        max_results:      int  = 500,
    ):
        _require_requests()
        self.domain           = domain.lower().strip()
        self.timeout          = timeout
        self.max_workers      = max_workers
        self.use_crtsh        = use_crtsh
        self.use_hackertarget = use_hackertarget
        self.resolve_dns      = resolve_dns
        self.max_results      = max_results
        self._session         = _make_session()

    # ── Sources ───────────────────────────────────────────────────────────────

    def _fetch_crtsh(self) -> set:
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            r = self._session.get(url, timeout=self.timeout)
            r.raise_for_status()
            certs = r.json()
        except Exception:
            return set()

        subs: set = set()
        for cert in certs:
            for name in cert.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{self.domain}") or name == self.domain:
                    subs.add(name)
        return subs

    def _fetch_hackertarget(self) -> set:
        url = f"https://api.hacktarget.com/hostsearch/?q={self.domain}"
        try:
            r = self._session.get(url, timeout=self.timeout)
            r.raise_for_status()
        except Exception:
            return set()

        subs: set = set()
        for line in r.text.splitlines():
            if "," in line:
                sub = line.split(",")[0].strip().lower()
                if sub.endswith(f".{self.domain}"):
                    subs.add(sub)
            elif line.strip().lower().endswith(f".{self.domain}"):
                subs.add(line.strip().lower())
        return subs

    # ── DNS resolution ────────────────────────────────────────────────────────

    def _resolve(self, subdomain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(subdomain)
        except (socket.gaierror, socket.herror, OSError):
            return None

    # ── Public API ────────────────────────────────────────────────────────────

    def enumerate(self) -> list:
        """
        Returns list of dicts: {subdomain, ip, alive}.
        Sorted: alive-first, then alphabetically.
        """
        all_subs: set = set()
        if self.use_crtsh:
            all_subs.update(self._fetch_crtsh())
        if self.use_hackertarget:
            all_subs.update(self._fetch_hackertarget())

        # Cap before DNS resolution
        sub_list = sorted(all_subs)[: self.max_results]

        if not self.resolve_dns:
            return [{"subdomain": s, "ip": None, "alive": False} for s in sub_list]

        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            future_map = {ex.submit(self._resolve, sub): sub for sub in sub_list}
            for future in as_completed(future_map):
                sub = future_map[future]
                ip  = future.result()
                results.append({"subdomain": sub, "ip": ip, "alive": ip is not None})

        return sorted(results, key=lambda x: (not x["alive"], x["subdomain"]))


# ═══════════════════════════════════════════════════════════════════════════════
#  JSEndpointExtractor
# ═══════════════════════════════════════════════════════════════════════════════

class JSEndpointExtractor:
    """
    Discovers JS files on a target and extracts API paths/endpoints via regex.

    Follows same-origin scripts and cross-origin CDN/asset scripts.
    Patterns: quoted paths, fetch/axios calls, object properties,
    route definitions, template literals.
    """

    _MAX_JS_SIZE = 5 * 1024 * 1024  # 5 MB per file

    # CDN/asset subdomains to follow cross-origin
    _CDN_RE = re.compile(
        r'^(?:cdn|assets|static|js|scripts|bundles|dist|media|files)\.',
        re.IGNORECASE,
    )

    # Quoted API-like paths
    _ENDPOINT_RE = re.compile(
        r'["\']'
        r'(/(?:api|v\d+|rest|graphql|auth|user[s]?|admin|public|private'
        r'|dashboard|search|upload|download|webhook|oauth|token|login|logout'
        r'|register|reset|verify|config|health|status|metrics|data|resource[s]?'
        r'|service[s]?|query|mutation|subscription|internal|external|partner)'
        r'[a-zA-Z0-9/_\-\.?\#=&%{}:]*)'
        r'["\']',
        re.IGNORECASE,
    )

    # fetch / axios / XHR / $ajax calls with literal path
    _FETCH_RE = re.compile(
        r'(?:fetch|axios\.(?:get|post|put|delete|patch|request)'
        r'|XMLHttpRequest\.open|http\.(?:get|post|put|delete|patch)'
        r'|\$\.(?:get|post|ajax)|request\.(?:get|post))'
        r'\s*\(\s*["\']'
        r'(/[a-zA-Z0-9/_\-\.?\#=&%{}:]+)'
        r'["\']',
        re.IGNORECASE,
    )

    # Object property assignments: url:"/api/...", endpoint:"/...", baseURL:"..."
    _PROP_RE = re.compile(
        r'(?:url|endpoint|path|href|action|to|baseURL|baseUrl)\s*[:=]\s*["\']'
        r'(/(?:api|v\d+|rest|graphql|auth|admin|data|service)'
        r'[a-zA-Z0-9/_\-\.?\#=&%{}:]*)'
        r'["\']',
        re.IGNORECASE,
    )

    # Router/route definitions: path:"/users/:id"
    _ROUTE_RE = re.compile(
        r'(?:path|route)\s*[:=]\s*["\']'
        r'(/[a-zA-Z0-9/_\-\.:?{}[\]*]+)'
        r'["\']',
        re.IGNORECASE,
    )

    # Template literal paths containing ${...} interpolation
    _TEMPLATE_RE = re.compile(
        r'`(/[a-zA-Z0-9/_\-\.]*\$\{[^`}]{1,60}\}[a-zA-Z0-9/_\-\.]*)`',
    )

    # <script src="..."> tags
    _SCRIPT_SRC_RE = re.compile(
        r'<script[^>]+\bsrc\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        re.IGNORECASE,
    )

    _SKIP_EXTS    = frozenset({".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                               ".ico", ".woff", ".woff2", ".ttf", ".eot",
                               ".mp4", ".mp3", ".pdf", ".map"})
    _SKIP_PREFIXES = frozenset({"/static/", "/images/", "/img/", "/fonts/",
                                "/assets/", "/media/", "/dist/", "/build/",
                                "/vendor/", "/node_modules/"})

    def __init__(self, base_url: str, timeout: int = 15,
                 max_workers: int = 10, max_js: int = 30):
        _require_requests()
        self.base_url     = base_url.rstrip("/")
        self.timeout      = timeout
        self.max_workers  = max_workers
        self.max_js       = max_js
        self._session     = _make_session()
        self._base_domain = self._parse_domain(base_url)

    @staticmethod
    def _parse_domain(url: str) -> str:
        from urllib.parse import urlparse
        try:
            return urlparse(url).netloc.lower()
        except Exception:
            return ""

    def _should_follow(self, url: str) -> bool:
        from urllib.parse import urlparse
        try:
            host = urlparse(url).netloc.lower()
        except Exception:
            return False
        if not host:
            return True  # relative URL
        if host == self._base_domain:
            return True
        if host.endswith("." + self._base_domain):
            return True
        if self._CDN_RE.match(host):
            return True
        # Same registrable domain (cdn.example.com when base is app.example.com)
        base_parts = self._base_domain.split(".")
        host_parts = host.split(".")
        if len(base_parts) >= 2 and base_parts[-2:] == host_parts[-2:]:
            return True
        return False

    def _discover_js_urls(self, html: str) -> list:
        urls: list = []
        seen: set  = set()
        for src in self._SCRIPT_SRC_RE.findall(html):
            src = src.strip()
            if not src:
                continue
            if src.startswith("//"):
                abs_url = "https:" + src
            elif src.startswith(("http://", "https://")):
                abs_url = src
            else:
                abs_url = urljoin(self.base_url, src)
            if abs_url not in seen and self._should_follow(abs_url):
                seen.add(abs_url)
                urls.append(abs_url)
        return urls[: self.max_js]

    def _extract_from_js(self, js: str) -> list:
        found: set = set()
        found.update(self._ENDPOINT_RE.findall(js))
        found.update(self._FETCH_RE.findall(js))
        found.update(self._PROP_RE.findall(js))
        found.update(self._ROUTE_RE.findall(js))
        found.update(self._TEMPLATE_RE.findall(js))
        return sorted(
            e for e in found
            if (len(e) >= 4
                and not any(e.endswith(ext) for ext in self._SKIP_EXTS)
                and not any(e.startswith(pfx) for pfx in self._SKIP_PREFIXES))
        )

    def _fetch_js(self, url: str) -> dict:
        try:
            r = self._session.get(url, timeout=self.timeout, stream=True)
            r.raise_for_status()
            # Bail early if content-length header says it's too large
            cl = r.headers.get("content-length", "")
            if cl.isdigit() and int(cl) > self._MAX_JS_SIZE:
                r.close()
                return {"url": url, "size_bytes": int(cl), "endpoints": [],
                        "endpoint_count": 0, "skipped": "too_large"}
            # Stream with size cap
            chunks: list = []
            total = 0
            for chunk in r.iter_content(chunk_size=65536):
                total += len(chunk)
                if total > self._MAX_JS_SIZE:
                    r.close()
                    return {"url": url, "size_bytes": total, "endpoints": [],
                            "endpoint_count": 0, "skipped": "too_large"}
                chunks.append(chunk)
            content   = b"".join(chunks).decode("utf-8", errors="ignore")
            endpoints = self._extract_from_js(content)
            return {"url": url, "size_bytes": total,
                    "endpoints": endpoints, "endpoint_count": len(endpoints)}
        except Exception as exc:
            return {"url": url, "size_bytes": 0, "endpoints": [],
                    "endpoint_count": 0, "error": str(exc)[:120]}

    def extract(self) -> dict:
        """
        Returns:
          { base_url, js_files: [{url, size_bytes, endpoints, endpoint_count}],
            endpoints, total_endpoints }
        """
        try:
            r    = self._session.get(self.base_url, timeout=self.timeout, allow_redirects=True)
            html = r.text
        except Exception as exc:
            return {
                "base_url":        self.base_url,
                "error":           str(exc),
                "js_files":        [],
                "endpoints":       [],
                "total_endpoints": 0,
            }

        js_urls       = self._discover_js_urls(html)
        all_endpoints: set = set()
        js_results    = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for result in ex.map(self._fetch_js, js_urls):
                js_results.append(result)
                all_endpoints.update(result.get("endpoints", []))

        endpoints = sorted(all_endpoints)
        return {
            "base_url":        self.base_url,
            "js_files":        js_results,
            "endpoints":       endpoints,
            "total_endpoints": len(endpoints),
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  TechFingerprinter
# ═══════════════════════════════════════════════════════════════════════════════

class TechFingerprinter:
    """
    Detects technology stack from HTTP headers, cookies, and HTML patterns.
    No external tools — pure HTTP + regex (Wappalyzer-inspired).
    """

    _SERVER_SIGS = {
        "nginx":         "Nginx",
        "apache":        "Apache",
        "microsoft-iis": "IIS",
        "openresty":     "OpenResty",
        "caddy":         "Caddy",
        "cloudflare":    "Cloudflare",
        "gunicorn":      "Gunicorn",
        "uvicorn":       "Uvicorn",
        "waitress":      "Waitress",
        "werkzeug":      "Flask/Werkzeug",
        "tornado":       "Tornado",
        "jetty":         "Jetty",
        "tomcat":        "Tomcat",
        "lighttpd":      "Lighttpd",
        "litespeed":     "LiteSpeed",
    }

    _COOKIE_SIGS = {
        "phpsessid":          "PHP",
        "jsessionid":         "Java/Tomcat",
        "laravel_session":    "Laravel",
        "django":             "Django",
        "express:sess":       "Express.js",
        "rack.session":       "Ruby/Rack",
        "asp.net_sessionid":  "ASP.NET",
        "awsalb":             "AWS ALB",
        "cf_clearance":       "Cloudflare",
        "__cfduid":           "Cloudflare",
        "wordpress_logged_in":"WordPress",
        "wp-settings":        "WordPress",
        "_rails":             "Ruby on Rails",
        "connect.sid":        "Express.js",
        "symfony":            "Symfony",
        "zend_session":       "Zend Framework",
    }

    # (header_name_lowercase, tech_or_None_for_raw_value)
    _INTERESTING_HEADERS = [
        ("x-powered-by",       None),
        ("x-generator",        None),
        ("x-drupal-cache",     "Drupal"),
        ("x-wp-total",         "WordPress"),
        ("x-shopify-stage",    "Shopify"),
        ("x-vercel-id",        "Vercel"),
        ("x-amzn-requestid",   "AWS"),
        ("x-envoy-upstream",   "Envoy/Istio"),
        ("x-kong-proxy-latency","Kong"),
        ("x-ratelimit-limit",  None),   # exposes rate limiting
    ]

    # (pattern, technology_name)
    _HTML_SIGS = [
        (r"/_next/static|__next",                 "Next.js"),
        (r"__nuxt|nuxt\.js",                       "Nuxt.js"),
        (r"\bgatsby\b",                            "Gatsby"),
        (r"\bsvelte\b",                            "Svelte"),
        (r'data-reactroot|react(?:dom)?\.(?:min\.)?js', "React"),
        (r'ng-version|angular(?:\.min)?\.js|ng-app', "Angular"),
        (r'vue(?:\.min)?\.js|v-bind:|v-model',    "Vue.js"),
        (r"ember(?:\.min)?\.js|ember-application", "Ember.js"),
        (r"backbone(?:\.min)?\.js",               "Backbone.js"),
        (r"wp-content/themes|wp-includes",        "WordPress"),
        (r"drupal\.settings|sites/default/files", "Drupal"),
        (r"\bjoomla\b",                           "Joomla"),
        (r"cdn\.shopify\.com|myshopify\.com",     "Shopify"),
        (r"squarespace\.com",                     "Squarespace"),
        (r"\bgraphql\b",                          "GraphQL"),
        (r"apollo-client",                        "Apollo GraphQL"),
        (r"bootstrap(?:\.min)?\.(?:js|css)",      "Bootstrap"),
        (r'tailwindcss|tailwind(?:\.min)?\.css',  "Tailwind CSS"),
        (r"jquery(?:\.min)?\.js",                 "jQuery"),
        (r"socket\.io(?:\.min)?\.js",             "Socket.IO"),
        (r'require(?:\.min)?\.js|data-main=',     "RequireJS"),
    ]

    _SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-xss-protection",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    def __init__(self, url: str, timeout: int = 15):
        _require_requests()
        self.url = url
        self.timeout = timeout
        self._session = _make_session()

    def fingerprint(self) -> dict:
        try:
            r = self._session.get(self.url, timeout=self.timeout, allow_redirects=True)
        except Exception as exc:
            return {
                "url": self.url,
                "error": str(exc),
                "technologies": [],
                "missing_security_headers": [],
                "headers": {},
            }

        detected: set = set()
        headers_lower = {k.lower(): v for k, v in r.headers.items()}

        # Web server
        server_val = headers_lower.get("server", "").lower()
        for sig, tech in self._SERVER_SIGS.items():
            if sig in server_val:
                detected.add(tech)

        # Interesting response headers
        for header, tech in self._INTERESTING_HEADERS:
            val = headers_lower.get(header)
            if val:
                detected.add(tech if tech else f"{header}: {val}")

        # Cookies
        for cookie_name in r.cookies.keys():
            for sig, tech in self._COOKIE_SIGS.items():
                if sig in cookie_name.lower():
                    detected.add(tech)

        # HTML/JS patterns
        html_lower = r.text.lower()
        for pattern, tech in self._HTML_SIGS:
            if re.search(pattern, html_lower):
                detected.add(tech)

        # <meta name="generator" content="...">
        meta_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            r.text, re.IGNORECASE,
        )
        if meta_match:
            detected.add(f"generator:{meta_match.group(1).strip()}")

        # Missing security headers
        present_lower = set(headers_lower.keys())
        missing_sec = [h for h in self._SECURITY_HEADERS if h not in present_lower]

        return {
            "url": self.url,
            "final_url": str(r.url),
            "status_code": r.status_code,
            "technologies": sorted(t for t in detected if t),
            "missing_security_headers": missing_sec,
            "headers": dict(r.headers),
            "redirect_chain": [str(resp.url) for resp in r.history],
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  WaybackFetcher
# ═══════════════════════════════════════════════════════════════════════════════

class WaybackFetcher:
    """
    Fetches archived URLs from the Wayback Machine CDX API.

    Categorizes results into: api, admin, params, json, sensitive.
    Free, no key required.
    """

    _CDX = "http://web.archive.org/cdx/search/cdx"

    _SENSITIVE_PATTERNS = [
        ".bak", ".sql", ".env", ".git/", ".svn/", ".htaccess", ".htpasswd",
        "backup", "/config", "passwd", "/debug", "/test", "staging",
        ".zip", ".tar.gz", ".tar.bz", ".db", "dump", "/export",
        "secret", "private", "credentials", ".pem", ".key", ".crt",
    ]

    def __init__(self, domain: str, limit: int = 5000, timeout: int = 45):
        _require_requests()
        self.domain = domain
        self.limit = limit
        self.timeout = timeout
        self._session = _make_session(retries=1)

    def fetch(self) -> dict:
        params = {
            "url":      f"*.{self.domain}/*",
            "output":   "json",
            "collapse": "urlkey",
            "fl":       "original,statuscode,timestamp,mimetype",
            "limit":    self.limit,
        }
        try:
            r = self._session.get(self._CDX, params=params, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as exc:
            return {
                "domain":     self.domain,
                "error":      str(exc),
                "urls":       [],
                "total":      0,
                "categories": {},
                "summary":    {},
            }

        if len(data) < 2:
            return {
                "domain": self.domain,
                "urls": [], "total": 0, "categories": {}, "summary": {},
            }

        headers_row = data[0]
        rows        = data[1:]
        urls        = [dict(zip(headers_row, row)) for row in rows]

        categories = {
            "api": [
                u for u in urls
                if re.search(r"/api/|/v\d+/|/graphql", u.get("original", ""), re.I)
            ],
            "admin": [
                u for u in urls
                if re.search(r"/admin|/dashboard|/panel|/manage|/cp/|/control", u.get("original", ""), re.I)
            ],
            "params": [u for u in urls if "?" in u.get("original", "")],
            "json":   [u for u in urls if ".json" in u.get("original", "")],
            "sensitive": [
                u for u in urls
                if any(p in u.get("original", "").lower() for p in self._SENSITIVE_PATTERNS)
            ],
        }

        return {
            "domain":     self.domain,
            "total":      len(urls),
            "urls":       urls[:1000],
            "categories": {k: v[:200] for k, v in categories.items()},
            "summary":    {k: len(v)  for k, v in categories.items()},
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  ReconRunner — orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class ReconRunner:
    """
    Orchestrates all recon modules for a target domain.

    Usage:
        runner = ReconRunner("example.com")
        results = runner.run()
        runner.print_summary()
        json_path = runner.save_json()
    """

    def __init__(
        self,
        domain:     str,
        base_url:   str  = None,
        output_dir: str  = ".",
        verbose:    bool = True,
        use_color:  bool = True,
        config:     dict = None,
    ):
        self.domain     = domain.lower().strip()
        self.base_url   = (base_url or f"https://{domain}").rstrip("/")
        self.output_dir = output_dir
        self.verbose    = verbose
        self.use_color  = use_color
        self.results: dict = {}

        # Parse recon config
        rcfg    = (config or {}).get("recon", {})
        modules = rcfg.get("modules", {})
        limits  = rcfg.get("limits", {})
        sources = rcfg.get("subdomain_sources", {})

        self._mod_subdomains = modules.get("subdomains",       True)
        self._mod_tech       = modules.get("tech_fingerprint", True)
        self._mod_js         = modules.get("js_endpoints",     True)
        self._mod_wayback    = modules.get("wayback",          True)
        self._mod_dns        = modules.get("dns_resolve",      True)

        self._src_crtsh  = sources.get("crtsh",       True)
        self._src_ht     = sources.get("hackertarget", True)

        self._max_subs      = int(limits.get("max_subs",      500))
        self._wayback_limit = int(limits.get("wayback_limit", 5000))
        self._max_js        = int(limits.get("max_js",        30))
        self._timeout       = int(limits.get("timeout",       15))
        self._dns_threads   = int(limits.get("dns_threads",   60))

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    def run(self) -> dict:
        start = datetime.now()
        results: dict = {
            "meta": {
                "domain":     self.domain,
                "base_url":   self.base_url,
                "started_at": start.isoformat(),
                "tool":       "whei-guard recon v2.0",
            }
        }
        uc = self.use_color

        # ── 1. Subdomain enumeration ──────────────────────────────────────────
        if self._mod_subdomains:
            self._log(
                f"\n  {_c('[~]', DIM, uc)} Enumerating subdomains for "
                f"{_c(self.domain, CYAN, uc)}..."
            )
            try:
                subdomains = SubdomainEnumerator(
                    self.domain,
                    timeout=self._timeout,
                    max_workers=self._dns_threads,
                    use_crtsh=self._src_crtsh,
                    use_hackertarget=self._src_ht,
                    resolve_dns=self._mod_dns,
                    max_results=self._max_subs,
                ).enumerate()
            except Exception as exc:
                subdomains = []
                self._log(f"  {_c('[!]', YELLOW, uc)} Subdomain enum failed: {exc}")
        else:
            subdomains = []
            self._log(f"\n  {_c('[~]', DIM, uc)} Subdomain enumeration disabled")

        results["subdomains"] = subdomains
        alive_n = sum(1 for s in subdomains if s.get("alive"))
        if self._mod_subdomains:
            self._log(
                f"  {_c('[✓]', GREEN, uc)} "
                f"{_c(str(len(subdomains)), BOLD, uc)} subdomains found, "
                f"{_c(str(alive_n), ORANGE, uc)} alive"
            )

        # ── 2. Tech fingerprinting ────────────────────────────────────────────
        if self._mod_tech:
            self._log(
                f"\n  {_c('[~]', DIM, uc)} Fingerprinting "
                f"{_c(self.base_url, CYAN, uc)}..."
            )
            try:
                tech = TechFingerprinter(self.base_url, timeout=self._timeout).fingerprint()
            except Exception as exc:
                tech = {"error": str(exc), "technologies": [], "missing_security_headers": [], "headers": {}}
                self._log(f"  {_c('[!]', YELLOW, uc)} Fingerprint failed: {exc}")
        else:
            tech = {"technologies": [], "missing_security_headers": []}
            self._log(f"\n  {_c('[~]', DIM, uc)} Tech fingerprinting disabled")

        results["tech_fingerprint"] = tech
        techs       = tech.get("technologies", [])
        missing_sec = tech.get("missing_security_headers", [])
        if self._mod_tech:
            self._log(
                f"  {_c('[✓]', GREEN, uc)} "
                f"Tech: {_c(', '.join(techs[:6]) if techs else 'none detected', CYAN, uc)}"
            )
            if missing_sec:
                self._log(
                    f"  {_c('[!]', YELLOW, uc)} "
                    f"Missing security headers: {', '.join(missing_sec)}"
                )

        # ── 3. JS endpoint extraction ─────────────────────────────────────────
        if self._mod_js:
            self._log(f"\n  {_c('[~]', DIM, uc)} Extracting endpoints from JS files...")
            try:
                js_data = JSEndpointExtractor(
                    self.base_url,
                    timeout=self._timeout,
                    max_js=self._max_js,
                ).extract()
            except Exception as exc:
                js_data = {"error": str(exc), "js_files": [], "endpoints": [], "total_endpoints": 0}
                self._log(f"  {_c('[!]', YELLOW, uc)} JS extraction failed: {exc}")
        else:
            js_data = {"js_files": [], "endpoints": [], "total_endpoints": 0}
            self._log(f"\n  {_c('[~]', DIM, uc)} JS endpoint extraction disabled")

        results["js_endpoints"] = js_data
        if self._mod_js:
            self._log(
                f"  {_c('[✓]', GREEN, uc)} "
                f"{_c(str(js_data.get('total_endpoints', 0)), BOLD, uc)} endpoints "
                f"from {len(js_data.get('js_files', []))} JS files"
            )

        # ── 4. Wayback Machine ────────────────────────────────────────────────
        if self._mod_wayback:
            self._log(f"\n  {_c('[~]', DIM, uc)} Fetching Wayback Machine URLs...")
            try:
                wb_data = WaybackFetcher(
                    self.domain,
                    limit=self._wayback_limit,
                    timeout=max(self._timeout * 3, 45),
                ).fetch()
            except Exception as exc:
                wb_data = {"error": str(exc), "total": 0, "urls": [], "categories": {}, "summary": {}}
                self._log(f"  {_c('[!]', YELLOW, uc)} Wayback fetch failed: {exc}")
        else:
            wb_data = {"total": 0, "urls": [], "categories": {}, "summary": {}}
            self._log(f"\n  {_c('[~]', DIM, uc)} Wayback Machine disabled")

        results["wayback"] = wb_data
        wb_summary = wb_data.get("summary", {})
        self._log(
            f"  {_c('[✓]', GREEN, uc)} "
            f"{_c(str(wb_data.get('total', 0)), BOLD, uc)} archived URLs "
            f"— api:{wb_summary.get('api', 0)} "
            f"admin:{wb_summary.get('admin', 0)} "
            f"sensitive:{_c(str(wb_summary.get('sensitive', 0)), RED if wb_summary.get('sensitive') else GRAY, uc)}"
        )

        # ── Finalize ──────────────────────────────────────────────────────────
        end = datetime.now()
        results["meta"]["completed_at"]     = end.isoformat()
        results["meta"]["duration_seconds"] = (end - start).total_seconds()
        self.results = results
        return results

    def print_summary(self):
        if not self.results:
            self._log("  [!] No results. Run .run() first.")
            return

        uc   = self.use_color
        sep  = "─" * 70
        meta = self.results.get("meta", {})
        subs = self.results.get("subdomains", [])
        tech = self.results.get("tech_fingerprint", {})
        js   = self.results.get("js_endpoints", {})
        wb   = self.results.get("wayback", {})

        print(f"\n{_c(sep, ORANGE, uc)}")
        print(f"{_c('  ✦ RECON SUMMARY', ORANGE + BOLD, uc)}\n")
        print(f"  {_c('Domain:',        BOLD, uc)}        {_c(meta.get('domain', ''), CYAN, uc)}")
        print(f"  {_c('Duration:',      BOLD, uc)}        {meta.get('duration_seconds', 0):.1f}s")
        alive_n = sum(1 for s in subs if s.get("alive"))
        print(f"  {_c('Subdomains:',    BOLD, uc)}        {len(subs)} found, {_c(str(alive_n), ORANGE, uc)} alive")
        techs = tech.get("technologies", [])
        print(f"  {_c('Tech Stack:',    BOLD, uc)}        {', '.join(techs[:6]) or 'none detected'}")
        print(f"  {_c('JS Endpoints:',  BOLD, uc)}        {js.get('total_endpoints', 0)}")
        print(f"  {_c('Wayback URLs:',  BOLD, uc)}        {wb.get('total', 0)}")

        wb_summary = wb.get("summary", {})
        if any(wb_summary.values()):
            print(f"\n  {_c('Wayback breakdown:', BOLD, uc)}")
            for k, v in wb_summary.items():
                if v:
                    col = RED if k == "sensitive" else CYAN
                    print(f"    {_c(f'{k:<12}', DIM, uc)} {_c(str(v), col, uc)}")

        missing_sec = tech.get("missing_security_headers", [])
        if missing_sec:
            print(f"\n  {_c('Missing Security Headers:', BOLD, uc)}")
            for h in missing_sec:
                print(f"    {_c('!', YELLOW, uc)} {h}")

        alive_subs = [s for s in subs if s.get("alive")][:10]
        if alive_subs:
            print(f"\n  {_c('Live Subdomains (top 10):', BOLD, uc)}")
            for s in alive_subs:
                print(f"    {_c(s['subdomain'], CYAN, uc)}  {_c(s.get('ip', ''), DIM, uc)}")

        endpoints = js.get("endpoints", [])[:15]
        if endpoints:
            print(f"\n  {_c('JS Endpoints (top 15):', BOLD, uc)}")
            for ep in endpoints:
                print(f"    {_c(ep, GREEN, uc)}")

        sensitive = wb.get("categories", {}).get("sensitive", [])[:5]
        if sensitive:
            print(f"\n  {_c('Sensitive Wayback URLs (top 5):', BOLD, uc)}")
            for u in sensitive:
                print(f"    {_c(u.get('original', ''), RED, uc)}")

        print(f"\n{_c(sep, ORANGE, uc)}\n")

    def save_json(self, path: str = None) -> str:
        if not self.results:
            raise RuntimeError("No results to save. Run .run() first.")

        if path is None:
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(self.output_dir, f"recon_{self.domain}_{ts}.json")

        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)

        return path
