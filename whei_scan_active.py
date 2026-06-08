#!/usr/bin/env python3
"""
whei_scan_active.py — Active HTTP Security Scanner for Whei Guard.

Scanners:
    CORSChecker           — CORS misconfiguration detection
    OpenRedirectDetector  — Open redirect via parameter injection
    HeaderInjectionTester — Host header + CRLF injection
    SecurityHeaderAuditor — Response header misconfiguration audit
    ParameterFuzzer       — XSS, SQLi, SSTI, path traversal reflection
    ActiveScanRunner      — Orchestrator with rate limiting + progress callbacks
"""

import json
import random
import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


_VERSION = "1.0"

_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

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
        raise RuntimeError("Package 'requests' is required. Run: pip install requests")


# ═══════════════════════════════════════════════════════════════════════════════
#  Token bucket rate limiter
# ═══════════════════════════════════════════════════════════════════════════════

class _TokenBucket:
    def __init__(self, rate: float):
        self.rate    = max(0.1, float(rate))
        self._tokens = self.rate
        self._last   = time.monotonic()
        self._lock   = threading.Lock()

    def wait(self):
        with self._lock:
            now            = time.monotonic()
            self._tokens   = min(self.rate, self._tokens + (now - self._last) * self.rate)
            self._last     = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            deficit = 1.0 - self._tokens
            self._tokens = 0.0
        time.sleep(deficit / self.rate)


# ═══════════════════════════════════════════════════════════════════════════════
#  Session factory
# ═══════════════════════════════════════════════════════════════════════════════

def _make_session() -> "requests.Session":
    s  = requests.Session()
    ua = random.choice(_USER_AGENTS)
    s.headers.update({
        "User-Agent":      ua,
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    })
    retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[500, 502, 503],
                  allowed_methods=["GET", "HEAD", "POST"])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


# ═══════════════════════════════════════════════════════════════════════════════
#  Normalized finding builder
# ═══════════════════════════════════════════════════════════════════════════════

def _finding(
    titulo:    str,
    sev:       str,
    confianca: str,
    descricao: str,
    url:       str,
    trecho:    str = "",
    regra:     str = "",
    request:   str = "",
    response:  str = "",
    elementos: list = None,
) -> dict:
    return {
        "titulo":     titulo,
        "severidade": sev,
        "confianca":  confianca,
        "descricao":  descricao,
        "elementos":  elementos or [url],
        "trecho":     trecho,
        "regra":      regra,
        "source":     "active",
        "url":        url,
        "request":    request,
        "response":   response,
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  CORSChecker
# ═══════════════════════════════════════════════════════════════════════════════

class CORSChecker:
    """Tests CORS misconfigurations: wildcard, null origin, arbitrary reflection."""

    def __init__(self, timeout: int = 15, bucket: "_TokenBucket" = None):
        _require_requests()
        self.timeout = timeout
        self.bucket  = bucket or _TokenBucket(2.0)
        self._sess   = _make_session()

    def _test_url(self, url: str, target_domain: str) -> list:
        findings = []
        parsed   = urlparse(url)
        sub_origin = f"https://notevil.{target_domain}"

        test_origins = [
            "https://evil.com",
            "null",
            sub_origin,
            f"{parsed.scheme}://{parsed.netloc}.evil.com",
        ]

        for origin in test_origins:
            self.bucket.wait()
            try:
                r = self._sess.get(
                    url, headers={"Origin": origin},
                    timeout=self.timeout, verify=False, allow_redirects=False,
                )
            except Exception:
                continue

            acao = r.headers.get("Access-Control-Allow-Origin", "").strip()
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower().strip()
            if not acao:
                continue

            is_wildcard      = (acao == "*")
            origin_reflected = (acao == origin)
            has_creds        = (acac == "true")

            if is_wildcard and has_creds:
                findings.append(_finding(
                    titulo    = "CORS: Wildcard with Credentials Allowed",
                    sev       = "High",
                    confianca = "Confirmed",
                    descricao = (
                        "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. "
                        "While browsers enforce the spec, some frameworks or older clients may not. "
                        "This allows any origin to make credentialed requests."
                    ),
                    url      = url, trecho = f"ACAO: {acao}  ACAC: {acac}",
                    regra    = "CORS-001",
                    request  = f"GET {url}\nOrigin: {origin}",
                    response = f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                ))
                break

            elif origin_reflected and has_creds:
                sev = "High" if origin in ("https://evil.com", "null") else "Medium"
                findings.append(_finding(
                    titulo    = f"CORS: Reflected Origin + Credentials ({origin})",
                    sev       = sev,
                    confianca = "Confirmed",
                    descricao = (
                        f"Server reflects Origin: '{origin}' and allows credentials. "
                        "An attacker controlling that origin can make authenticated API requests "
                        "on behalf of logged-in users, leading to account takeover."
                    ),
                    url      = url, trecho = f"Origin: {origin}  →  ACAO: {acao}  ACAC: {acac}",
                    regra    = "CORS-002",
                    request  = f"GET {url}\nOrigin: {origin}",
                    response = f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                ))
                break

            elif origin_reflected and origin in ("https://evil.com", "null"):
                findings.append(_finding(
                    titulo    = "CORS: Arbitrary Origin Reflected (no credentials)",
                    sev       = "Low",
                    confianca = "Confirmed",
                    descricao = (
                        f"Origin '{origin}' reflected in Access-Control-Allow-Origin without credentials. "
                        "Lower severity, but confirms overly permissive CORS configuration."
                    ),
                    url      = url, trecho = f"Origin: {origin}  →  ACAO: {acao}",
                    regra    = "CORS-003",
                    request  = f"GET {url}\nOrigin: {origin}",
                    response = f"Access-Control-Allow-Origin: {acao}",
                ))
                break

        return findings

    def check(self, urls: list, target_domain: str) -> list:
        seen: set = set()
        deduped   = []
        for u in urls:
            p   = urlparse(u)
            sig = f"{p.netloc}{p.path}"
            if sig not in seen:
                seen.add(sig)
                deduped.append(u)

        all_findings: list = []
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(self._test_url, u, target_domain): u for u in deduped[:100]}
            for f in as_completed(futures):
                try:
                    all_findings.extend(f.result())
                except Exception:
                    pass
        return all_findings


# ═══════════════════════════════════════════════════════════════════════════════
#  OpenRedirectDetector
# ═══════════════════════════════════════════════════════════════════════════════

class OpenRedirectDetector:
    """Tests URL parameters for open redirect vulnerabilities."""

    _REDIRECT_PARAMS = [
        "url", "redirect", "next", "return", "returnUrl", "returnurl",
        "goto", "destination", "redir", "redirect_uri", "continue",
        "target", "link", "out", "ref", "forward", "back",
        "successUrl", "failureUrl", "callback", "u", "r",
    ]

    _PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://evil.com%23",
        "/%0d%0aLocation:%20https://evil.com",
    ]

    _ATTACKER = "evil.com"

    _META_RE = re.compile(
        r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\']+)["\']',
        re.IGNORECASE,
    )
    _JS_REDIR_RE = re.compile(
        r'(?:window\.location|location\.href|location\.replace)\s*[=\(]\s*["\']([^"\']*evil\.com[^"\']*)["\']',
        re.IGNORECASE,
    )

    def __init__(self, timeout: int = 10, bucket: "_TokenBucket" = None):
        _require_requests()
        self.timeout = timeout
        self.bucket  = bucket or _TokenBucket(2.0)
        self._sess   = _make_session()

    def _test_url(self, url: str) -> list:
        parsed    = urlparse(url)
        existing  = parse_qs(parsed.query, keep_blank_values=True)
        all_params = list(existing.keys()) + [
            p for p in self._REDIRECT_PARAMS if p not in existing
        ]

        for param in all_params[:12]:
            for payload in self._PAYLOADS:
                self.bucket.wait()
                test_params = dict(existing)
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(
                    query=urlencode({k: v[0] for k, v in test_params.items()})
                ))
                try:
                    r = self._sess.get(
                        test_url, timeout=self.timeout,
                        allow_redirects=False, verify=False,
                    )
                except Exception:
                    continue

                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if self._ATTACKER in loc or loc.startswith("//evil"):
                        return [_finding(
                            titulo    = "Open Redirect via URL Parameter",
                            sev       = "Medium",
                            confianca = "Confirmed",
                            descricao = (
                                f"Parameter '{param}' causes a {r.status_code} redirect "
                                f"to an attacker-controlled domain. Payload: {payload!r}. "
                                "Can be exploited for phishing and OAuth token theft."
                            ),
                            url      = url,
                            trecho   = f"?{param}={payload}  →  {r.status_code} Location: {loc}",
                            regra    = "REDIR-001",
                            request  = f"GET {test_url}",
                            response = f"HTTP {r.status_code}\nLocation: {loc}",
                        )]

                body = r.text[:8192]
                if self._ATTACKER in payload and (self._META_RE.search(body) or self._JS_REDIR_RE.search(body)):
                    return [_finding(
                        titulo    = "Open Redirect (Client-Side)",
                        sev       = "Medium",
                        confianca = "Likely",
                        descricao = (
                            f"Parameter '{param}' with payload {payload!r} triggers "
                            "a meta-refresh or JS location redirect to evil.com."
                        ),
                        url      = url,
                        trecho   = f"?{param}={payload}  →  client-side redirect detected",
                        regra    = "REDIR-002",
                        request  = f"GET {test_url}",
                        response = f"HTTP {r.status_code} [body redirect]",
                    )]

        return []

    def detect(self, urls: list) -> list:
        candidates = [
            u for u in urls
            if "?" in u or any(p in u.lower() for p in ["redirect", "return", "next", "goto", "url="])
        ][:80]

        all_findings: list = []
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(self._test_url, u): u for u in candidates}
            for f in as_completed(futures):
                try:
                    all_findings.extend(f.result())
                except Exception:
                    pass
        return all_findings


# ═══════════════════════════════════════════════════════════════════════════════
#  HeaderInjectionTester
# ═══════════════════════════════════════════════════════════════════════════════

class HeaderInjectionTester:
    """Tests Host header injection and CRLF injection vulnerabilities."""

    _CRLF_PAYLOADS = [
        "%0d%0aInjected-Header: whei-crlf-test",
        "%0aInjected-Header: whei-crlf-test",
        "evil.com%0d%0aInjected-Header: whei-crlf-test",
        "%0d%0a%20Injected-Header: whei-crlf-test",
    ]
    _HOST_PAYLOADS = ["evil.com", "evil.com:443"]
    _MARKER        = "whei-crlf-test"

    def __init__(self, timeout: int = 10, bucket: "_TokenBucket" = None):
        _require_requests()
        self.timeout = timeout
        self.bucket  = bucket or _TokenBucket(2.0)
        self._sess   = _make_session()

    def _test_host(self, url: str) -> list:
        parsed = urlparse(url)
        for payload in self._HOST_PAYLOADS:
            self.bucket.wait()
            try:
                r = self._sess.get(
                    url, headers={"Host": payload, "X-Forwarded-Host": payload},
                    timeout=self.timeout, verify=False, allow_redirects=False,
                )
            except Exception:
                continue
            loc  = r.headers.get("Location", "")
            body = r.text[:4096]
            host = payload.split(":")[0]
            if host in loc or host in body:
                return [_finding(
                    titulo    = "Host Header Injection",
                    sev       = "Medium",
                    confianca = "Confirmed",
                    descricao = (
                        f"Injected Host header '{payload}' is reflected in the response. "
                        "Exploitable for password reset poisoning, cache poisoning, or SSRF."
                    ),
                    url      = url,
                    trecho   = f"Host: {payload}  →  reflected in Location or body",
                    regra    = "HINJ-001",
                    request  = f"GET {url}\nHost: {payload}\nX-Forwarded-Host: {payload}",
                    response = f"HTTP {r.status_code}\nLocation: {loc}" if loc else f"HTTP {r.status_code}",
                )]
        return []

    def _test_crlf(self, url: str) -> list:
        parsed = urlparse(url)
        for payload in self._CRLF_PAYLOADS:
            self.bucket.wait()
            crlf_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{payload}"
            try:
                r = self._sess.get(
                    crlf_url, timeout=self.timeout,
                    verify=False, allow_redirects=False,
                )
            except Exception:
                continue
            resp_hdrs = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            if self._MARKER in resp_hdrs:
                return [_finding(
                    titulo    = "CRLF Injection in URL Path",
                    sev       = "High",
                    confianca = "Confirmed",
                    descricao = (
                        "CRLF characters in the URL path are reflected into HTTP response headers. "
                        "Allows injecting arbitrary headers: Set-Cookie XSS, cache poisoning, "
                        "HTTP response splitting."
                    ),
                    url      = url,
                    trecho   = f"Payload: {payload}  →  injected header found in response",
                    regra    = "CRLF-001",
                    request  = f"GET {crlf_url}",
                    response = f"HTTP {r.status_code} [injected header confirmed]",
                )]
        return []

    def test(self, urls: list) -> list:
        all_findings: list = []
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = []
            for u in urls[:50]:
                futures.append(ex.submit(self._test_host, u))
                futures.append(ex.submit(self._test_crlf, u))
            for f in as_completed(futures):
                try:
                    all_findings.extend(f.result())
                except Exception:
                    pass
        return all_findings


# ═══════════════════════════════════════════════════════════════════════════════
#  SecurityHeaderAuditor
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityHeaderAuditor:
    """Audits HTTP response headers for security misconfigurations."""

    _REQUIRED: dict = {
        "strict-transport-security": ("HSTS not set — susceptible to SSL stripping", "Medium"),
        "content-security-policy":   ("No CSP — XSS mitigation absent",              "Medium"),
        "x-frame-options":           ("No X-Frame-Options — clickjacking risk",       "Low"),
        "x-content-type-options":    ("No X-Content-Type-Options — MIME sniffing",    "Low"),
        "referrer-policy":           ("No Referrer-Policy — URLs may leak via Referer","Low"),
        "permissions-policy":        ("No Permissions-Policy — features unrestricted", "Low"),
    }

    _INFO_HDRS = [
        "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "x-generator", "x-backend", "x-real-ip", "x-varnish",
    ]

    def __init__(self, timeout: int = 15, bucket: "_TokenBucket" = None):
        _require_requests()
        self.timeout = timeout
        self.bucket  = bucket or _TokenBucket(2.0)
        self._sess   = _make_session()

    def _audit(self, url: str, r: "requests.Response") -> list:
        findings  = []
        hl        = {k.lower(): v for k, v in r.headers.items()}

        # Missing required headers
        for hdr, (desc, sev) in self._REQUIRED.items():
            if hdr not in hl:
                findings.append(_finding(
                    titulo    = f"Missing Security Header: {hdr}",
                    sev       = sev,
                    confianca = "Confirmed",
                    descricao = desc,
                    url       = url, trecho = f"{hdr}: [absent]", regra = "SECHDR-001",
                ))

        # Weak CSP
        csp = hl.get("content-security-policy", "")
        if csp:
            for directive, rule, msg in [
                ("unsafe-inline", "CSP-001", "unsafe-inline negates inline script protection"),
                ("unsafe-eval",   "CSP-002", "unsafe-eval allows eval() — exploitable for XSS"),
            ]:
                if directive in csp:
                    findings.append(_finding(
                        titulo    = f"Weak CSP: '{directive}' present",
                        sev       = "Medium", confianca = "Confirmed",
                        descricao = msg, url = url,
                        trecho = f"Content-Security-Policy: {csp[:200]}", regra = rule,
                    ))
            if "default-src" not in csp and "script-src" not in csp:
                findings.append(_finding(
                    titulo    = "Weak CSP: No default-src or script-src",
                    sev       = "Low", confianca = "Confirmed",
                    descricao = "CSP has no script-src or default-src, scripts may load from any origin.",
                    url = url, trecho = f"CSP: {csp[:200]}", regra = "CSP-003",
                ))

        # HSTS audit
        hsts = hl.get("strict-transport-security", "")
        if hsts:
            m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if m and int(m.group(1)) < 15552000:
                findings.append(_finding(
                    titulo    = "HSTS: Insufficient max-age",
                    sev       = "Low", confianca = "Confirmed",
                    descricao = f"HSTS max-age={m.group(1)} < 6 months. Recommended: ≥31536000.",
                    url = url, trecho = f"Strict-Transport-Security: {hsts}", regra = "HSTS-001",
                ))
            if "includesubdomains" not in hsts.lower():
                findings.append(_finding(
                    titulo    = "HSTS: Missing includeSubDomains",
                    sev       = "Low", confianca = "Confirmed",
                    descricao = "HSTS does not cover subdomains — SSL stripping possible on them.",
                    url = url, trecho = f"Strict-Transport-Security: {hsts}", regra = "HSTS-002",
                ))

        # Server version disclosure
        server = hl.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(_finding(
                titulo    = "Information Disclosure: Server Version",
                sev       = "Low", confianca = "Confirmed",
                descricao = f"Server header '{server}' discloses version — aids targeted exploits.",
                url = url, trecho = f"Server: {server}", regra = "INFO-001",
            ))

        for hdr in self._INFO_HDRS:
            val = hl.get(hdr, "")
            if val:
                findings.append(_finding(
                    titulo    = f"Information Disclosure: {hdr}",
                    sev       = "Low", confianca = "Confirmed",
                    descricao = f"Header '{hdr}: {val}' discloses technology stack.",
                    url = url, trecho = f"{hdr}: {val}", regra = "INFO-002",
                ))

        # Cookie flags (parse Set-Cookie header string)
        sc_raw = r.headers.get("set-cookie", "")
        if sc_raw:
            sc_lower = sc_raw.lower()
            name     = sc_raw.split("=")[0].strip()
            if "secure" not in sc_lower:
                findings.append(_finding(
                    titulo    = f"Cookie Missing Secure Flag: {name!r}",
                    sev       = "Medium", confianca = "Confirmed",
                    descricao = f"Cookie '{name}' lacks Secure — transmitted over HTTP.",
                    url = url, trecho = f"Set-Cookie: {sc_raw[:120]}", regra = "COOKIE-001",
                ))
            if "httponly" not in sc_lower and any(
                kw in name.lower() for kw in ["sess", "token", "auth", "sid", "jwt"]
            ):
                findings.append(_finding(
                    titulo    = f"Session Cookie Missing HttpOnly: {name!r}",
                    sev       = "Medium", confianca = "Confirmed",
                    descricao = f"Cookie '{name}' lacks HttpOnly — accessible via XSS.",
                    url = url, trecho = f"Set-Cookie: {sc_raw[:120]}", regra = "COOKIE-002",
                ))

        return findings

    def audit(self, urls: list) -> list:
        all_findings: list = []
        seen_hosts:   set  = set()
        for url in urls[:30]:
            host = urlparse(url).netloc
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            self.bucket.wait()
            try:
                r = self._sess.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                all_findings.extend(self._audit(url, r))
            except Exception:
                continue
        return all_findings


# ═══════════════════════════════════════════════════════════════════════════════
#  ParameterFuzzer
# ═══════════════════════════════════════════════════════════════════════════════

class ParameterFuzzer:
    """Fuzz URL parameters for XSS, SQLi, SSTI, and path traversal."""

    _XSS = [
        '<script>alert("whei")</script>',
        '"><img src=x onerror=alert(1)>',
        "'><svg onload=alert(1)>",
        "{{7*7}}",
    ]

    _SQLI = [
        ("'",               "sqli_quote"),
        ('" OR ""="',       "sqli_or"),
        ("1' AND '1'='1",   "sqli_and"),
        ("' OR 1=1--",      "sqli_comment"),
        ("1; SELECT 1--",   "sqli_select"),
    ]

    _SQLI_TIME = [
        "1' AND SLEEP(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
        "1' AND pg_sleep(5)--",
    ]

    _SSTI = [
        ("{{7*7}}",   "49"),
        ("${7*7}",    "49"),
        ("#{7*7}",    "49"),
        ("<% 7*7 %>", "49"),
        ("${7*'7'}",  "7777777"),
    ]

    _TRAVERSAL = [
        "../../etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
    ]

    _SQLI_ERRORS = [
        "sql syntax", "mysql_fetch", "pg_query", "ora-01", "sqlite_",
        "you have an error in your sql syntax",
        "supplied argument is not a valid mysql",
        "warning: mysql", "microsoft jet database",
        "unclosed quotation mark", "invalid query",
        "sql command not properly ended",
    ]

    _TRAVERSAL_MARKERS = [
        "root:x:", "root:0:0", "[boot loader]",
        "daemon:x:", "/bin/bash", "/bin/sh",
    ]

    def __init__(self, timeout: int = 15, bucket: "_TokenBucket" = None):
        _require_requests()
        self.timeout = timeout
        self.bucket  = bucket or _TokenBucket(2.0)
        self._sess   = _make_session()

    def _inject(self, url: str, param: str, payload: str) -> str:
        p   = urlparse(url)
        qs  = parse_qs(p.query, keep_blank_values=True)
        qs[param] = [payload]
        return urlunparse(p._replace(query=urlencode({k: v[0] for k, v in qs.items()})))

    def _xss(self, url: str, param: str) -> list:
        for payload in self._XSS:
            self.bucket.wait()
            turl = self._inject(url, param, payload)
            try:
                r  = self._sess.get(turl, timeout=self.timeout, verify=False)
                if payload in r.text or payload.replace('"', "&quot;") in r.text:
                    ct  = r.headers.get("content-type", "").lower()
                    sev = "High" if "html" in ct else "Medium"
                    return [_finding(
                        titulo    = f"Reflected XSS: param '{param}'",
                        sev       = sev, confianca = "Confirmed" if "html" in ct else "Likely",
                        descricao = (
                            f"Parameter '{param}' reflects XSS payload unencoded. "
                            f"Content-Type: {ct or 'unknown'}. "
                            "Exploitable for cookie theft and account takeover."
                        ),
                        url = url, trecho = f"?{param}={payload[:60]}  →  reflected in body",
                        regra = "XSS-001", request = f"GET {turl}",
                        response = f"HTTP {r.status_code} Content-Type: {ct}",
                    )]
            except Exception:
                pass
        return []

    def _sqli(self, url: str, param: str) -> list:
        # Error-based
        for payload, _ in self._SQLI:
            self.bucket.wait()
            turl = self._inject(url, param, payload)
            try:
                r   = self._sess.get(turl, timeout=self.timeout, verify=False)
                bl  = r.text.lower()
                hit = next((e for e in self._SQLI_ERRORS if e in bl), None)
                if hit:
                    return [_finding(
                        titulo    = f"SQL Injection (Error-Based): param '{param}'",
                        sev       = "Critical", confianca = "Confirmed",
                        descricao = (
                            f"Parameter '{param}' with payload {payload!r} triggered SQL error: '{hit}'. "
                            "Indicates unsanitized SQL query. May expose/modify database."
                        ),
                        url = url, trecho = f"?{param}={payload}  →  SQL error: {hit!r}",
                        regra = "SQLI-001", request = f"GET {turl}",
                        response = f"HTTP {r.status_code} [SQL error in body]",
                    )]
            except Exception:
                pass

        # Time-based blind
        for payload in self._SQLI_TIME:
            self.bucket.wait()
            turl = self._inject(url, param, payload)
            t0 = time.monotonic()
            try:
                r       = self._sess.get(turl, timeout=self.timeout, verify=False)
                elapsed = time.monotonic() - t0
                if elapsed >= 4.5:
                    return [_finding(
                        titulo    = f"SQL Injection (Time-Based Blind): param '{param}'",
                        sev       = "Critical", confianca = "Likely",
                        descricao = (
                            f"Parameter '{param}' with SLEEP payload caused {elapsed:.1f}s delay. "
                            "Indicates blind time-based SQL injection."
                        ),
                        url = url, trecho = f"?{param}={payload}  →  {elapsed:.1f}s delay",
                        regra = "SQLI-002", request = f"GET {turl}",
                        response = f"HTTP {r.status_code} [response delayed {elapsed:.1f}s]",
                    )]
            except Exception:
                pass
        return []

    def _ssti(self, url: str, param: str) -> list:
        for payload, expected in self._SSTI:
            self.bucket.wait()
            turl = self._inject(url, param, payload)
            try:
                r = self._sess.get(turl, timeout=self.timeout, verify=False)
                if expected and expected in r.text:
                    return [_finding(
                        titulo    = f"Server-Side Template Injection: param '{param}'",
                        sev       = "Critical", confianca = "Confirmed",
                        descricao = (
                            f"Template expression '{payload}' evaluated to '{expected}'. "
                            "SSTI can escalate to Remote Code Execution."
                        ),
                        url = url, trecho = f"?{param}={payload}  →  result '{expected}' in response",
                        regra = "SSTI-001", request = f"GET {turl}",
                        response = f"HTTP {r.status_code}",
                    )]
            except Exception:
                pass
        return []

    def _traversal(self, url: str, param: str) -> list:
        for payload in self._TRAVERSAL:
            self.bucket.wait()
            turl = self._inject(url, param, payload)
            try:
                r   = self._sess.get(turl, timeout=self.timeout, verify=False)
                hit = next((m for m in self._TRAVERSAL_MARKERS if m in r.text), None)
                if hit:
                    return [_finding(
                        titulo    = f"Path Traversal: param '{param}'",
                        sev       = "High", confianca = "Confirmed",
                        descricao = (
                            f"Parameter '{param}' with payload {payload!r} returned "
                            f"content matching '{hit}' (likely /etc/passwd). "
                            "Allows reading arbitrary files from the server."
                        ),
                        url = url, trecho = f"?{param}={payload}  →  '{hit}' in body",
                        regra = "PATH-001", request = f"GET {turl}",
                        response = f"HTTP {r.status_code} [sensitive file content]",
                    )]
            except Exception:
                pass
        return []

    def fuzz(self, urls: list) -> list:
        all_findings: list = []
        candidates = [u for u in urls if "?" in u][:60]

        for url in candidates:
            params = list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
            for param in params[:6]:
                all_findings.extend(self._xss(url, param))
                all_findings.extend(self._sqli(url, param))
                all_findings.extend(self._ssti(url, param))
                all_findings.extend(self._traversal(url, param))

        return all_findings


# ═══════════════════════════════════════════════════════════════════════════════
#  ActiveScanRunner — Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class ActiveScanRunner:
    """
    Orchestrates all active scanners.

    Usage:
        runner = ActiveScanRunner("example.com", config=cfg)
        runner.load_recon("recon_example.json")
        results = runner.run(progress_cb=lambda msg, lvl: print(msg))
    """

    def __init__(
        self,
        domain:    str,
        config:    dict = None,
        verbose:   bool = True,
        use_color: bool = True,
    ):
        _require_requests()
        self.domain    = domain.lower().strip()
        self.verbose   = verbose
        self.use_color = use_color
        self.results:  dict = {}
        self._urls:    list = []

        acfg     = (config or {}).get("active", {})
        scanners = acfg.get("scanners", {})
        limits   = acfg.get("limits",   {})

        self._run_cors    = scanners.get("cors",             True)
        self._run_redir   = scanners.get("open_redirect",    True)
        self._run_headers = scanners.get("security_headers", True)
        self._run_crlf    = scanners.get("header_injection", True)
        self._run_fuzz    = scanners.get("param_fuzz",       True)

        rate                = float(acfg.get("rate_limit",   2.0))
        self._timeout       = int(limits.get("timeout",      15))
        self._max_urls      = int(limits.get("max_urls",     200))
        self._scan_timeout  = int(acfg.get("scan_timeout",   300))
        self._bucket        = _TokenBucket(rate)

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    def load_recon(self, path: str) -> None:
        with open(path) as f:
            self.load_recon_dict(json.load(f))

    def load_recon_dict(self, data: dict) -> None:
        self._urls = self._extract_urls(data)

    def set_urls(self, urls: list) -> None:
        self._urls = list(urls)[: self._max_urls]

    def _extract_urls(self, recon: dict) -> list:
        urls: set = set()

        base = recon.get("meta", {}).get("base_url", "")
        if base:
            urls.add(base)

        wb_cats = recon.get("wayback", {}).get("categories", {})
        for cat in ("api", "admin", "params", "sensitive"):
            for item in (wb_cats.get(cat) or [])[:50]:
                orig = item.get("original", "")
                if orig and orig.startswith("http"):
                    urls.add(orig)

        for ep in recon.get("js_endpoints", {}).get("endpoints", [])[:40]:
            if base and ep.startswith("/"):
                urls.add(base.rstrip("/") + ep)

        for sub in recon.get("subdomains", []):
            if sub.get("alive"):
                urls.add(f"https://{sub['subdomain']}")

        return sorted(urls)[: self._max_urls]

    def run(self, progress_cb: Callable = None) -> dict:
        if not self._urls:
            raise RuntimeError("No URLs. Call load_recon() or set_urls() first.")

        def send(msg: str, level: str = "info"):
            if progress_cb:
                progress_cb(msg, level)
            self._log(msg)

        start        = datetime.now()
        all_findings: list = []

        send(f"[~] Active scan: {self.domain} — {len(self._urls)} URLs", "info")

        # 1. Security headers
        if self._run_headers:
            send("[~] Auditing security headers ...", "info")
            try:
                f = SecurityHeaderAuditor(timeout=self._timeout, bucket=self._bucket).audit(self._urls)
                all_findings.extend(f)
                hi = sum(1 for x in f if x["severidade"] in ("High", "Critical"))
                send(f"[✓] Headers: {len(f)} findings ({hi} high+)", "success")
            except Exception as exc:
                send(f"[!] Header audit failed: {exc}", "warn")

        # 2. CORS
        if self._run_cors:
            send("[~] Testing CORS ...", "info")
            try:
                f = CORSChecker(timeout=self._timeout, bucket=self._bucket).check(self._urls, self.domain)
                all_findings.extend(f)
                send(f"[✓] CORS: {len(f)} findings", "success" if not f else "warn")
            except Exception as exc:
                send(f"[!] CORS check failed: {exc}", "warn")

        # 3. Open Redirect
        if self._run_redir:
            send("[~] Testing open redirects ...", "info")
            try:
                f = OpenRedirectDetector(timeout=self._timeout, bucket=self._bucket).detect(self._urls)
                all_findings.extend(f)
                send(f"[✓] Redirects: {len(f)} findings", "success" if not f else "warn")
            except Exception as exc:
                send(f"[!] Redirect detection failed: {exc}", "warn")

        # 4. Header injection / CRLF
        if self._run_crlf:
            send("[~] Testing Host header + CRLF injection ...", "info")
            try:
                f = HeaderInjectionTester(timeout=self._timeout, bucket=self._bucket).test(self._urls)
                all_findings.extend(f)
                send(f"[✓] Injection: {len(f)} findings", "success" if not f else "warn")
            except Exception as exc:
                send(f"[!] Injection test failed: {exc}", "warn")

        # 5. Parameter fuzzing
        if self._run_fuzz:
            n_param_urls = sum(1 for u in self._urls if "?" in u)
            send(f"[~] Fuzzing parameters ({n_param_urls} URLs with params) ...", "info")
            try:
                f = ParameterFuzzer(timeout=self._timeout, bucket=self._bucket).fuzz(self._urls)
                all_findings.extend(f)
                crits = sum(1 for x in f if x["severidade"] == "Critical")
                send(f"[✓] Fuzzing: {len(f)} findings ({crits} critical)", "success" if not f else "warn")
            except Exception as exc:
                send(f"[!] Fuzzing failed: {exc}", "warn")

        # Deduplicate
        seen: set  = set()
        deduped:  list = []
        for fi in all_findings:
            key = (fi["regra"], fi["url"])
            if key not in seen:
                seen.add(key)
                deduped.append(fi)

        sev_counts = {s: 0 for s in ("Critical", "High", "Medium", "Low", "Info")}
        for fi in deduped:
            sev_counts[fi.get("severidade", "Info")] = sev_counts.get(fi.get("severidade", "Info"), 0) + 1

        end = datetime.now()
        self.results = {
            "meta": {
                "domain":       self.domain,
                "scanned_urls": len(self._urls),
                "started_at":   start.isoformat(),
                "completed_at": end.isoformat(),
                "duration_s":   round((end - start).total_seconds(), 1),
                "tool":         f"whei-guard active-scan v{_VERSION}",
            },
            "findings":        deduped,
            "total_findings":  len(deduped),
            "severity_counts": sev_counts,
        }

        send(
            f"[✓] Scan done — {len(deduped)} findings "
            f"(critical:{sev_counts['Critical']} high:{sev_counts['High']} "
            f"medium:{sev_counts['Medium']} low:{sev_counts['Low']}) "
            f"in {self.results['meta']['duration_s']}s",
            "success",
        )
        return self.results

    def print_summary(self):
        if not self.results:
            print("No results — run .run() first.")
            return

        uc   = self.use_color
        sep  = "─" * 70
        meta = self.results.get("meta", {})
        sev  = self.results.get("severity_counts", {})

        print(f"\n{_c(sep, ORANGE, uc)}")
        print(f"{_c('  ✦ ACTIVE SCAN SUMMARY', ORANGE + BOLD, uc)}\n")
        print(f"  {_c('Domain:',   BOLD, uc)}  {_c(meta.get('domain', ''), CYAN, uc)}")
        print(f"  {_c('URLs:',     BOLD, uc)}  {meta.get('scanned_urls', 0)}")
        print(f"  {_c('Duration:', BOLD, uc)}  {meta.get('duration_s', 0)}s")
        print(f"  {_c('Findings:', BOLD, uc)}  {self.results.get('total_findings', 0)}\n")

        for label, col in [("Critical", RED), ("High", ORANGE), ("Medium", YELLOW), ("Low", CYAN)]:
            n = sev.get(label, 0)
            if n:
                print(f"    {_c(f'{label:<10}', col, uc)} {n}")

        priority = sorted(
            self.results.get("findings", []),
            key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(x["severidade"], 5),
        )
        if priority:
            print(f"\n  {_c('Top findings:', BOLD, uc)}")
            for fi in priority[:10]:
                col = {"Critical": RED, "High": ORANGE, "Medium": YELLOW}.get(fi["severidade"], CYAN)
                print(f"    {_c(fi['severidade'][:4], col, uc)}  {fi['titulo']}")
                print(f"         {_c(fi['url'][:80], DIM, uc)}")

        print(f"\n{_c(sep, ORANGE, uc)}\n")

    def save_json(self, path: str = None) -> str:
        if not self.results:
            raise RuntimeError("No results — run .run() first.")
        if path is None:
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = f"active_{self.domain}_{ts}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        return path
