#!/usr/bin/env python3
"""
WAF Lab — Red Team Test Ortamı
Flask tabanlı, tamamen local çalışan WAF simülasyonu + zafiyetli endpoint'ler.

Kurulum:
    pip install flask

Çalıştırma:
    python app.py
    python app.py --waf cloudflare   # WAF modunu değiştir
    python app.py --port 8080
"""

import re
import time
import json
import math
import hashlib
import argparse
import threading
from collections import defaultdict
from datetime import datetime
from flask import (Flask, request, jsonify, render_template_string,
                   redirect, url_for, make_response, session)

app = Flask(__name__)
app.secret_key = "waf-lab-secret-key-2024"

# ---------------------------------------------------------------------------
# Konfigürasyon
# ---------------------------------------------------------------------------
class Config:
    WAF_MODE     = "cloudflare"   # cloudflare | modsec | imperva | none
    RATE_LIMIT   = 30             # istek/dakika (0 = devre dışı)
    JS_CHALLENGE = True           # JS challenge aktif mi?
    DEBUG_MODE   = False          # WAF kararlarını loglara yaz

config = Config()

# ---------------------------------------------------------------------------
# WAF Kural Setleri — Her profil için ayrı motor
#
# CLOUDFLARE: ML/anomaly tarzı — temel pattern'ler, tek tur decode, case-sensitive
#   Encoding'leri decode ETMEz → hex/base64/unicode bypass'lara açık
#   Güçlü: bilinen imza listesi, rate limiting, JS challenge
#
# MODSEC (OWASP CRS): Çok katmanlı regex, multi-decode, geniş operatör listesi
#   3 tur URL decode + HTML entity decode + hex decode yapar
#   Operatör substitution'ı (||, &&) da yakalar
#   Unicode homoglifleri normalize eder
#   Zayıf: base64 ve octal encoding'i hâlâ kaçırır
#
# IMPERVA: Orta sıkılık — anomali skoru tabanlı, JS challenge ağırlıklı
#   İmza + davranış analizi karışımı; bazı encoding'leri decode eder
#   Zayıf: SSTI ve path traversal kuralları zayıf
# ---------------------------------------------------------------------------

# ── Cloudflare Kuralları ── temel imzalar, tek tur decode, case-sensitive ──
CF_RULES = {
    "sqli": [
        r"(?i)(union\s+select)",                        # boşluk-hassas, /**/ kaçar
        r"(?i)(select\s+.+\s+from)",
        r"(?i)(drop\s+table)",
        r"(?i)(\bor\b\s+['\"0-9])",                     # OR + tırnak/sayı
        r"(?i)(sleep\s*\()",
        r"(?i)(waitfor\s+delay)",
        r"'[\s]*or[\s]*'[\s]*=",                        # sadece ASCII OR
        r"(?i)(xp_cmdshell)",
        r"(?i)(information_schema)",
        r"(?i)(--\s)",                                  # tek kural: -- + boşluk
    ],
    "xss": [
        r"(?i)(<script[\s/>])",                         # sadece <script + boşluk/kapama
        r"(?i)(javascript\s*:)",
        r"(?i)(on(error|load|click)\s*=)",              # sınırlı event handler listesi
        r"(?i)(<iframe[\s/>])",
        r"(?i)(alert\s*\()",
        r"(?i)(document\.cookie)",
        r"(?i)(eval\s*\()",
    ],
    "path": [
        r"(\.\.\/){2,}",                                # sadece ASCII ../
        r"(\.\.\\){2,}",
        r"(?i)(/etc/passwd)",
        r"(?i)(/etc/shadow)",
        r"(?i)(file:///)",
    ],
    "cmdi": [
        r"(?i)(;\s*(cat|id|whoami|wget|curl|bash|sh)\b)",  # ; + komut
        r"(?i)(\|\s*(cat|id|whoami|wget|curl|bash|sh)\b)",
        r"(?i)(&&\s*(cat|id|whoami|wget|curl)\b)",
        r"(?i)(/bin/sh\b)",
        r"(?i)(/bin/bash\b)",
    ],
    "ssti": [
        r"\{\{[^}]*\}\}",                               # sadece {{ ... }} bloğu
        r"(?i)(class\.mro)",
        r"(?i)(__subclasses__)",
    ],
}

# ── ModSecurity / OWASP CRS Kuralları ── çok katmanlı, geniş kapsam ──
MODSEC_RULES = {
    "sqli": [
        r"(?i)(union[\s\+/\*!]+select)",                # comment obfuscation dahil
        r"(?i)(select[\s\+/\*!]+.+[\s\+/\*!]+from)",
        r"(?i)(insert[\s\+/\*!]+into)",
        r"(?i)(drop[\s\+/\*!]+table)",
        r"(?i)(update[\s\+/\*!]+.+[\s\+/\*!]+set)",
        r"(?i)(delete[\s\+/\*!]+from)",
        r"(?i)(\bor\b[\s\d'\"()+/*!-]+[=<>!])",        # OR operatörü geniş
        r"(?i)(\band\b[\s\d'\"()+/*!-]+[=<>!])",
        r"(?i)(\|\|[\s\d'\"()+/*!-]+[=<>!])",          # || operatörü de
        r"(?i)(&&[\s\d'\"()+/*!-]+[=<>!])",
        r"(?i)(sleep[\s]?\([\s]?\d)",
        r"(?i)(benchmark[\s]?\()",
        r"(?i)(waitfor[\s]+delay)",
        r"(?i)(extractvalue[\s]?\()",
        r"(?i)(updatexml[\s]?\()",
        r"(?i)(--[\s\-#])",                             # -- ve # yorum satırları
        r"(?i)(/\*[^!].*?\*/)",                         # /* */ (/*!*/ hariç değil)
        r"(?i)(/\*![\d]*\s*\w)",                        # MySQL /*!...*/ hint
        r"(?i)(xp_cmdshell)",
        r"(?i)(information_schema)",
        r"(?i)(pg_sleep[\s]?\()",
        r"(?i)(load_file[\s]?\()",
        r"(?i)(into[\s]+outfile)",
        r"'[\s]*or[\s]*'",
        r"(?i)(\bor\b[\s]+\d+[\s]*=[\s]*\d+)",         # OR 1=1
        r"(?i)(0x[0-9a-f]{4,})",                       # hex literal (0x...)
        r"(?i)(char[\s]?\([\d,\s]+\))",                # CHAR() fonksiyonu
    ],
    "xss": [
        r"(?i)(<script[\s\r\n\t/>])",
        r"(?i)(<\/script[\s>])",
        r"(?i)(javascript[\s]*:)",
        r"(?i)(vbscript[\s]*:)",
        r"(?i)(on(error|load|click|mouseover|focus|blur|submit|reset|change|keyup|keydown|input|paste|drag|drop|wheel)\s*=)",
        r"(?i)(<iframe[\s\r\n>])",
        r"(?i)(<object[\s\r\n>])",
        r"(?i)(<embed[\s\r\n>])",
        r"(?i)(<svg[\s\r\n>])",
        r"(?i)(<img[^>]+\bon\w+\s*=)",                 # img + event
        r"(?i)(<body[\s]+on\w+\s*=)",
        r"(?i)(alert[\s]?\()",
        r"(?i)(confirm[\s]?\()",
        r"(?i)(prompt[\s]?\()",
        r"(?i)(document[\s]?\.[\s]?cookie)",
        r"(?i)(document[\s]?\.[\s]?write[\s]?\()",
        r"(?i)(eval[\s]?\()",
        r"(?i)(expression[\s]?\()",
        r"(?i)(data[\s]*:[\s]*text/html)",
        r"(?i)(data[\s]*:[\s]*image/svg\+xml)",
        r"(?i)(<link[^>]+rel[\s]*=[\s]*['\"]?stylesheet)",
        r"(?i)(<style[\s>])",
        r"(?i)(<!--.*?-->.*?<)",                        # HTML comment bypass
        r"(?i)(&#[\d]+;.*<)",                           # entity + tag karışımı
        r"(?i)(String\.fromCharCode)",
        r"(?i)(window\.location)",
        r"(?i)(\.innerHTML[\s]*=)",
    ],
    "path": [
        r"(\.\.[\\/]){2,}",                             # hem / hem \
        r"(?i)(%2e%2e[%2f5c]){2,}",                    # URL encoded
        r"(?i)(%252e%252e)",                            # double encoded
        r"(?i)(%c0%af){2,}",                            # overlong UTF-8
        r"(?i)(%c1%9c){2,}",
        r"(?i)(/etc/passwd)",
        r"(?i)(/etc/shadow)",
        r"(?i)(/proc/self)",
        r"(?i)(win\.ini)",
        r"(?i)(system32)",
        r"(?i)(php://filter)",
        r"(?i)(file:///)",
        r"(?i)(\.\.[/\\]){2,}",                        # literal ../ ve ..\
        r"(?i)(etc[\s/]+passwd)",                       # boşluklu varyant
    ],
    "cmdi": [
        r"(?i)(;[\s]*(ls|dir|cat|id|whoami|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby)[\s;|&]?)",
        r"(?i)(\|[\s]*(ls|dir|cat|id|whoami|wget|curl|nc|bash|sh|cmd)[\s;|&]?)",
        r"(?i)(`[^`]{1,100}`)",                         # backtick execution
        r"(?i)(\$\([^)]{1,100}\))",                     # $() subshell
        r"(?i)(&&[\s]*(ls|dir|cat|id|whoami|wget|curl|bash)[\s;|&]?)",
        r"(?i)(\|\|[\s]*(ls|dir|cat|id|whoami)[\s;|&]?)",
        r"(?i)(/bin/(sh|bash|dash|zsh|ksh)[\s;|&\"'])",
        r"(?i)(/usr/bin/(python|perl|ruby|wget|curl|nc)[\s;|&\"'])",
        r"(?i)(\$\{IFS\})",
        r"(?i)(%0[ad][\s]*(ls|dir|cat|id|whoami))",    # newline injection + komut
        r"(?i)(&&id\b|&&whoami\b|&&ls\b|&&dir\b)",     # && + kısa komutlar
        r"(?i)(/\?{3}/\?{2}t)",                        # wildcard /???/??t
    ],
    "ssti": [
        r"\{\{[\s\S]{0,50}\}\}",                        # {{ ... }} geniş
        r"\$\{[\s\S]{0,50}\}",                          # ${ ... }
        r"<%[\s\S]{0,50}%>",                            # ERB tarzı
        r"(?i)(#\{[\s\S]{0,50}\})",                     # Ruby #{...}
        r"\*\{[\s\S]{0,50}\}",                          # Thymeleaf *{...}
        r"(?i)(class[\s]?\.[\s]?mro)",
        r"(?i)(__subclasses__)",
        r"(?i)(__import__)",
        r"(?i)(freemarker\.template)",
        r"(?i)(#set[\s]?\()",
        r"(?i)(#assign[\s]?\b)",
        r"(?i)(\{%[\s]*(for|if|set|raw|block))",
        r"(?i)(getRuntime[\s]?\(\))",
        r"(?i)(_self\.env)",
    ],
}

# ── Imperva Kuralları ── orta sıkılık, anomali skoru simülasyonu ──
IMPERVA_RULES = {
    "sqli": [
        r"(?i)(union[\s/*]+select)",
        r"(?i)(select[\s/*]+.+[\s/*]+from)",
        r"(?i)(\bor\b[\s'\"]+[=\d])",
        r"(?i)(\|\|[\s'\"]+[=\d])",                    # || operatörü
        r"(?i)(sleep[\s]?\(\d)",
        r"(?i)(waitfor[\s]+delay)",
        r"(?i)(--[\s])",
        r"(?i)(xp_cmdshell)",
        r"(?i)(information_schema)",
        r"'[\s]*or[\s]*'",
        r"(?i)(0x[0-9a-f]{6,})",                       # uzun hex literal
    ],
    "xss": [
        r"(?i)(<script[\s/>])",
        r"(?i)(javascript[\s]*:)",
        r"(?i)(on(error|load|click|mouseover|focus)\s*=)",
        r"(?i)(<iframe[\s/>])",
        r"(?i)(<svg[\s/>])",
        r"(?i)(alert[\s]?\()",
        r"(?i)(eval[\s]?\()",
        r"(?i)(document[\s]?\.[\s]?cookie)",
        r"(?i)(String\.fromCharCode)",
    ],
    "path": [
        r"(\.\.[\\/]){2,}",
        r"(?i)(%2e%2e%2f){2,}",
        r"(?i)(/etc/passwd)",
        r"(?i)(/etc/shadow)",
        r"(?i)(php://)",
    ],
    "cmdi": [
        r"(?i)(;[\s]*(cat|id|whoami|bash|sh|cmd)\b)",
        r"(?i)(\|[\s]*(cat|id|whoami|bash|sh)\b)",
        r"(?i)(`[^`]+`)",
        r"(?i)(\$\([^)]+\))",
        r"(?i)(/bin/(bash|sh)\b)",
    ],
    "ssti": [
        r"\{\{[^}]*[0-9\*\+\-][^}]*\}\}",              # sadece math içeren {{ }}
        r"(?i)(class\.mro)",
        r"(?i)(__subclasses__)",
    ],
}

# ── None — Kural Yok ──
NO_RULES = {k: [] for k in ["sqli", "xss", "path", "cmdi", "ssti"]}

# Profil → kural seti mapping
WAF_RULE_MAP = {
    "cloudflare": CF_RULES,
    "modsec":     MODSEC_RULES,
    "imperva":    IMPERVA_RULES,
    "none":       NO_RULES,
}

# ── Decode derinliği: her WAF ne kadar decode yapar? ──
WAF_DECODE_DEPTH = {
    "cloudflare": 1,   # Tek tur URL decode — hex/double-encode kaçar
    "modsec":     3,   # 3 tur URL + HTML entity + unicode normalize
    "imperva":    2,   # 2 tur URL decode
    "none":       0,
}

# ---------------------------------------------------------------------------
# WAF Profilleri — Her WAF'ın farklı bloklama davranışı
# ---------------------------------------------------------------------------
WAF_PROFILES = {
    "cloudflare": {
        "name": "Cloudflare",
        "block_status": 403,
        "block_headers": {
            "Server": "cloudflare",
            "CF-RAY": lambda: f"{hashlib.md5(str(time.time()).encode()).hexdigest()[:16].upper()}-IST",
            "CF-Cache-Status": "DYNAMIC",
            "X-Content-Type-Options": "nosniff",
        },
        "block_body": """<!DOCTYPE html>
<html>
<head><title>Access denied | {host} used Cloudflare to restrict access</title>
<style>body{{font-family:Arial,sans-serif;max-width:600px;margin:80px auto;padding:20px}}
.cf-error-type{{color:#e8612c;font-size:14px;font-weight:700;text-transform:uppercase}}
h1{{font-size:28px;margin:10px 0}}.ray-id{{color:#888;font-size:13px;margin-top:40px}}</style>
</head><body>
<div class="cf-error-type">Error 1006</div>
<h1>Access denied</h1>
<p>What happened?</p>
<p>The owner of this website ({host}) has banned your IP address ({ip}).</p>
<p class="ray-id">Ray ID: {ray_id} &bull; {timestamp} UTC &bull; Performance &amp; security by Cloudflare</p>
</body></html>""",
        "js_challenge": True,
        "rate_limit_header": "Retry-After",
    },
    "modsec": {
        "name": "ModSecurity",
        "block_status": 403,
        "block_headers": {
            "Server": "Apache/2.4.51 (Ubuntu)",
            "X-Mod-Security": "active",
        },
        "block_body": """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<p>Additionally, a 403 Forbidden error was encountered while trying to use an ErrorDocument to handle the request.</p>
<hr>
<address>Apache/2.4.51 (Ubuntu) Server at {host} Port 80</address>
<p><small>This error was generated by Mod_Security. Your IP: {ip} | Ref: {ray_id}</small></p>
</body></html>""",
        "js_challenge": False,
        "rate_limit_header": "Retry-After",
    },
    "imperva": {
        "name": "Imperva (Incapsula)",
        "block_status": 403,
        "block_headers": {
            "Server": "Imperva",
            "X-Iinfo": lambda: f"13-{int(time.time())}-0 NNNN RT(1234567890123 0) q(0 0 0 -1) r(0 0) B12(0,0,0) U5",
            "X-CDN": "Imperva",
        },
        "block_body": """<!DOCTYPE html>
<html>
<head><title>Request Unsuccessful</title>
<style>body{{font-family:Arial;text-align:center;padding:50px}}
.box{{border:1px solid #ddd;max-width:500px;margin:auto;padding:30px;border-radius:4px}}
.ref{{color:#999;font-size:12px;margin-top:20px}}</style>
</head>
<body><div class="box">
<h2>Request Unsuccessful</h2>
<p>Incapsula incident ID: {ray_id}</p>
<p>Your request was blocked by the web application security platform.</p>
<p class="ref">Reference #18.{ray_id}.{timestamp}</p>
</div></body></html>""",
        "js_challenge": True,
        "rate_limit_header": "X-RateLimit-Reset",
    },
    "none": {
        "name": "No WAF",
        "block_status": 200,
        "block_headers": {},
        "block_body": "",
        "js_challenge": False,
        "rate_limit_header": "Retry-After",
    },
}

# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self):
        self._counts  = defaultdict(list)   # ip → [timestamp, ...]
        self._lock    = threading.Lock()
        self._blocked = defaultdict(float)  # ip → blocked_until

    def check(self, ip: str, limit: int, window: int = 60) -> tuple[bool, int]:
        """Returns (allowed, remaining)"""
        if limit == 0:
            return True, 999

        now = time.time()
        with self._lock:
            # Blocked mı?
            if self._blocked[ip] > now:
                return False, 0

            # Eski kayıtları temizle
            self._counts[ip] = [t for t in self._counts[ip] if now - t < window]
            count = len(self._counts[ip])

            if count >= limit:
                # 30 saniye block
                self._blocked[ip] = now + 30
                return False, 0

            self._counts[ip].append(now)
            return True, limit - count - 1

rate_limiter = RateLimiter()

# ---------------------------------------------------------------------------
# JS Challenge Token Store
# ---------------------------------------------------------------------------
class ChallengeStore:
    def __init__(self):
        self._tokens = {}   # token → (ip, expire_time)
        self._lock   = threading.Lock()

    def issue(self, ip: str) -> str:
        token = hashlib.sha256(f"{ip}{time.time()}{app.secret_key}".encode()).hexdigest()[:32]
        with self._lock:
            self._tokens[token] = (ip, time.time() + 300)  # 5 dakika geçerli
        return token

    def verify(self, token: str, ip: str) -> bool:
        with self._lock:
            entry = self._tokens.get(token)
            if not entry:
                return False
            stored_ip, expire = entry
            if time.time() > expire:
                del self._tokens[token]
                return False
            return stored_ip == ip

    def cleanup(self):
        now = time.time()
        with self._lock:
            expired = [t for t, (_, e) in self._tokens.items() if e < now]
            for t in expired:
                del self._tokens[t]

challenge_store = ChallengeStore()

# ---------------------------------------------------------------------------
# Payload Analiz
# ---------------------------------------------------------------------------
def _decode_value(value: str, depth: int) -> list[str]:
    """
    WAF'ın decode kapasitesine göre farklı temsillerini üretir.
    depth: 0=ham, 1=tek tur URL, 2=çift tur URL, 3=tam decode
    """
    from urllib.parse import unquote
    import unicodedata

    variants = [value]

    # URL decode — depth kadar tur
    current = value
    for i in range(depth):
        new = unquote(current)
        if new != current:
            variants.append(new)
            current = new
        else:
            break

    # HTML entity decode (ModSec seviyesinde)
    if depth >= 2:
        decoded = current
        # decimal entities: &#NNN;
        decoded = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), decoded)
        # hex entities: &#xNN;
        decoded = re.sub(r'&#x([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)), decoded)
        # named entities
        decoded = decoded.replace("&lt;", "<").replace("&gt;", ">") \
                         .replace("&amp;", "&").replace("&quot;", '"') \
                         .replace("&apos;", "'")
        if decoded != current:
            variants.append(decoded)
            current = decoded

    # Unicode normalizasyon (ModSec tam seviye)
    if depth >= 3:
        for form in ["NFC", "NFKC"]:
            try:
                normalized = unicodedata.normalize(form, current)
                if normalized != current:
                    variants.append(normalized)
            except Exception:
                pass

    # Hex decode: \xNN formatı (ModSec yapar, CF yapmaz)
    if depth >= 3:
        try:
            hex_decoded = re.sub(r'\\x([0-9a-fA-F]{2})',
                                 lambda m: chr(int(m.group(1), 16)), current)
            if hex_decoded != current:
                variants.append(hex_decoded)
        except Exception:
            pass

    return variants


def analyze_payload(value: str) -> tuple[bool, str, str]:
    """
    Aktif WAF profiline göre decode + kural taraması yapar.
    Returns: (is_malicious, category, matched_rule)
    """
    if not value:
        return False, "", ""

    # Aktif WAF'ın kural seti ve decode derinliği
    rules   = WAF_RULE_MAP.get(config.WAF_MODE, CF_RULES)
    depth   = WAF_DECODE_DEPTH.get(config.WAF_MODE, 1)

    # Decode varyantları üret
    variants = _decode_value(value, depth)

    # Her varyant için hem orijinal hem lowercase tara
    checks = []
    for v in variants:
        checks.append(v)
        checks.append(v.lower())

    for category, patterns in rules.items():
        for pattern in patterns:
            for check in checks:
                try:
                    if re.search(pattern, check):
                        return True, category, pattern
                except re.error:
                    pass

    return False, "", ""

def scan_request() -> tuple[bool, str, str]:
    """Tüm request parametrelerini tara."""
    sources = []

    # Query string
    for k, v in request.args.items():
        sources.append(f"{k}={v}")

    # POST body
    if request.method in ["POST", "PUT", "PATCH"]:
        for k, v in request.form.items():
            sources.append(f"{k}={v}")
        if request.is_json:
            try:
                data = request.get_json(force=True)
                if isinstance(data, dict):
                    for k, v in data.items():
                        sources.append(f"{k}={v}")
            except Exception:
                pass
        # Raw body
        raw = request.get_data(as_text=True)
        if raw:
            sources.append(raw)

    # Headers (User-Agent, Referer vb. taranır)
    for header in ["User-Agent", "Referer", "X-Forwarded-For"]:
        val = request.headers.get(header, "")
        if val:
            sources.append(val)

    # Cookie
    for k, v in request.cookies.items():
        sources.append(f"{k}={v}")

    for source in sources:
        malicious, category, rule = analyze_payload(source)
        if malicious:
            return True, category, rule

    return False, "", ""

# ---------------------------------------------------------------------------
# WAF Middleware
# ---------------------------------------------------------------------------
def build_block_response(profile: dict, reason: str = ""):
    ip = request.remote_addr or "1.2.3.4"
    host = request.host or "localhost"
    ray_id = hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()[:16].upper()
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    body = profile["block_body"].format(
        host=host, ip=ip, ray_id=ray_id, timestamp=timestamp
    )

    resp = make_response(body, profile["block_status"])
    resp.headers["Content-Type"] = "text/html; charset=utf-8"

    for key, val in profile["block_headers"].items():
        resp.headers[key] = val() if callable(val) else val

    if config.DEBUG_MODE:
        resp.headers["X-WAF-Reason"] = reason

    return resp

@app.before_request
def waf_middleware():
    # Static dosyaları atla
    if request.path.startswith("/static"):
        return None

    profile = WAF_PROFILES.get(config.WAF_MODE, WAF_PROFILES["cloudflare"])
    ip = request.remote_addr or "127.0.0.1"

    # 1. Rate limiting
    if config.RATE_LIMIT > 0:
        allowed, remaining = rate_limiter.check(ip, config.RATE_LIMIT)
        if not allowed:
            resp = build_block_response(profile, "rate_limit")
            resp.status_code = 429
            resp.headers["Retry-After"] = "30"
            resp.headers["X-RateLimit-Limit"] = str(config.RATE_LIMIT)
            resp.headers["X-RateLimit-Remaining"] = "0"
            return resp

    # 2. JS Challenge — sadece Cloudflare/Imperva profili + browser isteği
    if (config.JS_CHALLENGE and profile.get("js_challenge") and
            not request.path.startswith("/waf/") and
            "text/html" in request.headers.get("Accept", "")):
        token = request.cookies.get("__waf_challenge_token")
        if not token or not challenge_store.verify(token, ip):
            return serve_js_challenge()

    # 3. Payload tarama — /waf/ ve /admin/ path'leri hariç
    if not request.path.startswith("/waf/") and not request.path.startswith("/admin"):
        malicious, category, rule = scan_request()
        if malicious:
            return build_block_response(profile, f"{category}: {rule[:50]}")

    return None  # devam et

# ---------------------------------------------------------------------------
# JS Challenge Sayfaları
# ---------------------------------------------------------------------------
JS_CHALLENGE_PAGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Just a moment... | {waf_name}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #f0f2f5; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: white; border-radius: 12px; padding: 48px 40px; max-width: 440px; width: 90%;
           box-shadow: 0 4px 24px rgba(0,0,0,.08); text-align: center; }
  .logo { font-size: 32px; margin-bottom: 16px; }
  h1 { font-size: 22px; color: #1a1a2e; margin-bottom: 8px; }
  p { color: #666; font-size: 14px; line-height: 1.6; margin-bottom: 24px; }
  .spinner { width: 40px; height: 40px; border: 3px solid #e0e0e0;
              border-top-color: #f6821f; border-radius: 50%;
              animation: spin 0.8s linear infinite; margin: 0 auto 20px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .progress { background: #e0e0e0; border-radius: 4px; height: 4px; overflow: hidden; margin-bottom: 16px; }
  .progress-bar { height: 100%; background: #f6821f; width: 0; animation: progress 3s ease-out forwards; }
  @keyframes progress { to { width: 100%; } }
  .ray { color: #aaa; font-size: 11px; font-family: monospace; margin-top: 24px; }
  .badge { display: inline-block; background: #f6821f; color: white; font-size: 11px;
            padding: 2px 8px; border-radius: 12px; margin-bottom: 16px; }
  #status { color: #888; font-size: 13px; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">🛡️</div>
  <div class="badge">{waf_name}</div>
  <h1>Checking your browser</h1>
  <p>This process is automatic. Your browser will redirect to your requested content shortly.</p>
  <div class="progress"><div class="progress-bar"></div></div>
  <div class="spinner"></div>
  <p id="status">Verifying you are human...</p>
  <div class="ray">Ray ID: {ray_id}</div>
</div>

<script>
// Simüle edilmiş JS challenge — gerçek PoW değil
(function() {{
  var steps = [
    [500,  "Computing challenge..."],
    [1200, "Validating response..."],
    [2200, "Almost done..."],
    [3000, "Redirecting..."]
  ];
  var status = document.getElementById("status");
  steps.forEach(function(s) {{
    setTimeout(function() { status.textContent = s[1]; }, s[0]);
  }});
  setTimeout(function() {{
    // Challenge token'ı al ve cookie olarak set et, sonra yönlendir
    fetch("/waf/challenge/verify", {{
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ray_id: "{ray_id}", ts: Date.now()})
    }})
    .then(function(r) {{ return r.json(); }})
    .then(function(d) {{
      if (d.token) {{
        document.cookie = "__waf_challenge_token=" + d.token + "; path=/; max-age=300";
        window.location.reload();
      }}
    }})
    .catch(function() {{ window.location.reload(); }});
  }, 3200);
}})();
</script>
</body>
</html>"""

def serve_js_challenge():
    ip = request.remote_addr or "127.0.0.1"
    waf_name = WAF_PROFILES.get(config.WAF_MODE, {}).get("name", "WAF")
    ray_id = hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()[:16].upper()
    html = JS_CHALLENGE_PAGE.format(waf_name=waf_name, ray_id=ray_id)
    resp = make_response(html, 503)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    if config.WAF_MODE == "cloudflare":
        resp.headers["Server"] = "cloudflare"
        resp.headers["CF-RAY"] = f"{ray_id}-IST"
    return resp

@app.route("/waf/challenge/verify", methods=["POST"])
def challenge_verify():
    ip = request.remote_addr or "127.0.0.1"
    token = challenge_store.issue(ip)
    return jsonify({"token": token, "ok": True})

# ---------------------------------------------------------------------------
# Admin Panel — WAF modunu runtime'da değiştir
# ---------------------------------------------------------------------------
ADMIN_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>WAF Lab — Admin Panel</title>
<style>
body{ font-family: monospace; background:#0d1117; color:#c9d1d9; margin:0; padding:24px; }
h1{ color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:12px; }
.card{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; margin:16px 0; }
.card h2{ color:#79c0ff; font-size:14px; margin:0 0 12px; text-transform:uppercase; letter-spacing:1px; }
label{ display:block; color:#8b949e; font-size:13px; margin-bottom:4px; }
select,input{ background:#0d1117; border:1px solid #30363d; color:#c9d1d9; padding:6px 10px;
               border-radius:4px; font-family:monospace; font-size:13px; }
button{ background:#238636; border:none; color:white; padding:8px 18px;
         border-radius:4px; cursor:pointer; font-size:13px; margin-top:8px; }
button:hover{ background:#2ea043; }
.badge{ display:inline-block; padding:2px 8px; border-radius:12px; font-size:11px;
         font-family:monospace; font-weight:700; }
.on{ background:#1f6feb; color:white; } .off{ background:#30363d; color:#8b949e; }
.tag{ background:#21262d; border:1px solid #30363d; padding:10px; border-radius:4px;
       font-size:12px; color:#8b949e; margin-top:8px; }
table{ width:100%; border-collapse:collapse; font-size:13px; }
th{ text-align:left; color:#8b949e; padding:6px 12px; border-bottom:1px solid #30363d; }
td{ padding:6px 12px; border-bottom:1px solid #21262d; }
a{ color:#58a6ff; text-decoration:none; }
a:hover{ text-decoration:underline; }
.method{ background:#1f6feb; color:white; padding:1px 6px; border-radius:3px;
          font-size:11px; margin-right:4px; }
.method.post{ background:#238636; }
.method.get{ background:#1f6feb; }
</style>
</head>
<body>
<h1>🛡 WAF Lab — Admin Panel</h1>

<div class="card">
  <h2>WAF Konfigürasyonu</h2>
  <form method="POST" action="/admin/config">
    <table>
      <tr>
        <td><label>WAF Modu</label>
            <select name="waf_mode">
              {% for m in ['cloudflare','modsec','imperva','none'] %}
              <option value="{{m}}" {'selected' if m == waf_mode else ''}>{{m}}</option>
              {% endfor %}
            </select></td>
        <td><label>Rate Limit (req/dk, 0=off)</label>
            <input type="number" name="rate_limit" value="{{rate_limit}}" min="0" max="300"></td>
        <td><label>JS Challenge</label>
            <select name="js_challenge">
              <option value="1" {{'selected' if js_challenge else ''}}>Açık</option>
              <option value="0" {{'' if js_challenge else 'selected'}}>Kapalı</option>
            </select></td>
        <td><label>Debug (WAF header)</label>
            <select name="debug_mode">
              <option value="1" {{'selected' if debug_mode else ''}}>Açık</option>
              <option value="0" {{'' if debug_mode else 'selected'}}>Kapalı</option>
            </select></td>
      </tr>
    </table>
    <button type="submit">💾 Kaydet</button>
  </form>
  <div class="tag">
    Aktif: <b>{{waf_mode}}</b> | Rate: <b>{{rate_limit}}/dk</b> |
    JS Challenge: <span class="badge {'on' if js_challenge else 'off'}">{'ON' if js_challenge else 'OFF'}</span> |
    Debug: <span class="badge {'on' if debug_mode else 'off'}">{'ON' if debug_mode else 'OFF'}</span>
  </div>
</div>

<div class="card">
  <h2>Test Endpoint'leri</h2>
  <table>
    <tr><th>Endpoint</th><th>Metod</th><th>Zafiyet</th><th>Örnek Payload</th></tr>
    <tr>
      <td><a href="/login">/login</a></td>
      <td><span class="method post">POST</span></td>
      <td>SQL Injection</td>
      <td><code>' OR '1'='1'--</code></td>
    </tr>
    <tr>
      <td><a href="/search?q=test">/search</a></td>
      <td><span class="method get">GET</span></td>
      <td>XSS</td>
      <td><code>&lt;script&gt;alert(1)&lt;/script&gt;</code></td>
    </tr>
    <tr>
      <td><a href="/download?file=report.pdf">/download</a></td>
      <td><span class="method get">GET</span></td>
      <td>Path Traversal</td>
      <td><code>../../etc/passwd</code></td>
    </tr>
    <tr>
      <td><a href="/ping?host=127.0.0.1">/ping</a></td>
      <td><span class="method get">GET</span></td>
      <td>Command Injection</td>
      <td><code>127.0.0.1; id</code></td>
    </tr>
    <tr>
      <td><a href="/render?template=Hello">/render</a></td>
      <td><span class="method get">GET</span></td>
      <td>SSTI</td>
      <td><code>{{7*7}}</code></td>
    </tr>
    <tr>
      <td><a href="/api/data?id=1">/api/data</a></td>
      <td><span class="method get">GET</span></td>
      <td>SQLi (API)</td>
      <td><code>1 UNION SELECT 1,2,3--</code></td>
    </tr>
  </table>
</div>

<div class="card">
  <h2>WAF Fuzzer Örnek Komutları</h2>
  <div class="tag">
    # SQLi bypass — login formu<br>
    python waf_fuzzer_v2.py -u http://localhost:{{port}}/login -X POST -d "username=FUZZ&password=test" --context sqli<br><br>
    # XSS bypass — arama kutusu<br>
    python waf_fuzzer_v2.py -u "http://localhost:{{port}}/search?q=FUZZ" --context xss<br><br>
    # Path traversal<br>
    python waf_fuzzer_v2.py -u "http://localhost:{{port}}/download?file=FUZZ" --context path<br><br>
    # Command injection<br>
    python waf_fuzzer_v2.py -u "http://localhost:{{port}}/ping?host=FUZZ" --context cmdi<br><br>
    # SSTI<br>
    python waf_fuzzer_v2.py -u "http://localhost:{{port}}/render?template=FUZZ" --context ssti<br><br>
    # Proxy (Burp Suite)<br>
    python waf_fuzzer_v2.py -u http://localhost:{{port}}/search?q=FUZZ --proxy http://127.0.0.1:8080 --context xss
  </div>
</div>
</body></html>"""

@app.route("/admin")
def admin():
    return render_template_string(ADMIN_PAGE,
        waf_mode=config.WAF_MODE,
        rate_limit=config.RATE_LIMIT,
        js_challenge=config.JS_CHALLENGE,
        debug_mode=config.DEBUG_MODE,
        port=app.config.get("PORT", 5000)
    )

@app.route("/admin/config", methods=["POST"])
def admin_config():
    config.WAF_MODE     = request.form.get("waf_mode", "cloudflare")
    config.RATE_LIMIT   = int(request.form.get("rate_limit", 30))
    config.JS_CHALLENGE = request.form.get("js_challenge") == "1"
    config.DEBUG_MODE   = request.form.get("debug_mode") == "1"
    return redirect("/admin")

# ---------------------------------------------------------------------------
# Ana Sayfa
# ---------------------------------------------------------------------------
HOME_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>ShopEasy — Online Alışveriş</title>
<style>
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#f8f9fa; }
nav { background:#1a1a2e; padding:14px 32px; display:flex; align-items:center; gap:24px; }
nav .brand { color:white; font-weight:700; font-size:20px; }
nav a { color:#adb5bd; text-decoration:none; font-size:14px; }
nav a:hover { color:white; }
nav .search { flex:1; max-width:400px; margin-left:auto; }
nav .search input { width:100%; padding:8px 14px; border-radius:20px; border:none;
                     background:#2d3561; color:white; font-size:14px; }
.hero { background:linear-gradient(135deg,#1a1a2e,#16213e); color:white; padding:80px 32px;
         text-align:center; }
.hero h1 { font-size:42px; margin-bottom:16px; }
.hero p { color:#adb5bd; font-size:16px; max-width:500px; margin:0 auto 24px; }
.btn { display:inline-block; background:#e94560; color:white; padding:12px 28px;
        border-radius:6px; text-decoration:none; font-weight:600; }
.products { max-width:1100px; margin:40px auto; padding:0 24px; }
.products h2 { font-size:22px; margin-bottom:20px; color:#1a1a2e; }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:20px; }
.card { background:white; border-radius:10px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.06); }
.card img { width:100%; height:160px; object-fit:cover; background:#e9ecef;
             display:flex; align-items:center; justify-content:center; font-size:40px; }
.card-body { padding:16px; }
.card-body h3 { font-size:15px; margin-bottom:6px; }
.card-body .price { color:#e94560; font-weight:700; font-size:18px; }
.card-body .btn-sm { display:block; text-align:center; background:#1a1a2e; color:white;
                      padding:8px; border-radius:5px; margin-top:10px; text-decoration:none;
                      font-size:13px; }
footer { background:#1a1a2e; color:#6c757d; text-align:center; padding:24px; margin-top:60px;
          font-size:13px; }
</style>
</head>
<body>
<nav>
  <span class="brand">🛒 ShopEasy</span>
  <a href="/">Ana Sayfa</a>
  <a href="/search?q=">Ara</a>
  <a href="/login">Giriş</a>
  <div class="search">
    <form action="/search">
      <input name="q" placeholder="Ürün ara..." value="">
    </form>
  </div>
</nav>
<div class="hero">
  <h1>En İyi Ürünler, En İyi Fiyatlar</h1>
  <p>Binlerce ürün arasından seçim yapın, hızlı teslimat garantisiyle.</p>
  <a href="/search?q=laptop" class="btn">Alışverişe Başla</a>
</div>
<div class="products">
  <h2>Öne Çıkan Ürünler</h2>
  <div class="grid">
    {% for p in products %}
    <div class="card">
      <div style="height:160px;background:#e9ecef;display:flex;align-items:center;
                  justify-content:center;font-size:48px;">{{p.icon}}</div>
      <div class="card-body">
        <h3>{{p.name}}</h3>
        <div class="price">₺{{p.price}}</div>
        <a href="/search?q={{p.name}}" class="btn-sm">İncele</a>
      </div>
    </div>
    {% endfor %}
  </div>
</div>
<footer>ShopEasy &copy; 2024 | WAF Lab Test Ortamı — Yalnızca yetkili kullanım için</footer>
</body>
</html>"""

PRODUCTS = [
    {"icon": "💻", "name": "Laptop Pro X", "price": "12.499"},
    {"icon": "📱", "name": "Akıllı Telefon", "price": "8.999"},
    {"icon": "🎧", "name": "Kablosuz Kulaklık", "price": "1.299"},
    {"icon": "⌨️", "name": "Mekanik Klavye", "price": "899"},
    {"icon": "🖥️", "name": "4K Monitör", "price": "6.499"},
    {"icon": "🖱️", "name": "Gaming Mouse", "price": "549"},
    {"icon": "📷", "name": "Dijital Kamera", "price": "4.999"},
    {"icon": "🔋", "name": "Powerbank 20000mAh", "price": "299"},
]

@app.route("/")
def home():
    return render_template_string(HOME_PAGE, products=PRODUCTS)

# ---------------------------------------------------------------------------
# Endpoint 1: SQLi — Login Formu
# ---------------------------------------------------------------------------
LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Giriş Yap — ShopEasy</title>
<style>
body{font-family:-apple-system,sans-serif;background:#f8f9fa;display:flex;align-items:center;
     justify-content:center;min-height:100vh;}
.box{background:white;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08);
      width:380px;}
h1{font-size:22px;color:#1a1a2e;margin-bottom:6px;}
p{color:#6c757d;font-size:14px;margin-bottom:24px;}
label{display:block;font-size:13px;color:#495057;margin-bottom:4px;font-weight:500;}
input{width:100%;padding:10px 12px;border:1px solid #dee2e6;border-radius:6px;
       font-size:14px;margin-bottom:16px;box-sizing:border-box;}
button{width:100%;padding:11px;background:#1a1a2e;color:white;border:none;
        border-radius:6px;font-size:14px;cursor:pointer;font-weight:600;}
.msg{padding:10px 14px;border-radius:6px;font-size:13px;margin-bottom:16px;}
.success{background:#d1e7dd;color:#0f5132;} .error{background:#f8d7da;color:#842029;}
.hint{color:#adb5bd;font-size:11px;margin-top:16px;text-align:center;}
</style>
</head>
<body>
<div class="box">
  <h1>🔐 Giriş Yap</h1>
  <p>ShopEasy hesabınıza giriş yapın</p>
  {% if message %}
  <div class="msg {{msg_class}}">{{message}}</div>
  {% endif %}
  <form method="POST">
    <label>Kullanıcı Adı</label>
    <input type="text" name="username" placeholder="admin" autocomplete="off">
    <label>Şifre</label>
    <input type="password" name="password" placeholder="••••••••">
    <button type="submit">Giriş Yap</button>
  </form>
  <div class="hint">Test: admin / password123 | SQLi: ' OR '1'='1'--</div>
</div>
</body></html>"""

# Sahte kullanıcı DB (gerçek SQL yok — simüle ediliyor)
FAKE_USERS = {
    "admin":    "password123",
    "user1":    "letmein",
    "testuser": "test1234",
}

def simulate_sql_query(username: str, password: str) -> tuple[bool, str]:
    """
    Gerçek SQL çalıştırmaz — injection mantığını simüle eder.
    WAF bu noktaya ulaşabilirse bypass başarılı demektir.
    """
    # Tautology bypass simülasyonu
    tautologies = [
        r"'\s*or\s*'1'\s*=\s*'1",
        r"'\s*or\s*1\s*=\s*1",
        r"1\s*=\s*1",
        r"'\s*--",
        r'"\s*or\s*"1"\s*=\s*"1',
        r"or\s+true",
    ]
    combined = f"{username} {password}".lower()
    for pattern in tautologies:
        if re.search(pattern, combined, re.IGNORECASE):
            return True, "SQL injection bypass başarılı! Simüle edilmiş admin erişimi."

    # Union select simülasyonu
    if re.search(r"union\s+select", combined, re.IGNORECASE):
        return True, "UNION SELECT bypass! Simüle edilmiş veri sızıntısı: admin:password123, user1:letmein"

    # Normal auth
    if FAKE_USERS.get(username) == password:
        return True, f"Başarılı giriş: {username}"

    return False, "Kullanıcı adı veya şifre hatalı."

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    msg_class = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        success, msg = simulate_sql_query(username, password)
        message = msg
        msg_class = "success" if success else "error"
    return render_template_string(LOGIN_PAGE, message=message, msg_class=msg_class)

# ---------------------------------------------------------------------------
# Endpoint 2: XSS — Arama Kutusu
# ---------------------------------------------------------------------------
SEARCH_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Arama: {{ query }} — ShopEasy</title>
{% raw %}<style>
body{font-family:-apple-system,sans-serif;background:#f8f9fa;}
nav{background:#1a1a2e;padding:14px 32px;display:flex;align-items:center;gap:16px;}
nav .brand{color:white;font-weight:700;font-size:18px;}
nav input{flex:1;max-width:400px;padding:8px 14px;border-radius:20px;border:none;
           background:#2d3561;color:white;font-size:14px;margin-left:auto;}
main{max-width:900px;margin:32px auto;padding:0 24px;}
.result-info{color:#6c757d;font-size:14px;margin-bottom:20px;}
.result-info b{color:#1a1a2e;}
.results{display:grid;gap:12px;}
.result-item{background:white;padding:20px;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.06);}
.result-item h3{font-size:16px;color:#1a1a2e;margin-bottom:4px;}
.result-item p{color:#6c757d;font-size:13px;}
.result-item .price{color:#e94560;font-weight:700;margin-top:6px;}
.xss-note{background:#fff3cd;border:1px solid #ffc107;padding:12px 16px;border-radius:6px;
           font-size:12px;color:#856404;margin-bottom:16px;}
</style>{% endraw %}
</head>
<body>
<nav>
  <span class="brand">🛒 ShopEasy</span>
  <form action="/search" style="flex:1;max-width:400px;margin-left:auto;">
    <input name="q" value="{{query}}" placeholder="Ürün ara...">
  </form>
</nav>
<main>
  <div class="xss-note">⚠️ WAF Lab: Bu sayfa XSS test endpoint'idir. Arama terimi sanitize edilmeden yansıtılır.</div>
  <div class="result-info">
    <b>{{query}}</b> için {{count}} sonuç bulundu
  </div>
  <div style="background:#f0f0f0;padding:10px;border-radius:4px;font-size:12px;color:#666;margin-bottom:16px;">
    Arama terimi (ham): {{query_raw}}
  </div>
  <div class="results">
    {% for r in results %}
    <div class="result-item">
      <h3>{{r.icon}} {{r.name}}</h3>
      <p>{{r.desc}}</p>
      <div class="price">₺{{r.price}}</div>
    </div>
    {% endfor %}
  </div>
  {% if not results %}
  <p style="color:#6c757d;text-align:center;margin-top:40px;">Sonuç bulunamadı.</p>
  {% endif %}
</main>
</body></html>"""

@app.route("/search")
def search():
    query = request.args.get("q", "")

    # XSS simülasyonu: query olduğu gibi sayfaya gömülüyor (intentionally unsafe render)
    # Gerçek Jinja2 auto-escaping'i bypass etmek için Markup kullanıyoruz — LAB AMAÇLI
    from markupsafe import Markup
    query_raw = Markup(query)  # <-- intentionally unsafe, WAF bypass testi için

    results = [p for p in PRODUCTS if query.lower() in p["name"].lower()] if query else PRODUCTS
    results_enriched = [{
        "icon": p["icon"], "name": p["name"], "price": p["price"],
        "desc": f"Yüksek kaliteli {p['name']} ürünü. Hızlı kargo."
    } for p in results]

    return render_template_string(SEARCH_PAGE,
        query=query, query_raw=query_raw,
        count=len(results_enriched), results=results_enriched)

# ---------------------------------------------------------------------------
# Endpoint 3: Path Traversal — Dosya indirme
# ---------------------------------------------------------------------------
DOWNLOAD_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Dosya İndir — ShopEasy</title>
<style>
body{font-family:-apple-system,sans-serif;background:#f8f9fa;padding:40px;}
.box{max-width:600px;margin:auto;background:white;padding:32px;border-radius:12px;
      box-shadow:0 2px 12px rgba(0,0,0,.08);}
h1{font-size:20px;color:#1a1a2e;margin-bottom:20px;}
.files{list-style:none;padding:0;}
.files li{padding:10px 14px;border:1px solid #dee2e6;border-radius:6px;margin-bottom:8px;
           display:flex;align-items:center;gap:10px;font-size:14px;}
.files li a{color:#0066cc;text-decoration:none;}
.files li a:hover{text-decoration:underline;}
.result{background:#d1ecf1;border:1px solid #bee5eb;padding:16px;border-radius:6px;
         margin-top:20px;font-size:13px;white-space:pre-wrap;font-family:monospace;}
.error{background:#f8d7da;border:1px solid #f5c6cb;}
.warn{background:#fff3cd;border:1px solid #ffc107;padding:10px 14px;border-radius:6px;
       font-size:12px;color:#856404;margin-bottom:16px;}
</style>
</head>
<body>
<div class="box">
  <h1>📁 Dosya İndirme Servisi</h1>
  <div class="warn">⚠️ WAF Lab: Path traversal test endpoint'i. Dosya adı sanitize edilmez.</div>
  <ul class="files">
    <li>📄 <a href="/download?file=report.pdf">report.pdf</a> — Q4 2024 Raporu</li>
    <li>📊 <a href="/download?file=data.csv">data.csv</a> — Ürün verileri</li>
    <li>📋 <a href="/download?file=readme.txt">readme.txt</a> — Dokümantasyon</li>
  </ul>
  {% if filename %}
  <div class="result {{result_class}}">
<b>İstenen dosya:</b> {{filename}}
<b>Simüle edilen path:</b> /var/www/files/{{filename}}
<b>Sonuç:</b>
{{content}}
  </div>
  {% endif %}
</div>
</body></html>"""

# Simüle edilmiş dosyalar
SIMULATED_FILES = {
    "report.pdf":  "[PDF içeriği simüle edildi] Q4 2024 ShopEasy Satış Raporu\nGelir: ₺4.2M\nKullanıcı: 12,847",
    "data.csv":    "id,product,price,stock\n1,Laptop Pro X,12499,45\n2,Akıllı Telefon,8999,120",
    "readme.txt":  "ShopEasy v2.4.1\nKurulum: pip install -r requirements.txt\nAdmin panel: /admin",
    "etc/passwd":  "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nshopeasy:x:1000:1000:ShopEasy App:/home/shopeasy:/bin/bash",
    "etc/shadow":  "root:$6$xyz$hashedpassword:18000:0:99999:7:::\nwww-data:*:18000:0:99999:7:::",
    "proc/self/environ": "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\nPWD=/var/www/html\nSECRET_KEY=super_secret_key_12345\nDB_PASSWORD=mysql_prod_pass",
    "windows/win.ini": "[boot]\nSystem.ini=C:\\Windows\\system.ini\nWin.ini=C:\\Windows\\win.ini\n[extensions]",
}

def resolve_traversal(filename: str) -> str:
    """Path traversal simülasyonu — gerçek dosya sistemi'ne DOKUNMAZ."""
    # normalize
    normalized = filename.replace("\\", "/")
    normalized = normalized.replace("%2f", "/").replace("%2F", "/")
    normalized = normalized.replace("%2e", ".").replace("%2E", ".")
    normalized = normalized.replace("%00", "").replace("\x00", "")

    # ../ resolve
    parts = []
    for part in normalized.split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part and part != ".":
            parts.append(part)
    resolved = "/".join(parts)

    # Simüle edilmiş dosya var mı?
    for key, content in SIMULATED_FILES.items():
        if resolved.endswith(key) or resolved == key:
            return content

    return f"[Dosya bulunamadı: {resolved}]"

@app.route("/download")
def download():
    filename = request.args.get("file", "")
    content = ""
    result_class = ""

    if filename:
        content = resolve_traversal(filename)
        # Hassas dosyaya erişim simülasyonu
        if any(s in filename for s in ["passwd", "shadow", "environ", "win.ini"]):
            result_class = "error"
        else:
            result_class = ""

    return render_template_string(DOWNLOAD_PAGE,
        filename=filename, content=content, result_class=result_class)

# ---------------------------------------------------------------------------
# Endpoint 4: Command Injection — Ping Tool
# ---------------------------------------------------------------------------
PING_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Ping Aracı — ShopEasy</title>
<style>
body{font-family:-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;padding:40px;}
.box{max-width:700px;margin:auto;}
h1{color:#58a6ff;margin-bottom:20px;}
.form-row{display:flex;gap:10px;margin-bottom:20px;}
input{flex:1;padding:10px 14px;background:#161b22;border:1px solid #30363d;color:#c9d1d9;
       border-radius:6px;font-size:14px;}
button{padding:10px 20px;background:#238636;color:white;border:none;border-radius:6px;
        cursor:pointer;font-size:14px;}
.terminal{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;
           font-family:monospace;font-size:13px;min-height:160px;white-space:pre-wrap;}
.terminal .prompt{color:#58a6ff;} .terminal .output{color:#3fb950;}
.terminal .error{color:#f85149;} .terminal .injection{color:#e3b341;}
.warn{background:#21262d;border:1px solid #e3b341;color:#e3b341;padding:10px 14px;
       border-radius:6px;font-size:12px;margin-bottom:16px;}
</style>
</head>
<body>
<div class="box">
  <h1>🔧 Network Ping Aracı</h1>
  <div class="warn">⚠️ WAF Lab: Command injection test endpoint'i. Input sanitize edilmez.</div>
  <div class="form-row">
    <form action="/ping" style="display:flex;flex:1;gap:10px;">
      <input name="host" value="{{host}}" placeholder="Hedef: 127.0.0.1 veya google.com">
      <button type="submit">▶ Ping At</button>
    </form>
  </div>
  {% if host %}
  <div class="terminal">
<span class="prompt">$ ping -c 4 {{host}}</span>
{{output}}
  </div>
  {% else %}
  <div class="terminal">
<span class="prompt">$</span> <span style="color:#6e7681">Komut çalıştırmak için bir host girin...</span>
  </div>
  {% endif %}
  <div style="margin-top:12px;font-size:12px;color:#6e7681;">
    Örnekler: 127.0.0.1 | google.com | <code style="color:#e3b341;">127.0.0.1; id</code> | <code style="color:#e3b341;">127.0.0.1 && whoami</code>
  </div>
</div>
</body></html>"""

# Simüle edilmiş komut çıktıları
SIMULATED_OUTPUTS = {
    "id":      "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "whoami":  "www-data",
    "ls":      "app.py  requirements.txt  templates/  static/  uploads/  .env",
    "ls -la":  "total 48\ndrwxr-xr-x 5 www-data www-data 4096 Jan 15 10:23 .\n-rw-r--r-- 1 www-data www-data 18432 Jan 15 10:23 app.py\n-rw-r--r-- 1 root     root       256 Jan 10 09:00 .env",
    "cat /etc/passwd": SIMULATED_FILES["etc/passwd"],
    "uname -a":"Linux shopeasy-prod 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "env":      "PATH=/usr/local/bin:/usr/bin\nSECRET_KEY=super_secret_key_12345\nDB_PASSWORD=mysql_prod_pass\nFLASK_ENV=production",
    "pwd":      "/var/www/shopeasy",
    "hostname": "shopeasy-prod-01",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>\n  inet 10.0.1.42  netmask 255.255.255.0\n  inet6 fe80::1  prefixlen 64",
}

def simulate_ping(host: str) -> tuple[str, str]:
    """Gerçek ping ATMAZ — simüle eder. İnjection'ı tanır."""
    from markupsafe import Markup

    # Injection separator tespiti
    injections = re.split(r"(;|&&|\|\||\||\$\(|\`)", host, maxsplit=1)
    base_host = injections[0].strip()

    ping_output = (
        f"\nPING {base_host} (127.0.0.1): 56 data bytes\n"
        f"64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.432 ms\n"
        f"64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.418 ms\n"
        f"64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.441 ms\n"
        f"64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.427 ms\n\n"
        f"--- {base_host} ping statistics ---\n"
        f"4 packets transmitted, 4 received, 0% packet loss\n"
    )

    if len(injections) > 1:
        injected_cmd = "".join(injections[1:]).strip().strip(";& `$()")
        # Simüle edilmiş çıktı ara
        cmd_output = None
        for cmd, out in SIMULATED_OUTPUTS.items():
            if injected_cmd.startswith(cmd) or cmd in injected_cmd:
                cmd_output = out
                break
        if cmd_output is None:
            cmd_output = f"-bash: {injected_cmd}: command not found"

        full = (f'<span class="output">{ping_output}</span>'
                f'<span class="injection">[INJECTION EXECUTED]: $ {injected_cmd}\n{cmd_output}</span>')
        return host, Markup(full)

    return host, Markup(f'<span class="output">{ping_output}</span>')

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    output = ""
    if host:
        _, output = simulate_ping(host)
    return render_template_string(PING_PAGE, host=host, output=output)

# ---------------------------------------------------------------------------
# Endpoint 5: SSTI — Template Render
# ---------------------------------------------------------------------------
SSTI_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Template Render — ShopEasy</title>
<style>
body{font-family:-apple-system,sans-serif;background:#f8f9fa;padding:40px;}
.box{max-width:700px;margin:auto;background:white;padding:32px;border-radius:12px;
      box-shadow:0 2px 12px rgba(0,0,0,.08);}
h1{font-size:20px;color:#1a1a2e;margin-bottom:6px;}
.subtitle{color:#6c757d;font-size:13px;margin-bottom:24px;}
textarea{width:100%;height:100px;padding:12px;border:1px solid #dee2e6;border-radius:6px;
          font-family:monospace;font-size:13px;resize:vertical;}
button{padding:10px 20px;background:#1a1a2e;color:white;border:none;border-radius:6px;
        cursor:pointer;font-size:14px;margin-top:10px;}
.output-box{background:#f8f9fa;border:1px solid #dee2e6;border-radius:6px;padding:16px;
             margin-top:20px;font-family:monospace;font-size:14px;min-height:80px;}
.warn{background:#fff3cd;border:1px solid #ffc107;padding:10px 14px;border-radius:6px;
       font-size:12px;color:#856404;margin-bottom:16px;}
.label{font-size:12px;color:#6c757d;margin-bottom:6px;}
.examples{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;}
.ex-btn{background:#e9ecef;border:1px solid #dee2e6;padding:4px 10px;border-radius:4px;
         font-size:12px;cursor:pointer;color:#495057;}
</style>
</head>
<body>
<div class="box">
  <h1>📝 Template Render Servisi</h1>
  <div class="subtitle">Kullanıcı şablonlarını render eder — Hoş geldiniz mesajları için</div>
  <div class="warn">⚠️ WAF Lab: SSTI test endpoint'i. Template Jinja2 ile render edilir.</div>
  <form method="GET">
    <div class="label">Şablon girin:</div>
    <textarea name="template" placeholder="Merhaba {{user}}! Siparişiniz hazır.">{{template_input}}</textarea>
    <div class="examples">
      <span style="font-size:12px;color:#6c757d;padding:4px 0;">Hızlı örnekler:</span>
      <button type="button" class="ex-btn" onclick="document.querySelector('textarea').value='Merhaba {%raw%}{{user}}{%endraw%}!'">Normal</button>
      <button type="button" class="ex-btn" onclick="document.querySelector('textarea').value='{%raw%}{{7*7}}{%endraw%}'">Math Probe</button>
      <button type="button" class="ex-btn" onclick="document.querySelector('textarea').value='{%raw%}{{config}}{%endraw%}'">Config Leak</button>
    </div>
    <button type="submit">▶ Render Et</button>
  </form>
  {% if rendered %}
  <div style="margin-top:20px;">
    <div class="label">Render çıktısı:</div>
    <div class="output-box">{{rendered}}</div>
  </div>
  {% endif %}
</div>
</body></html>"""

@app.route("/render")
def render_template_endpoint():
    from markupsafe import Markup
    template_input = request.args.get("template", "")
    rendered = ""

    if template_input:
        # Gerçek SSTI simülasyonu — sınırlı güvenli sandbox
        # {7*7} gibi basit matematik çalışır, __subclasses__ gibi tehlikeliler engellenir
        dangerous_patterns = [
            "__class__", "__mro__", "__subclasses__", "__import__",
            "os.system", "subprocess", "open(", "exec(", "eval(",
            "request.environ", "config.SECRET",
        ]

        is_dangerous = any(dp in template_input for dp in dangerous_patterns)

        if is_dangerous:
            rendered = Markup(
                "<span style='color:red;font-weight:700;'>"
                "⛔ Tehlikeli SSTI payload tespit edildi (sandbox engelledi).<br>"
                "Ama WAF bypass başarılı — sunucuya ulaştı!</span>"
            )
        else:
            try:
                # Gerçekten render et (math probe için)
                result = app.jinja_env.from_string(template_input).render(
                    user="TestUser",
                    config_hint="[config objesi gizlendi]"
                )
                rendered = Markup(result)
            except Exception as e:
                rendered = Markup(f"<span style='color:red;'>Render hatası: {str(e)[:100]}</span>")

    return render_template_string(SSTI_PAGE,
        template_input=template_input, rendered=rendered)

# ---------------------------------------------------------------------------
# Endpoint 6: API — JSON tabanlı SQLi
# ---------------------------------------------------------------------------
@app.route("/api/data")
def api_data():
    item_id = request.args.get("id", "1")

    # Simüle edilmiş DB
    db = {
        "1": {"id": 1, "product": "Laptop Pro X", "price": 12499, "stock": 45, "internal_cost": 8200},
        "2": {"id": 2, "product": "Akıllı Telefon", "price": 8999, "stock": 120, "internal_cost": 5800},
        "3": {"id": 3, "product": "Kulaklık", "price": 1299, "stock": 340, "internal_cost": 600},
    }

    # UNION SELECT simülasyonu
    if re.search(r"(?i)union.*select", item_id):
        return jsonify({
            "status": "bypass",
            "message": "UNION SELECT bypass başarılı!",
            "leaked_data": {
                "users": [
                    {"username": "admin", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
                    {"username": "dbuser", "password_hash": "e10adc3949ba59abbe56e057f20f883e"},
                ],
                "config": {"db_host": "mysql-prod-01:3306", "secret_key": app.secret_key}
            }
        })

    # Error-based injection simülasyonu
    if re.search(r"(?i)(extractvalue|updatexml|floor\(rand)", item_id):
        return jsonify({
            "error": "XPATH syntax error: '~5.7.42-log'",
            "status": "bypass",
            "message": "Error-based injection başarılı! DB version sızdı."
        }), 500

    # Time-based blind (simüle — gerçek sleep yok)
    if re.search(r"(?i)(sleep|benchmark|pg_sleep|waitfor)", item_id):
        return jsonify({
            "status": "bypass",
            "message": "Time-based blind injection bypass başarılı! (Simüle edildi)",
            "simulated_delay": "5000ms"
        })

    # Normal sorgu
    record = db.get(str(item_id))
    if record:
        # Sadece public alanları döndür
        return jsonify({"id": record["id"], "product": record["product"], "price": record["price"]})

    return jsonify({"error": "Kayıt bulunamadı", "id": item_id}), 404

# ---------------------------------------------------------------------------
# Durum API'si — Fuzzer için
# ---------------------------------------------------------------------------
@app.route("/api/status")
def api_status():
    return jsonify({
        "server": "ShopEasy WAF Lab",
        "waf_mode": config.WAF_MODE,
        "waf_name": WAF_PROFILES.get(config.WAF_MODE, {}).get("name"),
        "rate_limit": config.RATE_LIMIT,
        "js_challenge": config.JS_CHALLENGE,
        "endpoints": ["/login", "/search", "/download", "/ping", "/render", "/api/data"],
        "timestamp": datetime.utcnow().isoformat(),
    })

# ---------------------------------------------------------------------------
# 404 / 500
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "path": request.path}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WAF Lab Server")
    parser.add_argument("--port",    type=int, default=5000,    help="Port (varsayılan: 5000)")
    parser.add_argument("--host",    default="127.0.0.1",       help="Bind adresi (varsayılan: 127.0.0.1)")
    parser.add_argument("--waf",     default="cloudflare",
                        choices=["cloudflare", "modsec", "imperva", "none"],
                        help="WAF modu (varsayılan: cloudflare)")
    parser.add_argument("--rate",    type=int, default=30,      help="Rate limit req/dk (0=kapalı)")
    parser.add_argument("--no-js",   action="store_true",       help="JS challenge'ı devre dışı bırak")
    parser.add_argument("--debug",   action="store_true",       help="WAF debug header'ları ekle")
    args = parser.parse_args()

    config.WAF_MODE     = args.waf
    config.RATE_LIMIT   = args.rate
    config.JS_CHALLENGE = not args.no_js
    config.DEBUG_MODE   = args.debug

    app.config["PORT"] = args.port

    print(f"""
╔══════════════════════════════════════════════════════╗
║         WAF Lab — Red Team Test Ortamı               ║
╠══════════════════════════════════════════════════════╣
║  Adres     : http://{args.host}:{args.port}
║  WAF Modu  : {config.WAF_MODE}
║  Rate Limit: {config.RATE_LIMIT}/dk {'(kapalı)' if config.RATE_LIMIT == 0 else ''}
║  JS Chall. : {'Açık' if config.JS_CHALLENGE else 'Kapalı'}
║  Admin     : http://{args.host}:{args.port}/admin
╠══════════════════════════════════════════════════════╣
║  Endpoint'ler:
║    /login          → SQLi (POST username/password)
║    /search?q=      → XSS (reflected)
║    /download?file= → Path Traversal
║    /ping?host=     → Command Injection
║    /render?template=→ SSTI (Jinja2)
║    /api/data?id=   → SQLi (JSON API)
╠══════════════════════════════════════════════════════╣
║  Fuzzer örneği:
║  python waf_fuzzer_v2.py \\
║    -u "http://localhost:{args.port}/search?q=FUZZ" \\
║    --context xss --no-js
╚══════════════════════════════════════════════════════╝
""")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)
