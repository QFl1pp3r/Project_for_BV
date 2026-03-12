#!/usr/bin/env python3
"""
Generate a labeled dataset for CatBoost training.

The script primarily builds a balanced synthetic dataset and can optionally
append locally available public datasets converted into access-log rows.
"""

import argparse
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from feature_engineering import extract_features
from parser import parse_line

LABELS = ["NORMAL", "SQLI", "XSS", "BRUTE_FORCE", "DOS", "ANOMALY"]
CLASS_PROFILES = {
    "balanced": {
        "NORMAL": 1.0,
        "SQLI": 1.0,
        "XSS": 1.0,
        "BRUTE_FORCE": 1.0,
        "DOS": 1.0,
        "ANOMALY": 1.0,
    },
    "realistic": {
        "NORMAL": 0.80,
        "SQLI": 0.03,
        "XSS": 0.03,
        "BRUTE_FORCE": 0.05,
        "DOS": 0.04,
        "ANOMALY": 0.05,
    },
}

UA_NORMAL = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X)",
]
UA_TOOLS = [
    "curl/8.0",
    "python-requests/2.31",
    "sqlmap/1.7",
    "XSS-Scanner/1.0",
    "Nikto/2.1.6",
    "Go-http-client/1.1",
]
PUBLIC_PAGE_PATHS = [
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
CATALOG_PATHS = [
    "/products",
    "/products?category=electronics",
    "/products?category=books",
    "/search?q=laptop",
    "/search?q=phone",
    "/api/search?q=laptop",
    "/cart",
    "/checkout",
]
API_READ_PATHS = [
    "/api/items",
    "/api/items?page=1",
    "/api/items?page=2&limit=20",
    "/api/users",
    "/api/users/me",
    "/api/search",
]
STATIC_PATHS = [
    "/static/app.js",
    "/static/site.css",
    "/images/logo.png",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
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
NORMAL_PATHS = PUBLIC_PAGE_PATHS + CATALOG_PATHS + API_READ_PATHS + STATIC_PATHS + BENIGN_EDGE_PATHS
LOGIN_PATHS = ["/login", "/admin", "/signin", "/wp-login.php", "/auth", "/auth/login", "/account/login"]
DOS_PATHS = ["/api/items", "/api/items?page=1", "/api/search", "/"]

SQLI_PAYLOADS = [
    "/products?id=1%20OR%201=1",
    "/products?id=1' OR '1'='1",
    "/api/items?search=' UNION SELECT password FROM users--",
    "/api/items?search=' UNION SELECT username,password FROM users--",
    "/index.html?q=1' AND SLEEP(2)--",
    "/products?id=1; DROP TABLE users--",
    "/api/users?name=' OR 1=1#",
    "/products?sort=name; SELECT * FROM information_schema.tables--",
    "/api/items?filter=1' UNION SELECT null,null,null--",
    "/api/data?id=1' AND BENCHMARK(5000000,MD5('test'))--",
    "/products?category=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "/api/items?q=1%27%20UNION%20SELECT%20load_file('/etc/passwd')--",
    "/api/v2/items?id=1;EXEC+xp_cmdshell('dir')",
    "/search?q=1' HAVING 1=1--",
    "/api/items?sort=1' ORDER BY 10--",
]
XSS_PAYLOADS = [
    "/search?q=<script>alert(1)</script>",
    "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/comments?text=<img src=x onerror=alert(1)>",
    "/comments?text=%3Cimg%20src=x%20onerror=alert(1)%3E",
    "/profile?name=\"><svg onload=alert(document.cookie)>",
    "/redirect?next=javascript:alert(1)",
    "/search?q=<body onload=alert('xss')>",
    "/search?q=<iframe src='javascript:alert(1)'>",
    "/comments?text=<svg/onload=alert('XSS')>",
    "/api/name?v=<details open ontoggle=alert(1)>",
    "/profile?name=<input onfocus=alert(1) autofocus>",
    "/comments?msg=<a href=javascript:alert(1)>click</a>",
    "/page?content=<div onmouseover=alert(1)>hover</div>",
]
SCAN_PATHS = [
    "/.env",
    "/wp-admin",
    "/phpmyadmin",
    "/backup.zip",
    "/config",
    "/server-status",
    "/.git/config",
    "/db.sql",
    "/admin.php",
    "/.htaccess",
    "/wp-config.php",
    "/etc/passwd",
    "/../../../etc/shadow",
    "/proc/self/environ",
    "/api/debug",
    "/console",
    "/actuator/health",
    "/swagger.json",
]


def fmt_time(ts: datetime) -> str:
    return ts.strftime("%d/%b/%Y:%H:%M:%S %z")


def make_log_line(ts: datetime, ip: str, method: str, url: str, status: int, size: int, ua: str, ref: str = "-") -> str:
    return f'{ip} - - [{fmt_time(ts)}] "{method} {url} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def _next_ts(ts: datetime, rng: random.Random, min_ms: int = 400, max_ms: int = 3500) -> datetime:
    return ts + timedelta(milliseconds=rng.randint(min_ms, max_ms))


def _class_distribution(total: int, class_profile: str) -> dict[str, int]:
    weights = CLASS_PROFILES[class_profile]
    total_weight = sum(weights[label] for label in LABELS)
    raw = {label: (total * weights[label]) / total_weight for label in LABELS}
    distribution = {label: int(raw[label]) for label in LABELS}
    remainder = total - sum(distribution.values())
    order = sorted(LABELS, key=lambda label: raw[label] - distribution[label], reverse=True)
    for label in order[:remainder]:
        distribution[label] += 1
    return distribution


def _split_count(count: int, parts: int) -> list[int]:
    base = count // parts
    remainder = count % parts
    chunks = [base] * parts
    for index in range(remainder):
        chunks[index] += 1
    return [chunk for chunk in chunks if chunk > 0]


def _diurnal_weight(hour: int) -> float:
    """Relative request rate for a given hour of day (0–23).

    Models a typical business-hours traffic pattern:
    low at night, ramp up in the morning, peak around midday, taper in the evening.
    """
    weights = [
        0.10, 0.07, 0.05, 0.04, 0.05, 0.10,  # 00-05 – night
        0.30, 0.60, 0.85, 0.95, 1.00, 1.00,  # 06-11 – morning peak
        0.95, 0.90, 0.85, 0.80, 0.75, 0.70,  # 12-17 – afternoon
        0.60, 0.50, 0.40, 0.30, 0.20, 0.15,  # 18-23 – evening wind-down
    ]
    return weights[hour % 24]


def _sample_normal_request(rng: random.Random) -> tuple[str, str, int, int, str]:
    """Sample a benign request with endpoint-aware method/status combinations."""
    profile = rng.choices(
        ["page", "catalog", "api", "static", "auth", "edge"],
        weights=[29, 19, 17, 15, 12, 8],
    )[0]

    if profile == "page":
        path = rng.choice(PUBLIC_PAGE_PATHS)
        method = rng.choices(["GET", "HEAD"], weights=[95, 5])[0]
        status = rng.choices([200, 301, 404, 500], weights=[86, 7, 5, 2])[0]
        size = rng.randint(1200, 26000)
    elif profile == "catalog":
        path = rng.choice(CATALOG_PATHS)
        method = rng.choices(["GET", "POST"], weights=[93, 7])[0]
        status = rng.choices([200, 200, 301, 404, 500], weights=[73, 12, 7, 6, 2])[0]
        size = rng.randint(500, 22000)
    elif profile == "api":
        path = rng.choice(API_READ_PATHS)
        method = rng.choices(["GET", "HEAD"], weights=[97, 3])[0]
        status = rng.choices([200, 304, 404, 500], weights=[82, 7, 8, 3])[0]
        size = rng.randint(250, 12000)
    elif profile == "static":
        path = rng.choice(STATIC_PATHS)
        method = rng.choices(["GET", "HEAD"], weights=[90, 10])[0]
        status = rng.choices([200, 304, 404], weights=[77, 18, 5])[0]
        size = rng.randint(180, 24000)
    elif profile == "auth":
        path = rng.choice(LOGIN_PATHS + ["/profile", "/checkout"])
        method = rng.choices(["GET", "POST"], weights=[58, 42])[0]
        if method == "POST":
            status = rng.choices([200, 302, 401, 403, 429], weights=[40, 28, 20, 8, 4])[0]
        else:
            status = rng.choices([200, 302, 404], weights=[82, 13, 5])[0]
        size = rng.randint(250, 9000)
    else:
        path = rng.choice(BENIGN_EDGE_PATHS)
        method = rng.choices(["GET", "POST"], weights=[90, 10])[0]
        status = rng.choices([200, 200, 301, 404], weights=[63, 17, 12, 8])[0]
        size = rng.randint(350, 14000)

    return path, method, status, size, rng.choice(UA_NORMAL)


def gen_normal_records(count: int, start_ts: datetime, ips: list[str], rng: random.Random) -> list[tuple[str, str]]:
    """Normal traffic spread diurnally across a 48-hour window starting at start_ts.

    Timestamps are drawn randomly from each hour weighted by _diurnal_weight so
    daytime hours have proportionally more requests than night hours.
    """
    hours_span = 48
    hour_weights = [_diurnal_weight(h % 24) for h in range(hours_span)]

    # Pre-generate and sort all timestamps so the returned list is time-ordered.
    offsets = sorted(
        timedelta(
            hours=rng.choices(range(hours_span), weights=hour_weights)[0],
            minutes=rng.randint(0, 59),
            seconds=rng.randint(0, 59),
        )
        for _ in range(count)
    )

    records = []
    for offset in offsets:
        ts = start_ts + offset
        path, method, status, size, ua = _sample_normal_request(rng)
        records.append(
            (
                make_log_line(ts, rng.choice(ips), method, path, status, size, ua),
                "NORMAL",
            )
        )
    return records


def gen_sqli_records(count: int, start_ts: datetime, ips: list[str], rng: random.Random) -> list[tuple[str, str]]:
    records = []
    ts = start_ts
    for _ in range(count):
        url = rng.choice(SQLI_PAYLOADS)
        status = rng.choices([200, 400, 403, 500], weights=[20, 30, 15, 35])[0]
        records.append(
            (
                make_log_line(ts, rng.choice(ips), rng.choice(["GET", "POST"]), url, status, rng.randint(120, 1800), rng.choice(UA_TOOLS)),
                "SQLI",
            )
        )
        ts = _next_ts(ts, rng, 700, 4500)
    return records


def gen_xss_records(count: int, start_ts: datetime, ips: list[str], rng: random.Random) -> list[tuple[str, str]]:
    records = []
    ts = start_ts
    for _ in range(count):
        url = rng.choice(XSS_PAYLOADS)
        status = rng.choices([200, 400, 403], weights=[50, 30, 20])[0]
        records.append(
            (
                make_log_line(ts, rng.choice(ips), rng.choice(["GET", "POST"]), url, status, rng.randint(120, 1800), rng.choice(UA_TOOLS)),
                "XSS",
            )
        )
        ts = _next_ts(ts, rng, 700, 4500)
    return records


def gen_bruteforce_records(count: int, start_ts: datetime, ips: list[str], rng: random.Random) -> list[tuple[str, str]]:
    records = []
    ts = start_ts
    remaining = count
    while remaining > 0:
        ip = rng.choice(ips)
        path = rng.choice(LOGIN_PATHS)
        burst = min(rng.randint(10, 40), remaining)
        for _ in range(burst):
            status = rng.choices([401, 403], weights=[75, 25])[0]
            records.append(
                (
                    make_log_line(ts, ip, "POST", path, status, rng.randint(200, 900), rng.choice(UA_TOOLS)),
                    "BRUTE_FORCE",
                )
            )
            ts = _next_ts(ts, rng, 50, 1200)
            remaining -= 1
        ts += timedelta(seconds=rng.randint(30, 240))
    return records


def gen_dos_records(count: int, start_ts: datetime, ips: list[str], rng: random.Random) -> list[tuple[str, str]]:
    records = []
    ts = start_ts
    remaining = count
    while remaining > 0:
        burst = min(rng.randint(250, 600), remaining)
        for _ in range(burst):
            records.append(
                (
                    make_log_line(
                        ts,
                        rng.choice(ips),
                        "GET",
                        rng.choice(DOS_PATHS),
                        rng.choices([200, 429, 500, 503, 504], weights=[55, 10, 15, 10, 10])[0],
                        rng.randint(200, 3200),
                        rng.choice(UA_NORMAL),
                    ),
                    "DOS",
                )
            )
            ts += timedelta(milliseconds=rng.randint(1, 30))
            remaining -= 1
        ts += timedelta(minutes=rng.randint(1, 5))
    return records


def gen_mixed_attack_campaign(
    count: int, start_ts: datetime, attacker_ip: str, rng: random.Random
) -> list[tuple[str, str]]:
    """Simulate a realistic multi-technique attack campaign from a single IP.

    An attacker typically probes with several methods (e.g. SQLI → XSS → recon)
    within a concentrated time window.  This function generates bursts of 2–3
    attack types interleaved within that window so the resulting log rows have
    naturally overlapping timestamps with the surrounding normal traffic.
    """
    records: list[tuple[str, str]] = []
    ts = start_ts
    remaining = count

    # Each campaign uses 2–3 attack types chosen without replacement.
    n_types = rng.randint(2, 3)
    attack_types = rng.sample(["SQLI", "XSS", "BRUTE_FORCE", "ANOMALY"], k=n_types)

    while remaining > 0:
        attack_type = rng.choice(attack_types)
        burst = min(rng.randint(3, 12), remaining)

        for _ in range(burst):
            if attack_type == "SQLI":
                url = rng.choice(SQLI_PAYLOADS)
                status = rng.choices([200, 400, 403, 500], weights=[20, 30, 15, 35])[0]
                method = rng.choice(["GET", "POST"])
                size = rng.randint(120, 1800)
            elif attack_type == "XSS":
                url = rng.choice(XSS_PAYLOADS)
                status = rng.choices([200, 400, 403], weights=[50, 30, 20])[0]
                method = rng.choice(["GET", "POST"])
                size = rng.randint(120, 1800)
            elif attack_type == "BRUTE_FORCE":
                url = rng.choice(LOGIN_PATHS)
                status = rng.choices([401, 403], weights=[75, 25])[0]
                method = "POST"
                size = rng.randint(200, 900)
            else:  # ANOMALY / recon
                url = rng.choice(SCAN_PATHS)
                status = rng.choice([400, 403, 403, 404, 500])
                method = "GET"
                size = rng.randint(80, 700)

            records.append(
                (
                    make_log_line(ts, attacker_ip, method, url, status, size, rng.choice(UA_TOOLS)),
                    attack_type,
                )
            )
            ts = _next_ts(ts, rng, 300, 4000)
            remaining -= 1

        # Brief tactical pause between attack phases (5–90 s).
        ts += timedelta(seconds=rng.randint(5, 90))

    return records


def gen_anomaly_records(count: int, start_ts: datetime, ips: list[str], rng: random.Random) -> list[tuple[str, str]]:
    records = []
    ts = start_ts
    remaining = count
    while remaining > 0:
        ip = rng.choice(ips)
        mode = rng.choice(["scan", "path_traversal", "rapid_crawl"])
        if mode == "scan":
            burst = min(rng.randint(10, 40), remaining)
            for _ in range(burst):
                path = rng.choice(SCAN_PATHS)
                if rng.random() < 0.3:
                    path = f"{path}?id={rng.randint(1, 999)}"
                records.append(
                    (
                        make_log_line(ts, ip, "GET", path, rng.choice([403, 404, 404, 500]), rng.randint(80, 700), rng.choice(UA_TOOLS)),
                        "ANOMALY",
                    )
                )
                ts = _next_ts(ts, rng, 100, 1600)
                remaining -= 1
        elif mode == "path_traversal":
            burst = min(rng.randint(5, 15), remaining)
            payloads = [
                "/../../../../etc/passwd",
                "/api/file?name=../../etc/shadow",
                "/download?path=../../../config/db.yml",
                "/static/../../proc/self/environ",
            ]
            for _ in range(burst):
                records.append(
                    (
                        make_log_line(ts, ip, "GET", rng.choice(payloads), rng.choice([400, 403, 404, 500]), rng.randint(100, 550), rng.choice(UA_TOOLS)),
                        "ANOMALY",
                    )
                )
                ts = _next_ts(ts, rng, 150, 2400)
                remaining -= 1
        else:
            burst = min(rng.randint(20, 60), remaining)
            for page in range(burst):
                records.append(
                    (
                        make_log_line(ts, ip, "GET", f"/api/items?page={page}&limit=100", 200, rng.randint(5000, 50000), rng.choice(UA_TOOLS)),
                        "ANOMALY",
                    )
                )
                ts = _next_ts(ts, rng, 40, 220)
                remaining -= 1
        ts += timedelta(minutes=rng.randint(2, 8))
    return records


def generate_synthetic_records(total: int, seed: int, class_profile: str) -> list[tuple[str, str]]:
    """Generate labelled synthetic access-log records.

    Key design decisions
    --------------------
    * Normal traffic is spread diurnally across a 48-hour window (see
      gen_normal_records / _diurnal_weight) so it is not uniform.
    * Each attack type is assigned a set of *dedicated, non-overlapping* 1-hour
      windows across the same 48-hour span.  Because the windows are staggered
      by 2 hours per type, no two attack types share a starting hour, which
      prevents artificial timestamp collisions after the final sort.
    * 25 % of non-DOS attack records are reserved for *mixed campaigns*
      (gen_mixed_attack_campaign) that interleave 2–3 attack types from a
      single IP within a short window – more representative of real attacks.
    * Records are NOT shuffled; parse_records() already sorts by timestamp.
    """
    rng = random.Random(seed)
    tz = timezone(timedelta(hours=3))
    # Use midnight as base so diurnal hour offsets map directly to wall clock.
    base_ts = datetime(2026, 1, 10, 0, 0, 0, tzinfo=tz)
    normal_ips = [f"192.168.1.{index}" for index in range(10, 90)]
    attacker_ips = [f"45.133.{rng.randint(1, 255)}.{rng.randint(1, 255)}" for _ in range(35)]
    dos_ips = [f"10.0.{rng.randint(0, 255)}.{rng.randint(2, 254)}" for _ in range(180)]
    distribution = _class_distribution(total, class_profile=class_profile)

    print("Synthetic distribution:")
    print(f"  class_profile: {class_profile}")
    for label in LABELS:
        print(f"  {label}: {distribution[label]}")

    # ── Mixed-campaign budget ────────────────────────────────────────────────
    # Reserve MIXED_FRAC of each non-DOS attack type for mixed campaigns.
    MIXED_FRAC = 0.25
    mixed_labels = ["SQLI", "XSS", "BRUTE_FORCE", "ANOMALY"]
    mixed_budget: dict[str, int] = {
        label: min(int(distribution[label] * MIXED_FRAC), distribution[label])
        for label in mixed_labels
    }

    # ── Time-window layout (hours from base_ts, 48-hour horizon) ────────────
    # Each type gets 6 windows spaced 8 h apart, staggered by 2 h between
    # types so they never share the same starting hour.
    attack_windows: dict[str, list[int]] = {
        "SQLI":        [2,  10, 18, 26, 34, 42],
        "XSS":         [4,  12, 20, 28, 36, 44],
        "BRUTE_FORCE": [6,  14, 22, 30, 38, 46],
        "DOS":         [1,   9, 17, 25, 33, 41],
        "ANOMALY":     [3,  11, 19, 27, 35, 43],
    }
    # Mixed campaigns occupy the gaps between solo windows.
    mixed_windows = [5, 8, 13, 16, 21, 24, 29, 32, 37, 40, 45, 47]

    generators = {
        "SQLI":        (gen_sqli_records, attacker_ips),
        "XSS":         (gen_xss_records, attacker_ips),
        "BRUTE_FORCE": (gen_bruteforce_records, attacker_ips),
        "DOS":         (gen_dos_records, dos_ips),
        "ANOMALY":     (gen_anomaly_records, attacker_ips),
    }

    all_records: list[tuple[str, str]] = []

    # ── 1. Normal traffic ────────────────────────────────────────────────────
    normal_rng = random.Random(seed + 500)
    normal_records = gen_normal_records(distribution["NORMAL"], base_ts, normal_ips, normal_rng)
    all_records.extend(normal_records)
    print(f"  generated {len(normal_records)} rows for NORMAL")

    # ── 2. Solo attack records in dedicated windows ──────────────────────────
    for label in ["SQLI", "XSS", "BRUTE_FORCE", "DOS", "ANOMALY"]:
        generator, ips = generators[label]
        solo_count = distribution[label] - mixed_budget.get(label, 0)
        windows = attack_windows[label]
        generated = 0
        for seg_idx, seg_size in enumerate(_split_count(solo_count, parts=len(windows))):
            class_rng = random.Random(seed + 1000 + LABELS.index(label) * 100 + seg_idx)
            # Small random jitter within the window (0–45 min) avoids all
            # segments of the same type starting on the exact same minute.
            seg_start = base_ts + timedelta(hours=windows[seg_idx], minutes=rng.randint(0, 45))
            class_records = generator(seg_size, seg_start, ips, class_rng)
            all_records.extend(class_records)
            generated += len(class_records)
        print(f"  generated {generated} rows for {label}")

    # ── 3. Mixed attack campaigns ────────────────────────────────────────────
    total_mixed = sum(mixed_budget.values())
    mixed_generated = 0
    for camp_idx, hour_offset in enumerate(mixed_windows):
        camp_size = total_mixed // len(mixed_windows)
        if camp_idx < total_mixed % len(mixed_windows):
            camp_size += 1
        if camp_size == 0:
            continue
        camp_rng = random.Random(seed + 9000 + camp_idx)
        attacker_ip = rng.choice(attacker_ips)
        camp_start = base_ts + timedelta(hours=hour_offset, minutes=rng.randint(0, 30))
        campaign_records = gen_mixed_attack_campaign(camp_size, camp_start, attacker_ip, camp_rng)
        all_records.extend(campaign_records)
        mixed_generated += len(campaign_records)
    if mixed_generated:
        print(f"  generated {mixed_generated} rows across {len(mixed_windows)} mixed campaigns")

    # parse_records() will sort everything by timestamp – no shuffle needed.
    return all_records


def _request_blocks_from_text(text: str) -> list[str]:
    blocks = []
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if current:
                blocks.append("\n".join(current))
                current = []
            continue
        current.append(stripped)
    if current:
        blocks.append("\n".join(current))
    return blocks


def _label_from_request_text(text: str, default: str) -> str:
    lowered = text.lower()
    if any(token in lowered for token in ["union select", " or 1=1", "sleep(", "information_schema"]):
        return "SQLI"
    if any(token in lowered for token in ["<script", "javascript:", "onerror=", "onload=", "alert("]):
        return "XSS"
    if any(token in lowered for token in ["../", "/etc/passwd", "/.env", "/phpmyadmin", "/wp-admin"]):
        return "ANOMALY"
    return default


def load_csic_records(csic_dir: str, seed: int) -> list[tuple[str, str]]:
    root = Path(csic_dir)
    if not root.exists():
        raise FileNotFoundError(f"CSIC directory not found: {csic_dir}")

    rng = random.Random(seed)
    tz = timezone(timedelta(hours=3))
    ts = datetime(2026, 1, 20, 9, 0, 0, tzinfo=tz)
    records: list[tuple[str, str]] = []

    for txt_file in sorted(root.rglob("*.txt")):
        default_label = "NORMAL" if "normal" in txt_file.name.lower() else "ANOMALY"
        content = txt_file.read_text(encoding="utf-8", errors="ignore")
        for block in _request_blocks_from_text(content):
            request_line = block.splitlines()[0]
            parts = request_line.split()
            if len(parts) < 2:
                continue
            method = parts[0].upper()
            path = parts[1]
            label = _label_from_request_text(block, default_label)
            if label == "NORMAL":
                status = rng.choice([200, 200, 301, 304])
            elif label == "SQLI":
                status = rng.choice([400, 403, 500])
            elif label == "XSS":
                status = rng.choice([200, 400, 403])
            else:
                status = rng.choice([400, 403, 404, 500])

            records.append(
                (
                    make_log_line(ts, f"172.16.{rng.randint(0, 255)}.{rng.randint(2, 254)}", method, path, status, rng.randint(100, 2500), rng.choice(UA_TOOLS + UA_NORMAL)),
                    label,
                )
            )
            ts = _next_ts(ts, rng, 150, 3500)

    print(f"Loaded {len(records)} CSIC-derived rows from {csic_dir}")
    return records


def load_cicids_records(cic_csv: str, seed: int) -> list[tuple[str, str]]:
    path = Path(cic_csv)
    if not path.exists():
        raise FileNotFoundError(f"CICIDS CSV not found: {cic_csv}")

    rng = random.Random(seed)
    df = pd.read_csv(path)
    label_col = next((column for column in df.columns if column.lower() == "label"), None)
    ip_col = next((column for column in df.columns if column.lower() in {"src ip", "source ip"}), None)
    if label_col is None:
        raise ValueError("CICIDS CSV must contain a Label column.")

    records: list[tuple[str, str]] = []
    tz = timezone(timedelta(hours=3))
    ts = datetime(2026, 1, 22, 8, 0, 0, tzinfo=tz)
    for _, row in df.iterrows():
        raw_label = str(row[label_col]).lower()
        if "benign" in raw_label:
            label = "NORMAL"
            method = "GET"
            path_value = rng.choice(NORMAL_PATHS)
            status = rng.choice([200, 200, 301, 304])
        elif "brute" in raw_label:
            label = "BRUTE_FORCE"
            method = "POST"
            path_value = rng.choice(LOGIN_PATHS)
            status = rng.choice([401, 403])
        elif "dos" in raw_label or "ddos" in raw_label or "slowloris" in raw_label:
            label = "DOS"
            method = "GET"
            path_value = rng.choice(DOS_PATHS)
            status = rng.choice([200, 429, 500, 503])
        else:
            label = "ANOMALY"
            method = "GET"
            path_value = rng.choice(SCAN_PATHS)
            status = rng.choice([400, 403, 404, 500])

        ip = str(row[ip_col]) if ip_col else f"10.10.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
        records.append(
            (
                make_log_line(ts, ip, method, path_value, status, rng.randint(100, 3000), rng.choice(UA_TOOLS + UA_NORMAL)),
                label,
            )
        )
        ts = _next_ts(ts, rng, 30, 1500)

    print(f"Loaded {len(records)} CICIDS-derived rows from {cic_csv}")
    return records


def parse_records(records: list[tuple[str, str]]) -> pd.DataFrame:
    parsed_rows = []
    labels = []
    for line, label in records:
        parsed = parse_line(line)
        if not parsed:
            continue
        parsed_rows.append(parsed)
        labels.append(label)

    if not parsed_rows:
        raise RuntimeError("No records could be parsed into access-log rows.")

    df = pd.DataFrame(parsed_rows)
    df["label"] = labels
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)
    return df


def generate_dataset(
    total: int = 120000,
    seed: int = 42,
    class_profile: str = "realistic",
    csic_dir: Optional[str] = None,
    cic_csv: Optional[str] = None,
) -> pd.DataFrame:
    print(f"Generating synthetic dataset with {total} rows")
    records = generate_synthetic_records(total=total, seed=seed, class_profile=class_profile)
    if csic_dir:
        records.extend(load_csic_records(csic_dir, seed + 5000))
    if cic_csv:
        records.extend(load_cicids_records(cic_csv, seed + 6000))

    df = parse_records(records)
    print(f"Parsed rows: {len(df)}")

    features = extract_features(df)
    features["split_group"] = df["ts"].dt.floor("30min").dt.strftime("%Y-%m-%dT%H:%M:%S%z")
    features["label"] = df["label"].astype(str)
    print("Label distribution:")
    print(features["label"].value_counts().sort_index())
    return features


def main():
    parser = argparse.ArgumentParser(description="Generate a labeled HTTP access-log dataset")
    parser.add_argument("--output", default="data/dataset.csv", help="Output CSV path")
    parser.add_argument("--total", type=int, default=120000, help="Synthetic row count")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--class-profile",
        choices=sorted(CLASS_PROFILES),
        default="realistic",
        help="Class prior profile for synthetic data (default: realistic)",
    )
    parser.add_argument("--csic-dir", default=None, help="Optional local CSIC dataset directory")
    parser.add_argument("--cic-csv", default=None, help="Optional local CICIDS CSV path")
    args = parser.parse_args()

    dataset = generate_dataset(
        total=args.total,
        seed=args.seed,
        class_profile=args.class_profile,
        csic_dir=args.csic_dir,
        cic_csv=args.cic_csv,
    )
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    dataset.to_csv(args.output, index=False)
    size_mb = os.path.getsize(args.output) / 1024 / 1024
    print(f"Saved dataset to {args.output} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
