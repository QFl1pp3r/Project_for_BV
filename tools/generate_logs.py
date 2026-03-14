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

  # Multi-stage campaign (brute-force → SQLi → XSS):
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
  sqli        SQL Injection probing
  xss         Cross-Site Scripting probing
  dos         Denial-of-Service flood
  mixed       All selected attacks at random times (default: all four)
  campaign    Realistic multi-stage attack: brute-force → SQLi → XSS

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
  --sqli-count   number of SQLi requests
  --xss-count    number of XSS requests
  --dos-seconds  DoS flood duration (s)
  --dos-rps      DoS requests-per-second
"""

from __future__ import annotations

import argparse
import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.data_for_generators import (
    UA_NORMAL, UA_TOOLS, UA_BOTS,
    PUBLIC_PAGE_PATHS, CATALOG_PATHS, API_READ_PATHS,
    STATIC_PATHS, AUTH_FLOW_PATHS, BENIGN_EDGE_PATHS,
    LOGIN_PATHS,
    SQLI_PAYLOADS, XSS_PAYLOADS,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Number of distributed IPs generated for DoS flooding.
_DOS_POOL_SIZE = 150

# Maximum iterations for _pick_spread_times() before falling back to even spacing.
_RETRY_LIMIT = 1000

# Profile sampling weights for _pick_normal_request().
_LOG_PROFILE_WEIGHTS: dict[str, int] = {
    "page": 28, "catalog": 20, "api": 17,
    "static": 15, "auth": 12, "edge": 8,
}

# Maps each attack mode to a function that estimates its duration in seconds
# from the intensity preset.  Used by _estimate_duration() and single-attack
# mode in main() to calculate how long the total log window should be.
_ATTACK_DURATION_ESTIMATORS: dict[str, object] = {
    "bruteforce": lambda p: p["bf_seconds"],
    "sqli":       lambda p: p["sqli_count"] * 8,
    "xss":        lambda p: p["xss_count"] * 5,
    "dos":        lambda p: p["dos_seconds"],
}

ALL_ATTACKS: list[str] = ["bruteforce", "sqli", "xss", "dos"]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fmt_time(ts: datetime) -> str:
    """Format a datetime into CLF (Common Log Format) timestamp."""
    return ts.strftime("%d/%b/%Y:%H:%M:%S %z")


def _parse_ts(line: str) -> datetime:
    """Extract and parse the CLF timestamp from a log line."""
    s = line.index("[") + 1
    e = line.index("]")
    return datetime.strptime(line[s:e], "%d/%b/%Y:%H:%M:%S %z")


def _make_line_combined(
    ts: datetime,
    ip: str,
    method: str,
    url: str,
    status: int,
    size: int,
    ua: str,
    ref: str = "-",
) -> str:
    """Build a single Combined Log Format line."""
    return (
        f'{ip} - - [{_fmt_time(ts)}] '
        f'"{method} {url} HTTP/1.1" {status} {size} "{ref}" "{ua}"'
    )


def _make_line_common(
    ts: datetime,
    ip: str,
    method: str,
    url: str,
    status: int,
    size: int,
) -> str:
    """Build a single Common Log Format line (no UA / Referer)."""
    return f'{ip} - - [{_fmt_time(ts)}] "{method} {url} HTTP/1.1" {status} {size}'


def _emit_line(
    fmt: str,
    ts: datetime,
    ip: str,
    method: str,
    url: str,
    status: int,
    size: int,
    ua: str | None = None,
) -> str:
    """Build a log line in the requested format, with an optional UA override."""
    if fmt == "combined":
        return _make_line_combined(ts, ip, method, url, status, size, ua or random.choice(UA_NORMAL))
    if fmt == "common":
        return _make_line_common(ts, ip, method, url, status, size)
    raise ValueError(f"Unknown format: {fmt!r}")


def _ms(low: int, high: int) -> timedelta:
    """Return a random timedelta between *low* and *high* milliseconds."""
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


def _pick_spread_times(
    n: int,
    zone_start_s: int,
    zone_end_s: int,
    min_gap_s: int = 60,
) -> list[int]:
    """Return *n* sorted random offsets in [zone_start_s, zone_end_s] with *min_gap_s* spacing."""
    span = zone_end_s - zone_start_s
    if span <= 0 or n <= 0:
        return []
    for _ in range(_RETRY_LIMIT):
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

INTENSITY_PRESETS: dict[str, dict] = {
    "low": dict(
        bf_seconds=30, sqli_count=5, xss_count=5, dos_seconds=5, dos_rps=210,
        bf_burst_range=(3, 8), bf_gap_ms=(2000, 12000),
        sqli_delay_ms=(3000, 10000), xss_delay_ms=(2000, 8000),
    ),
    "medium": dict(
        bf_seconds=90, sqli_count=15, xss_count=15, dos_seconds=20, dos_rps=350,
        bf_burst_range=(5, 20), bf_gap_ms=(1000, 8000),
        sqli_delay_ms=(1000, 8000), xss_delay_ms=(500, 5000),
    ),
    "high": dict(
        bf_seconds=180, sqli_count=40, xss_count=40, dos_seconds=40, dos_rps=600,
        bf_burst_range=(15, 50), bf_gap_ms=(200, 2000),
        sqli_delay_ms=(200, 2000), xss_delay_ms=(100, 1500),
    ),
}


# ---------------------------------------------------------------------------
# Traffic generators
# ---------------------------------------------------------------------------

def _pick_normal_request() -> tuple[str, str, int, int, str, str]:
    """Sample a benign request with endpoint-aware method/status combinations.

    Returns ``(path, method, status, size, user_agent, referer)``.
    """
    referers = ["-", "https://google.com/", "https://bing.com/", "https://t.co/x", "-", "-"]
    profile = random.choices(
        list(_LOG_PROFILE_WEIGHTS.keys()),
        weights=list(_LOG_PROFILE_WEIGHTS.values()),
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


def normal_traffic(
    lines: list[str],
    fmt: str,
    start_ts: datetime,
    seconds: int,
    ips: list[str],
) -> datetime:
    """Append realistic background traffic to *lines* over *seconds* of wall time.

    Returns the timestamp just past the last emitted line.
    """
    ts = start_ts
    end_ts = start_ts + timedelta(seconds=seconds)
    while ts < end_ts:
        ip = random.choice(ips)
        path, method, status, size, ua, ref = _pick_normal_request()
        if fmt == "combined":
            lines.append(_make_line_combined(ts, ip, method, path, status, size, ua, ref))
        else:
            lines.append(_make_line_common(ts, ip, method, path, status, size))
        ts += _ms(300, 5000)
    return ts


# ---------------------------------------------------------------------------
# Attack generators
# ---------------------------------------------------------------------------

def attack_bruteforce(
    lines: list[str],
    fmt: str,
    start_ts: datetime,
    seconds: int,
    ips: list[str],
    *,
    burst_range: tuple[int, int] = (5, 20),
    gap_ms: tuple[int, int] = (1000, 8000),
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
            lines.append(_emit_line(fmt, ts, ip, "POST", path, status, size, random.choice(UA_TOOLS[:6])))
            ts += _ms(30, 500)
        ts += _ms(*gap_ms)
    return ts


def attack_sqli(
    lines: list[str],
    fmt: str,
    start_ts: datetime,
    count: int,
    ips: list[str],
    *,
    delay_ms: tuple[int, int] = (1000, 8000),
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
        lines.append(_emit_line(fmt, ts, ip, method, url, status, size, ua))
        ts += _ms(*delay_ms)
    return ts


def attack_xss(
    lines: list[str],
    fmt: str,
    start_ts: datetime,
    count: int,
    ips: list[str],
    *,
    delay_ms: tuple[int, int] = (500, 5000),
) -> datetime:
    """XSS probing against unsanitised reflection points."""
    ts = start_ts
    for _ in range(count):
        ip = random.choice(ips)
        url = random.choice(XSS_PAYLOADS)
        method = random.choices(["GET", "POST"], weights=[75, 25])[0]
        status = random.choices([200, 400, 403, 500], weights=[45, 25, 20, 10])[0]
        size = random.randint(100, 2000)
        ua = random.choices(UA_TOOLS[3:5] + UA_NORMAL[:2], weights=[40, 40, 10, 10])[0]
        lines.append(_emit_line(fmt, ts, ip, method, url, status, size, ua))
        ts += _ms(*delay_ms)
    return ts


def attack_dos(
    lines: list[str],
    fmt: str,
    start_ts: datetime,
    seconds: int,
    rps: int,
    ips: list[str],
) -> datetime:
    """DoS/DDoS flood: very high rate from a pool of IPs."""
    ts = start_ts
    total = seconds * rps
    step_ms = max(1, int(1000 / max(1, rps)))
    dos_paths = ["/api/items", "/api/search", "/api/items?page=1", "/", "/api/users"]
    for _ in range(total):
        ip = random.choice(ips)
        url = random.choice(dos_paths)
        status = random.choices([200, 429, 500, 503, 504], weights=[40, 20, 15, 15, 10])[0]
        size = random.randint(200, 3000)
        lines.append(_emit_line(fmt, ts, ip, "GET", url, status, size, random.choice(UA_NORMAL)))
        ts += _ms(1, max(2, step_ms))
    return ts


def attack_campaign(
    lines: list[str],
    fmt: str,
    start_ts: datetime,
    attacker_ip: str,
    preset: dict,
) -> datetime:
    """Multi-stage attack campaign from a single IP.

    Stages (with realistic delays between them):
      1. Brute     — credential stuffing on login panel
      2. SQLi      — injection probing on found endpoints
      3. XSS       — reflected XSS on search/form parameters
    """
    ts = start_ts
    stage_gap = timedelta(seconds=random.randint(30, 120))

    print(f"[campaign] Stage 1: Brute-force from {attacker_ip}", file=sys.stderr)
    ts = attack_bruteforce(lines, fmt, ts, preset["bf_seconds"] // 2, [attacker_ip],
                           burst_range=preset["bf_burst_range"],
                           gap_ms=preset["bf_gap_ms"])
    ts += stage_gap

    print(f"[campaign] Stage 2: SQLi from {attacker_ip}", file=sys.stderr)
    ts = attack_sqli(lines, fmt, ts, preset["sqli_count"] // 2, [attacker_ip],
                     delay_ms=preset["sqli_delay_ms"])
    ts += stage_gap

    print(f"[campaign] Stage 3: XSS from {attacker_ip}", file=sys.stderr)
    ts = attack_xss(lines, fmt, ts, preset["xss_count"] // 2, [attacker_ip],
                    delay_ms=preset["xss_delay_ms"])
    return ts


# ---------------------------------------------------------------------------
# Main dispatch helpers
# ---------------------------------------------------------------------------

def _parse_attacks(attacks_str: str | None) -> list[str]:
    """Parse a comma-separated attack list from the CLI, falling back to all attacks."""
    if attacks_str is None:
        return list(ALL_ATTACKS)
    chosen = [a.strip().lower() for a in attacks_str.split(",")]
    invalid = [a for a in chosen if a not in ALL_ATTACKS]
    if invalid:
        print(f"[warn] Unknown attack types ignored: {invalid}", file=sys.stderr)
    return [a for a in chosen if a in ALL_ATTACKS] or list(ALL_ATTACKS)


def _estimate_duration(attacks: list[str], preset: dict) -> int:
    """Estimate total duration (seconds) for a list of attacks under *preset*."""
    dur = 0
    for a in attacks:
        estimator = _ATTACK_DURATION_ESTIMATORS.get(a)
        dur += estimator(preset) if estimator else 60
    return dur


def _run_single(
    lines: list[str],
    fmt: str,
    attack_type: str,
    ts: datetime,
    attacker_ips: list[str],
    preset: dict,
    dos_pool: list[str],
) -> None:
    """Dispatch a single attack type into *lines* starting at *ts*."""
    if attack_type == "bruteforce":
        attack_bruteforce(lines, fmt, ts, preset["bf_seconds"], attacker_ips,
                          burst_range=preset["bf_burst_range"], gap_ms=preset["bf_gap_ms"])
    elif attack_type == "sqli":
        attack_sqli(lines, fmt, ts, preset["sqli_count"], attacker_ips,
                    delay_ms=preset["sqli_delay_ms"])
    elif attack_type == "xss":
        attack_xss(lines, fmt, ts, preset["xss_count"], attacker_ips,
                   delay_ms=preset["xss_delay_ms"])
    elif attack_type == "dos":
        attack_dos(lines, fmt, ts, preset["dos_seconds"], preset["dos_rps"], dos_pool)


def _output(lines: list[str], path: str | None) -> None:
    """Write *lines* to a file at *path*, or to stdout if *path* is ``None``."""
    text = "\n".join(lines)
    if path:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"[info] Written {len(lines)} lines → {path}", file=sys.stderr)
    else:
        print(text)


# ---------------------------------------------------------------------------
# Mode handlers (called from main)
# ---------------------------------------------------------------------------

def _handle_normal_mode(
    args: argparse.Namespace,
    fmt: str,
    normal_ips: list[str],
) -> list[str]:
    """Generate normal-only traffic."""
    lines: list[str] = []
    tz = timezone(timedelta(hours=args.tz))
    start = datetime.now(tz) - timedelta(minutes=args.warmup_min)
    normal_traffic(lines, fmt, start, args.warmup_min * 60, normal_ips)
    return lines


def _handle_campaign_mode(
    args: argparse.Namespace,
    fmt: str,
    normal_ips: list[str],
    attacker_pool: list[str],
    preset: dict,
) -> list[str]:
    """Generate a multi-stage campaign with background normal traffic."""
    lines: list[str] = []
    tz = timezone(timedelta(hours=args.tz))
    camp_dur_s = (
        preset["bf_seconds"] // 2 + preset["sqli_count"] * 5
        + preset["xss_count"] * 3 + 600
    )
    total_s = args.warmup_min * 60 + camp_dur_s + args.tail_min * 60
    start = datetime.now(tz) - timedelta(seconds=total_s)
    normal_traffic(lines, fmt, start, total_s, normal_ips)
    camp_start = start + timedelta(minutes=args.warmup_min)
    attacker_ip = random.choice(attacker_pool)
    attack_campaign(lines, fmt, camp_start, attacker_ip, preset)
    lines.sort(key=_parse_ts)
    return lines


def _handle_single_attack_mode(
    args: argparse.Namespace,
    fmt: str,
    normal_ips: list[str],
    attacker_pool: list[str],
    preset: dict,
    dos_pool: list[str],
) -> list[str]:
    """Generate a single attack type with surrounding normal traffic."""
    lines: list[str] = []
    tz = timezone(timedelta(hours=args.tz))
    attack_dur_s = _ATTACK_DURATION_ESTIMATORS[args.mode](preset)
    total_s = args.warmup_min * 60 + attack_dur_s + args.tail_min * 60 + 120
    start = datetime.now(tz) - timedelta(seconds=total_s)
    normal_traffic(lines, fmt, start, total_s, normal_ips)
    attack_offset = random.randint(
        args.warmup_min * 60,
        max(args.warmup_min * 60 + 1, total_s - args.tail_min * 60 - attack_dur_s),
    )
    attack_ts = start + timedelta(seconds=attack_offset)
    ip = random.choice(attacker_pool)
    _run_single(lines, fmt, args.mode, attack_ts, [ip], preset, dos_pool)
    lines.sort(key=_parse_ts)
    return lines


def _handle_mixed_mode(
    args: argparse.Namespace,
    fmt: str,
    normal_ips: list[str],
    attacker_pool: list[str],
    preset: dict,
    dos_pool: list[str],
) -> list[str]:
    """Generate multiple attack types at random times with background traffic."""
    lines: list[str] = []
    tz = timezone(timedelta(hours=args.tz))
    chosen = _parse_attacks(args.attacks)
    attack_dur_s = _estimate_duration(chosen, preset)
    total_s = args.warmup_min * 60 + args.tail_min * 60 + attack_dur_s + 600
    start = datetime.now(tz) - timedelta(seconds=total_s)
    normal_traffic(lines, fmt, start, total_s, normal_ips)

    zone_start = args.warmup_min * 60
    zone_end = total_s - args.tail_min * 60 - 30
    offsets = _pick_spread_times(len(chosen), zone_start, zone_end, min_gap_s=60)
    random.shuffle(chosen)

    for attack_type, offset in zip(chosen, offsets):
        attack_ts = start + timedelta(seconds=offset)
        ip = random.choice(attacker_pool)
        pool = dos_pool if attack_type == "dos" else [ip]
        _run_single(lines, fmt, attack_type, attack_ts, pool, preset, dos_pool)

    lines.sort(key=_parse_ts)
    return lines


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments and generate the requested access-log output."""
    ap = argparse.ArgumentParser(
        description="HTTP access-log generator with configurable attack scenarios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    ap.add_argument("--format", choices=["combined", "common"], default="combined",
                    help="Log format (default: combined)")
    ap.add_argument("--mode",
                    choices=["normal", "bruteforce", "sqli", "xss", "dos", "mixed", "campaign"],
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
    ap.add_argument("--sqli-count", type=int, default=None)
    ap.add_argument("--xss-count", type=int, default=None)
    ap.add_argument("--dos-seconds", type=int, default=None)
    ap.add_argument("--dos-rps", type=int, default=None)

    args = ap.parse_args()
    random.seed(args.seed)

    # --- Apply intensity preset, then apply CLI overrides ---
    preset = dict(INTENSITY_PRESETS[args.intensity])
    for key, attr in [
        ("bf_seconds", "bf_seconds"),
        ("sqli_count", "sqli_count"),
        ("xss_count", "xss_count"),
        ("dos_seconds", "dos_seconds"),
        ("dos_rps", "dos_rps"),
    ]:
        val = getattr(args, attr)
        if val is not None:
            preset[key] = val

    # --- Build IP pools ---
    normal_ips = [f"192.168.{random.randint(1, 5)}.{i}" for i in range(10, 70)]

    if args.attackers == 1:
        attacker_pool = ["45.133.12.77"]
    else:
        attacker_pool = [_random_public_ip() for _ in range(args.attackers)]
        print(f"[info] Attacker IPs: {attacker_pool}", file=sys.stderr)

    dos_pool = [_random_public_ip() for _ in range(_DOS_POOL_SIZE)]

    # --- Dispatch to mode handler ---
    fmt = args.format

    if args.mode == "normal":
        lines = _handle_normal_mode(args, fmt, normal_ips)
    elif args.mode == "campaign":
        lines = _handle_campaign_mode(args, fmt, normal_ips, attacker_pool, preset)
    elif args.mode != "mixed":
        lines = _handle_single_attack_mode(args, fmt, normal_ips, attacker_pool, preset, dos_pool)
    else:
        lines = _handle_mixed_mode(args, fmt, normal_ips, attacker_pool, preset, dos_pool)

    _output(lines, args.output)


if __name__ == "__main__":
    main()
