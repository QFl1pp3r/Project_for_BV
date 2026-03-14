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
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import ATTACK_LABELS
from core.feature_engineering import extract_features
from core.parser import parse_line

from tools.data_for_generators import (
    UA_NORMAL, UA_TOOLS, UA_BOTS,
    PUBLIC_PAGE_PATHS, CATALOG_PATHS, API_READ_PATHS,
    STATIC_PATHS, BENIGN_EDGE_PATHS, NORMAL_PATHS,
    LOGIN_PATHS, DOS_PATHS, SQLI_PAYLOADS, XSS_PAYLOADS,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LABELS = list(ATTACK_LABELS)

CLASS_PROFILES: dict[str, dict[str, float]] = {
    "balanced": {
        "NORMAL": 1.0,
        "SQLI": 1.0,
        "XSS": 1.0,
        "BRUTE_FORCE": 1.0,
        "DOS": 1.0,
    },
    "realistic": {
        "NORMAL": 0.85,
        "SQLI": 0.03,
        "XSS": 0.03,
        "BRUTE_FORCE": 0.05,
        "DOS": 0.04,
    },
}

# Profile sampling weights for _sample_normal_request().
_NORMAL_PROFILE_WEIGHTS: dict[str, int] = {
    "page": 24, "catalog": 16, "api": 14, "static": 12,
    "auth": 10, "edge": 10, "bot": 8, "api_pagination": 6,
}

# RNG seed offsets used in generate_synthetic_records() to isolate
# each generator's random stream from the master RNG.
_SEED_OFFSET_NORMAL = 500
_SEED_OFFSET_SOLO = 1000
_SEED_OFFSET_MIXED = 9000

# Fraction of each non-DOS attack type reserved for mixed campaigns.
_MIXED_CAMPAIGN_FRACTION = 0.25

# Normal traffic is spread across this many hours starting at base_ts.
_DIURNAL_SPAN_HOURS = 48


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fmt_time(ts: datetime) -> str:
    """Format a datetime into CLF (Common Log Format) timestamp."""
    return ts.strftime("%d/%b/%Y:%H:%M:%S %z")


def _make_log_line(
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


def _next_ts(
    ts: datetime,
    rng: random.Random,
    min_ms: int = 400,
    max_ms: int = 3500,
) -> datetime:
    """Advance *ts* by a random millisecond interval."""
    return ts + timedelta(milliseconds=rng.randint(min_ms, max_ms))


# ---------------------------------------------------------------------------
# Distribution & splitting helpers
# ---------------------------------------------------------------------------

def _class_distribution(total: int, class_profile: str) -> dict[str, int]:
    """Compute per-class row counts for *total* rows using the named profile.

    Applies largest-remainder rounding so the counts sum to *total* exactly.
    """
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
    """Divide *count* into *parts* roughly-equal integer chunks."""
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


# ---------------------------------------------------------------------------
# Request sampling
# ---------------------------------------------------------------------------

def _sample_normal_request(rng: random.Random) -> tuple[str, str, int, int, str]:
    """Sample a benign request with endpoint-aware method/status combinations.

    Returns ``(path, method, status, size, user_agent)``.
    """
    profile = rng.choices(
        list(_NORMAL_PROFILE_WEIGHTS.keys()),
        weights=list(_NORMAL_PROFILE_WEIGHTS.values()),
    )[0]

    if profile == "page":
        path = rng.choice(PUBLIC_PAGE_PATHS)
        method = rng.choices(["GET", "HEAD"], weights=[95, 5])[0]
        status = rng.choices([200, 301, 404, 500], weights=[86, 7, 5, 2])[0]
        size = rng.randint(1200, 26000)
        ua = rng.choice(UA_NORMAL)
    elif profile == "catalog":
        path = rng.choice(CATALOG_PATHS)
        method = rng.choices(["GET", "POST"], weights=[93, 7])[0]
        status = rng.choices([200, 200, 301, 404, 500], weights=[73, 12, 7, 6, 2])[0]
        size = rng.randint(500, 22000)
        ua = rng.choice(UA_NORMAL)
    elif profile == "api":
        path = rng.choice(API_READ_PATHS)
        method = rng.choices(["GET", "HEAD"], weights=[97, 3])[0]
        status = rng.choices([200, 304, 404, 500], weights=[82, 7, 8, 3])[0]
        size = rng.randint(250, 12000)
        ua = rng.choice(UA_NORMAL)
    elif profile == "static":
        path = rng.choice(STATIC_PATHS)
        method = rng.choices(["GET", "HEAD"], weights=[90, 10])[0]
        status = rng.choices([200, 304, 404], weights=[77, 18, 5])[0]
        size = rng.randint(180, 24000)
        ua = rng.choice(UA_NORMAL)
    elif profile == "auth":
        path = rng.choice(list(LOGIN_PATHS) + ["/profile", "/checkout"])
        method = rng.choices(["GET", "POST"], weights=[58, 42])[0]
        if method == "POST":
            status = rng.choices([200, 302, 401, 403, 429], weights=[40, 28, 20, 8, 4])[0]
        else:
            status = rng.choices([200, 302, 404], weights=[82, 13, 5])[0]
        size = rng.randint(250, 9000)
        ua = rng.choice(UA_NORMAL)
    elif profile == "bot":
        # Legitimate bot/crawler traffic — hits many paths including admin-like ones
        all_crawlable = PUBLIC_PAGE_PATHS + CATALOG_PATHS + API_READ_PATHS + [
            "/admin", "/admin/login", "/config/public", "/health", "/status",
            "/actuator/info", "/server-status", "/robots.txt", "/sitemap.xml",
        ]
        path = rng.choice(all_crawlable)
        method = "GET"
        status = rng.choices([200, 301, 304, 404], weights=[70, 12, 10, 8])[0]
        size = rng.randint(200, 18000)
        ua = rng.choice(UA_BOTS)
    elif profile == "api_pagination":
        # Legitimate sequential API pagination
        page = rng.randint(1, 50)
        limit = rng.choice([10, 20, 50, 100])
        path = f"/api/items?page={page}&limit={limit}"
        method = "GET"
        status = rng.choices([200, 200, 304], weights=[80, 12, 8])[0]
        size = rng.randint(2000, 50000)
        ua = rng.choice(UA_NORMAL)
    else:
        path = rng.choice(BENIGN_EDGE_PATHS)
        method = rng.choices(["GET", "POST"], weights=[90, 10])[0]
        status = rng.choices([200, 200, 301, 404], weights=[63, 17, 12, 8])[0]
        size = rng.randint(350, 14000)
        ua = rng.choice(UA_NORMAL)

    return path, method, status, size, ua


# ---------------------------------------------------------------------------
# Per-class record generators
# ---------------------------------------------------------------------------

def gen_normal_records(
    count: int,
    start_ts: datetime,
    ips: list[str],
    rng: random.Random,
) -> list[tuple[str, str]]:
    """Normal traffic spread diurnally across a 48-hour window starting at *start_ts*.

    Timestamps are drawn randomly from each hour weighted by :func:`_diurnal_weight`
    so daytime hours have proportionally more requests than night hours.
    """
    hour_weights = [_diurnal_weight(h % 24) for h in range(_DIURNAL_SPAN_HOURS)]

    # Pre-generate and sort all timestamps so the returned list is time-ordered.
    offsets = sorted(
        timedelta(
            hours=rng.choices(range(_DIURNAL_SPAN_HOURS), weights=hour_weights)[0],
            minutes=rng.randint(0, 59),
            seconds=rng.randint(0, 59),
        )
        for _ in range(count)
    )

    records: list[tuple[str, str]] = []
    for offset in offsets:
        ts = start_ts + offset
        path, method, status, size, ua = _sample_normal_request(rng)
        records.append(
            (
                _make_log_line(ts, rng.choice(ips), method, path, status, size, ua),
                "NORMAL",
            )
        )
    return records


def gen_sqli_records(
    count: int,
    start_ts: datetime,
    ips: list[str],
    rng: random.Random,
) -> list[tuple[str, str]]:
    """Generate SQL-injection attack records.

    Each request uses a random SQLi payload URL with error-heavy status codes.
    20 % of requests use normal browser UAs to simulate manual testing.
    """
    records: list[tuple[str, str]] = []
    ts = start_ts
    for _ in range(count):
        url = rng.choice(SQLI_PAYLOADS)
        status = rng.choices([200, 400, 403, 500], weights=[20, 30, 15, 35])[0]
        ua = rng.choice(UA_NORMAL) if rng.random() < 0.2 else rng.choice(UA_TOOLS)
        records.append(
            (
                _make_log_line(ts, rng.choice(ips), rng.choice(["GET", "POST"]), url, status, rng.randint(120, 1800), ua),
                "SQLI",
            )
        )
        ts = _next_ts(ts, rng, 700, 4500)
    return records


def gen_xss_records(
    count: int,
    start_ts: datetime,
    ips: list[str],
    rng: random.Random,
) -> list[tuple[str, str]]:
    """Generate cross-site scripting attack records.

    Each request uses a random XSS payload URL.  20 % of requests use normal
    browser UAs to simulate manual testing.
    """
    records: list[tuple[str, str]] = []
    ts = start_ts
    for _ in range(count):
        url = rng.choice(XSS_PAYLOADS)
        status = rng.choices([200, 400, 403], weights=[50, 30, 20])[0]
        ua = rng.choice(UA_NORMAL) if rng.random() < 0.2 else rng.choice(UA_TOOLS)
        records.append(
            (
                _make_log_line(ts, rng.choice(ips), rng.choice(["GET", "POST"]), url, status, rng.randint(120, 1800), ua),
                "XSS",
            )
        )
        ts = _next_ts(ts, rng, 700, 4500)
    return records


def gen_bruteforce_records(
    count: int,
    start_ts: datetime,
    ips: list[str],
    rng: random.Random,
) -> list[tuple[str, str]]:
    """Generate brute-force login attack records.

    Requests arrive in rapid bursts (10–40 attempts each) separated by short
    pauses, mimicking credential-stuffing tools.
    """
    records: list[tuple[str, str]] = []
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
                    _make_log_line(ts, ip, "POST", path, status, rng.randint(200, 900), rng.choice(UA_TOOLS)),
                    "BRUTE_FORCE",
                )
            )
            ts = _next_ts(ts, rng, 50, 1200)
            remaining -= 1
        ts += timedelta(seconds=rng.randint(30, 240))
    return records


def gen_dos_records(
    count: int,
    start_ts: datetime,
    ips: list[str],
    rng: random.Random,
) -> list[tuple[str, str]]:
    """Generate denial-of-service flood records.

    Requests arrive in large bursts (250–600) with sub-30 ms spacing to
    simulate volumetric flooding from a distributed IP pool.
    """
    records: list[tuple[str, str]] = []
    ts = start_ts
    remaining = count
    while remaining > 0:
        burst = min(rng.randint(250, 600), remaining)
        for _ in range(burst):
            records.append(
                (
                    _make_log_line(
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


# ---------------------------------------------------------------------------
# Mixed-campaign helpers
# ---------------------------------------------------------------------------

def _build_attack_record(
    attack_type: str,
    ts: datetime,
    attacker_ip: str,
    rng: random.Random,
) -> tuple[str, str]:
    """Build a single attack log line for use in mixed campaigns."""
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
    else:
        raise ValueError(f"Unsupported mixed-campaign attack type: {attack_type}")

    ua = rng.choice(UA_NORMAL) if rng.random() < 0.15 else rng.choice(UA_TOOLS)
    return _make_log_line(ts, attacker_ip, method, url, status, size, ua), attack_type


def gen_mixed_attack_campaign_from_plan(
    attack_plan: list[str],
    start_ts: datetime,
    attacker_ip: str,
    rng: random.Random,
) -> list[tuple[str, str]]:
    """Generate a mixed campaign from an exact label plan.

    The plan preserves exact per-class counts while still emitting traffic in
    short tactical bursts of 2-3 attack types per campaign.
    """
    records: list[tuple[str, str]] = []
    ts = start_ts
    remaining_counts = Counter(attack_plan)

    while sum(remaining_counts.values()) > 0:
        available_types = [label for label, count in remaining_counts.items() if count > 0]
        attack_type = rng.choice(available_types)
        burst = min(rng.randint(3, 12), remaining_counts[attack_type])

        for _ in range(burst):
            records.append(_build_attack_record(attack_type, ts, attacker_ip, rng))
            ts = _next_ts(ts, rng, 300, 4000)
            remaining_counts[attack_type] -= 1

        ts += timedelta(seconds=rng.randint(5, 90))

    return records


def gen_mixed_attack_campaign(
    count: int,
    start_ts: datetime,
    attacker_ip: str,
    rng: random.Random,
) -> list[tuple[str, str]]:
    """Backward-compatible helper that generates an exact random label plan."""
    n_types = rng.randint(2, 3)
    attack_types = rng.sample(["SQLI", "XSS", "BRUTE_FORCE"], k=n_types)
    attack_plan = rng.choices(attack_types, k=count)
    return gen_mixed_attack_campaign_from_plan(attack_plan, start_ts, attacker_ip, rng)


def _allocate_mixed_attack_plan(
    camp_size: int,
    remaining_counts: dict[str, int],
    rng: random.Random,
) -> list[str]:
    """Allocate *camp_size* attack labels from *remaining_counts* for one campaign."""
    if camp_size <= 0:
        return []

    available = [label for label, count in remaining_counts.items() if count > 0]
    if not available:
        return []

    target_types = min(len(available), rng.randint(2, 3))
    campaign_types = rng.sample(available, k=target_types)
    attack_plan: list[str] = []

    while len(attack_plan) < camp_size:
        active = [label for label in campaign_types if remaining_counts[label] > 0]
        if not active:
            active = [label for label, count in remaining_counts.items() if count > 0]
            if not active:
                break
            refill = rng.sample(active, k=min(len(active), rng.randint(1, min(3, len(active)))))
            for label in refill:
                if label not in campaign_types:
                    campaign_types.append(label)
            active = [label for label in campaign_types if remaining_counts[label] > 0]

        label = rng.choices(active, weights=[remaining_counts[item] for item in active], k=1)[0]
        attack_plan.append(label)
        remaining_counts[label] -= 1

    return attack_plan


# ---------------------------------------------------------------------------
# Orchestrator — synthetic record generation
# ---------------------------------------------------------------------------

def generate_synthetic_records(
    total: int,
    seed: int,
    class_profile: str,
) -> list[tuple[str, str]]:
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
      that interleave 2–3 supported attack types from a single IP within a
      short window.
    * Records are NOT shuffled; parse_records() already sorts by timestamp.
    """
    rng = random.Random(seed)
    tz = timezone(timedelta(hours=3))

    # --- Base timestamp -------------------------------------------------------
    # Use midnight as base so diurnal hour offsets map directly to wall clock.
    base_ts = datetime(2026, 1, 10, 0, 0, 0, tzinfo=tz)

    # --- IP pool generation ---------------------------------------------------
    # IPs overlap between normal and attacker ranges to prevent IP-based shortcuts.
    normal_ips = (
        [f"192.168.1.{index}" for index in range(10, 90)]
        + [f"45.133.{rng.randint(1, 255)}.{rng.randint(1, 255)}" for _ in range(10)]
        + [f"10.0.{rng.randint(0, 255)}.{rng.randint(2, 254)}" for _ in range(5)]
    )
    attacker_ips = (
        [f"45.133.{rng.randint(1, 255)}.{rng.randint(1, 255)}" for _ in range(25)]
        + [f"192.168.1.{rng.randint(10, 89)}" for _ in range(10)]
    )
    dos_ips = [f"10.0.{rng.randint(0, 255)}.{rng.randint(2, 254)}" for _ in range(180)]

    # --- Class distribution ---------------------------------------------------
    distribution = _class_distribution(total, class_profile=class_profile)

    print("Synthetic distribution:")
    print(f"  class_profile: {class_profile}")
    for label in LABELS:
        print(f"  {label}: {distribution[label]}")

    # --- Mixed-campaign budget ------------------------------------------------
    # Reserve _MIXED_CAMPAIGN_FRACTION of each non-DOS attack type for mixed campaigns.
    mixed_labels = ["SQLI", "XSS", "BRUTE_FORCE"]
    mixed_budget: dict[str, int] = {
        label: min(int(distribution[label] * _MIXED_CAMPAIGN_FRACTION), distribution[label])
        for label in mixed_labels
    }

    # --- Time-window layout (hours from base_ts, 48-hour horizon) -------------
    # Each type gets 6 windows spaced 8 h apart, staggered by 2 h between
    # types so they never share the same starting hour.
    attack_windows: dict[str, list[int]] = {
        "SQLI":        [2,  10, 18, 26, 34, 42],
        "XSS":         [4,  12, 20, 28, 36, 44],
        "BRUTE_FORCE": [6,  14, 22, 30, 38, 46],
        "DOS":         [1,   9, 17, 25, 33, 41],
    }
    # Mixed campaigns occupy the gaps between solo windows.
    mixed_windows = [5, 8, 13, 16, 21, 24, 29, 32, 37, 40, 45, 47]

    generators = {
        "SQLI":        (gen_sqli_records, attacker_ips),
        "XSS":         (gen_xss_records, attacker_ips),
        "BRUTE_FORCE": (gen_bruteforce_records, attacker_ips),
        "DOS":         (gen_dos_records, dos_ips),
    }

    all_records: list[tuple[str, str]] = []

    # --- 1. Normal traffic ----------------------------------------------------
    normal_rng = random.Random(seed + _SEED_OFFSET_NORMAL)
    normal_records = gen_normal_records(distribution["NORMAL"], base_ts, normal_ips, normal_rng)
    all_records.extend(normal_records)
    print(f"  generated {len(normal_records)} rows for NORMAL")

    # --- 2. Solo attack records in dedicated windows --------------------------
    for label in ["SQLI", "XSS", "BRUTE_FORCE", "DOS"]:
        generator, ips = generators[label]
        solo_count = distribution[label] - mixed_budget.get(label, 0)
        windows = attack_windows[label]
        generated = 0
        for seg_idx, seg_size in enumerate(_split_count(solo_count, parts=len(windows))):
            class_rng = random.Random(seed + _SEED_OFFSET_SOLO + LABELS.index(label) * 100 + seg_idx)
            # Small random jitter within the window (0–45 min) avoids all
            # segments of the same type starting on the exact same minute.
            seg_start = base_ts + timedelta(hours=windows[seg_idx], minutes=rng.randint(0, 45))
            class_records = generator(seg_size, seg_start, ips, class_rng)
            all_records.extend(class_records)
            generated += len(class_records)
        print(f"  generated {generated} rows for {label}")

    # --- 3. Mixed attack campaigns --------------------------------------------
    total_mixed = sum(mixed_budget.values())
    mixed_generated = 0
    for camp_idx, hour_offset in enumerate(mixed_windows):
        camp_size = total_mixed // len(mixed_windows)
        if camp_idx < total_mixed % len(mixed_windows):
            camp_size += 1
        if camp_size == 0:
            continue
        camp_rng = random.Random(seed + _SEED_OFFSET_MIXED + camp_idx)
        attacker_ip = rng.choice(attacker_ips)
        camp_start = base_ts + timedelta(hours=hour_offset, minutes=rng.randint(0, 30))
        attack_plan = _allocate_mixed_attack_plan(camp_size, mixed_budget, camp_rng)
        campaign_records = gen_mixed_attack_campaign_from_plan(attack_plan, camp_start, attacker_ip, camp_rng)
        all_records.extend(campaign_records)
        mixed_generated += len(campaign_records)
    if mixed_generated:
        print(f"  generated {mixed_generated} rows across {len(mixed_windows)} mixed campaigns")

    remaining_mixed = sum(mixed_budget.values())
    if remaining_mixed != 0:
        raise RuntimeError(f"Mixed campaign allocation drifted by {remaining_mixed} rows.")

    # parse_records() will sort everything by timestamp – no shuffle needed.
    return all_records


# ---------------------------------------------------------------------------
# External dataset loaders
# ---------------------------------------------------------------------------

def _request_blocks_from_text(text: str) -> list[str]:
    """Split raw HTTP request text into individual request blocks.

    Blocks are separated by blank lines, as found in CSIC-format datasets.
    """
    blocks: list[str] = []
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


def _label_from_request_text(text: str, default: Optional[str]) -> Optional[str]:
    """Infer a supported attack label from raw HTTP request text via keyword matching."""
    lowered = text.lower()
    if any(token in lowered for token in ["union select", " or 1=1", "sleep(", "information_schema"]):
        return "SQLI"
    if any(token in lowered for token in ["<script", "javascript:", "onerror=", "onload=", "alert("]):
        return "XSS"
    return default


def load_csic_records(csic_dir: str, seed: int) -> list[tuple[str, str]]:
    """Load and convert the CSIC HTTP dataset into labelled access-log records.

    Each raw HTTP request block is classified into one of the supported labels
    and wrapped in a Combined Log Format line with a synthetic timestamp and IP.
    """
    root = Path(csic_dir)
    if not root.exists():
        raise FileNotFoundError(f"CSIC directory not found: {csic_dir}")

    rng = random.Random(seed)
    tz = timezone(timedelta(hours=3))
    ts = datetime(2026, 1, 20, 9, 0, 0, tzinfo=tz)
    records: list[tuple[str, str]] = []

    for txt_file in sorted(root.rglob("*.txt")):
        default_label = "NORMAL" if "normal" in txt_file.name.lower() else None
        content = txt_file.read_text(encoding="utf-8", errors="ignore")
        for block in _request_blocks_from_text(content):
            request_line = block.splitlines()[0]
            parts = request_line.split()
            if len(parts) < 2:
                continue
            method = parts[0].upper()
            path = parts[1]
            label = _label_from_request_text(block, default_label)
            if label not in LABELS:
                continue
            if label == "NORMAL":
                status = rng.choice([200, 200, 301, 304])
            elif label == "SQLI":
                status = rng.choice([400, 403, 500])
            else:
                status = rng.choice([200, 400, 403])

            records.append(
                (
                    _make_log_line(ts, f"172.16.{rng.randint(0, 255)}.{rng.randint(2, 254)}", method, path, status, rng.randint(100, 2500), rng.choice(UA_TOOLS + UA_NORMAL)),
                    label,
                )
            )
            ts = _next_ts(ts, rng, 150, 3500)

    print(f"Loaded {len(records)} CSIC-derived rows from {csic_dir}")
    return records


def load_cicids_records(cic_csv: str, seed: int) -> list[tuple[str, str]]:
    """Load and convert a CICIDS CSV into labelled access-log records.

    Flow-level records are mapped to supported access-log labels and wrapped in
    Combined Log Format.
    """
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
            continue

        ip = str(row[ip_col]) if ip_col else f"10.10.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
        records.append(
            (
                _make_log_line(ts, ip, method, path_value, status, rng.randint(100, 3000), rng.choice(UA_TOOLS + UA_NORMAL)),
                label,
            )
        )
        ts = _next_ts(ts, rng, 30, 1500)

    print(f"Loaded {len(records)} CICIDS-derived rows from {cic_csv}")
    return records


# ---------------------------------------------------------------------------
# Parsing & feature extraction
# ---------------------------------------------------------------------------

def parse_records(records: list[tuple[str, str]]) -> pd.DataFrame:
    """Parse raw log lines into a DataFrame with extracted fields and labels.

    Lines that fail to parse (e.g. due to special characters) are silently
    skipped.  The result is sorted by timestamp.
    """
    parsed_rows: list[dict] = []
    labels: list[str] = []
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_dataset(
    total: int = 120000,
    seed: int = 42,
    class_profile: str = "realistic",
    csic_dir: Optional[str] = None,
    cic_csv: Optional[str] = None,
) -> pd.DataFrame:
    """Generate the full labelled dataset with features, timestamps, and split groups.

    Combines synthetic records with optional external datasets (CSIC, CICIDS),
    extracts ML features, and adds ``event_ts`` / ``split_group`` columns for
    train/test splitting.
    """
    print(f"Generating synthetic dataset with {total} rows")
    records = generate_synthetic_records(total=total, seed=seed, class_profile=class_profile)
    if csic_dir:
        records.extend(load_csic_records(csic_dir, seed + 5000))
    if cic_csv:
        records.extend(load_cicids_records(cic_csv, seed + 6000))

    df = parse_records(records)
    print(f"Parsed rows: {len(df)}")

    features = extract_features(df)
    features["event_ts"] = df["ts"].dt.strftime("%Y-%m-%dT%H:%M:%S%z")
    features["split_group"] = df["ts"].dt.floor("30min").dt.strftime("%Y-%m-%dT%H:%M:%S%z")
    features["label"] = df["label"].astype(str)
    print("Label distribution:")
    print(features["label"].value_counts().sort_index())
    return features


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments and generate the dataset CSV."""
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
