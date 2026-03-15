#!/usr/bin/env python3
"""Generate attack traffic against vulnerable_service and export collected access logs.

Usage example:
  python3 tools/attack_lab_service.py \
    --base-url http://127.0.0.1:8080 \
    --service-log vulnerable_service/logs/access.log \
    --output test_logs/lab_attack.log
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import sys
import time
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


DEFAULT_UA = "KittyHubLabAttack/1.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Attack generator for KittyHub vulnerable service")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080", help="Target service base URL")
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
    parser.add_argument("--bf-attempts", type=int, default=14, help="Failed login attempts for brute-force scenario")
    parser.add_argument("--dos-requests", type=int, default=220, help="Number of requests for DoS scenario")
    parser.add_argument("--dos-units", type=int, default=5000, help="Work units for /api/cat-feed")
    parser.add_argument("--dos-workers", type=int, default=20, help="Parallel workers for DoS scenario")
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


def _run_sqli(base_url: str, timeout: float, ua: str) -> int:
    return _http_get(base_url, "/cats", timeout, ua, query={"q": "' OR 1=1 --"})


def _run_xss(base_url: str, timeout: float, ua: str) -> int:
    return _http_get(base_url, "/community", timeout, ua, query={"note": "<script>alert('xss')</script>"})


def _run_bruteforce(base_url: str, timeout: float, ua: str, attempts: int) -> tuple[int, int]:
    failed = 0
    for idx in range(attempts):
        status = _http_post(
            base_url,
            "/account/login",
            timeout,
            ua,
            data={"username": "admin", "password": f"wrong-{idx}-{time.time_ns()}"},
        )
        if status == 401:
            failed += 1
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [
            pool.submit(_dos_worker, base_url, timeout, ua, units, idx)
            for idx in range(requests_count)
        ]
        for future in concurrent.futures.as_completed(futures):
            statuses.append(future.result())

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
    print(f"[+] Collected log lines: {count}")
    print(f"[+] Output file: {output}")


def main() -> int:
    args = parse_args()

    service_log = Path(args.service_log)
    output = Path(args.output)
    _ensure_parent(output)

    start_offset = service_log.stat().st_size if service_log.exists() else 0
    print(f"[*] Starting offset in service log: {start_offset} bytes")

    try:
        sqli_status = _run_sqli(args.base_url, args.timeout, args.user_agent)
        xss_status = _run_xss(args.base_url, args.timeout, args.user_agent)
        failed, attempted = _run_bruteforce(args.base_url, args.timeout, args.user_agent, max(1, args.bf_attempts))
        dos_ok, dos_total = _run_dos(
            args.base_url,
            args.timeout,
            args.user_agent,
            max(1, args.dos_requests),
            max(5000, args.dos_units),
            max(1, args.dos_workers),
        )
    except URLError as exc:
        print(f"[!] Network error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        print(f"[!] Unexpected error: {exc}", file=sys.stderr)
        return 3

    print(f"[+] SQLI request status: {sqli_status}")
    print(f"[+] XSS request status: {xss_status}")
    print(f"[+] BRUTE_FORCE failures: {failed}/{attempted}")
    print(f"[+] DOS successful responses: {dos_ok}/{dos_total}")

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
