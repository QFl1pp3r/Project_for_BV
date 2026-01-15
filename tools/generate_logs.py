#!/usr/bin/env python3
import argparse
import random
from datetime import datetime, timedelta, timezone

UA_NORMAL = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
]
UA_TOOLS = [
    "curl/8.0",
    "python-requests/2.31",
    "sqlmap/1.7",
]

PATHS = [
    "/", "/index.html", "/about", "/products", "/api/items",
    "/contact", "/static/app.js", "/static/site.css",
]
LOGIN_PATHS = ["/login", "/admin", "/signin", "/wp-login.php"]

SCAN_WORDLIST = [
    "/.env", "/wp-admin", "/phpmyadmin", "/backup.zip", "/config",
    "/server-status", "/.git/config", "/db.sql", "/admin.php"
]

SQLI_PAYLOADS = [
    "/products?id=1%20OR%201=1",
    "/api/items?search=' UNION SELECT password FROM users--",
    "/index.html?q=1%27%20AND%20SLEEP(2)--",
    "/api/items?id=1%27%20OR%20%271%27=%271",
]

def fmt_time(ts: datetime) -> str:
    return ts.strftime("%d/%b/%Y:%H:%M:%S %z")

def make_line_combined(ts, ip, method, url, status, size, ua, ref="-"):
    t = fmt_time(ts)
    return f'{ip} - - [{t}] "{method} {url} HTTP/1.1" {status} {size} "{ref}" "{ua}"'

def make_line_common(ts, ip, method, url, status, size):
    t = fmt_time(ts)
    return f'{ip} - - [{t}] "{method} {url} HTTP/1.1" {status} {size}'

def emit_line(fmt: str, ts, ip, method, url, status, size, ua=None):
    if fmt == "combined":
        return make_line_combined(ts, ip, method, url, status, size, ua or random.choice(UA_NORMAL))
    if fmt == "common":
        return make_line_common(ts, ip, method, url, status, size)
    raise ValueError("Unknown format")

def normal_traffic(lines, fmt, start_ts, seconds, ips):
    ts = start_ts
    for _ in range(seconds):
        ip = random.choice(ips)
        path = random.choice(PATHS)
        method = "GET"
        status = random.choices([200, 200, 200, 404, 301, 500], weights=[82, 8, 4, 3, 2, 1])[0]
        size = random.randint(200, 8000)
        ua = random.choice(UA_NORMAL)
        lines.append(emit_line(fmt, ts, ip, method, path, status, size, ua))
        ts += timedelta(seconds=1)
    return ts

def idle_gap(lines, fmt, start_ts, minutes, ips):
    """Период 'нормы' между атаками, чтобы на графике были разрывы."""
    return normal_traffic(lines, fmt, start_ts, minutes * 60, ips)

def attack_bruteforce(lines, fmt, start_ts, seconds, ip):
    ts = start_ts
    for _ in range(seconds):
        path = random.choice(LOGIN_PATHS)
        status = random.choice([401, 403])
        size = random.randint(300, 900)
        ua = random.choice(UA_TOOLS)
        lines.append(emit_line(fmt, ts, ip, "POST", path, status, size, ua))
        ts += timedelta(seconds=1)
    return ts

def attack_scanning(lines, fmt, start_ts, seconds, ip):
    ts = start_ts
    for _ in range(seconds):
        path = random.choice(SCAN_WORDLIST)
        if random.random() < 0.3:
            path += f"?id={random.randint(1,999)}"
        status = random.choice([404, 403, 404, 404])
        size = random.randint(150, 600)
        ua = random.choice(["curl/8.0", "Mozilla/5.0"])
        lines.append(emit_line(fmt, ts, ip, "GET", path, status, size, ua))
        ts += timedelta(seconds=1)
    return ts

def attack_sqli(lines, fmt, start_ts, count, ip):
    ts = start_ts
    for _ in range(count):
        url = random.choice(SQLI_PAYLOADS)
        status = random.choice([400, 500, 500, 200])
        size = random.randint(120, 900)
        ua = "sqlmap/1.7"
        lines.append(emit_line(fmt, ts, ip, "GET", url, status, size, ua))
        ts += timedelta(seconds=3)
    return ts

def attack_dos(lines, fmt, start_ts, seconds, rps, ip_pool, burst=True):
    """
    DoS-атака: короткий интенсивный всплеск.
    burst=True делает максимально плотную генерацию, чтобы график точно показал пик.
    """
    ts = start_ts
    if burst:
        # максимально плотный всплеск: много запросов в очень короткое время
        for _ in range(seconds * rps):
            ip = random.choice(ip_pool)
            url = random.choice(["/api/items", "/api/items?page=1", "/api/items?page=2"])
            status = random.choice([200, 200, 200, 504, 500])
            size = random.randint(400, 2500)
            ua = random.choice(UA_NORMAL)
            lines.append(emit_line(fmt, ts, ip, "GET", url, status, size, ua))
            ts += timedelta(milliseconds=1)  # почти "заливка"
        return ts
    else:
        step_ms = max(1, int(1000 / max(1, rps)))
        for _ in range(seconds * rps):
            ip = random.choice(ip_pool)
            url = random.choice(["/api/items", "/api/items?page=1", "/api/items?page=2"])
            status = random.choice([200, 200, 200, 504, 500])
            size = random.randint(400, 2500)
            ua = random.choice(UA_NORMAL)
            lines.append(emit_line(fmt, ts, ip, "GET", url, status, size, ua))
            ts += timedelta(milliseconds=step_ms)
        return ts

def main():
    ap = argparse.ArgumentParser(description="Log generator for VSOSH demo")
    ap.add_argument("--format", choices=["combined", "common"], default="combined", help="Log format")
    ap.add_argument("--mode", choices=["normal", "bruteforce", "scanning", "sqli", "dos", "mixed"], default="mixed")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--tz", type=int, default=3, help="Timezone offset hours (default +3)")

    # сколько нормального трафика до/между атак
    ap.add_argument("--warmup-min", type=int, default=6, help="Normal traffic before attacks (minutes)")
    ap.add_argument("--gap-min", type=int, default=4, help="Normal traffic between attacks (minutes)")
    ap.add_argument("--tail-min", type=int, default=3, help="Normal traffic after last attack (minutes)")

    # параметры атак
    ap.add_argument("--bf-seconds", type=int, default=90)
    ap.add_argument("--scan-seconds", type=int, default=90)
    ap.add_argument("--sqli-count", type=int, default=8)
    ap.add_argument("--dos-seconds", type=int, default=20)
    ap.add_argument("--dos-rps", type=int, default=350)

    args = ap.parse_args()
    random.seed(args.seed)

    tz = timezone(timedelta(hours=args.tz))
    start = datetime.now(tz) - timedelta(minutes=args.warmup_min + args.gap_min * 4 + args.tail_min + 2)

    ips_normal = [f"192.168.1.{i}" for i in range(10, 60)]
    attacker_ip = "45.133.12.77"
    dos_pool = [f"10.0.0.{i}" for i in range(2, 120)]

    lines = []
    ts = start

    # 1) Пролог нормы
    ts = normal_traffic(lines, args.format, ts, args.warmup_min * 60, ips_normal)

    if args.mode == "normal":
        print("\n".join(lines))
        return

    if args.mode == "bruteforce":
        ts = attack_bruteforce(lines, args.format, ts, args.bf_seconds, attacker_ip)
        ts = idle_gap(lines, args.format, ts, args.tail_min, ips_normal)

    elif args.mode == "scanning":
        ts = attack_scanning(lines, args.format, ts, args.scan_seconds, attacker_ip)
        ts = idle_gap(lines, args.format, ts, args.tail_min, ips_normal)

    elif args.mode == "sqli":
        ts = attack_sqli(lines, args.format, ts, args.sqli_count, attacker_ip)
        ts = idle_gap(lines, args.format, ts, args.tail_min, ips_normal)

    elif args.mode == "dos":
        ts = attack_dos(lines, args.format, ts, args.dos_seconds, args.dos_rps, dos_pool, burst=True)
        ts = idle_gap(lines, args.format, ts, args.tail_min, ips_normal)

    elif args.mode == "mixed":
        # 2) Brute Force (всплеск ошибок 401/403 на login)
        ts = attack_bruteforce(lines, args.format, ts, args.bf_seconds, attacker_ip)
        ts = idle_gap(lines, args.format, ts, args.gap_min, ips_normal)

        # 3) Active Scanning (много 404/403 по разным путям)
        ts = attack_scanning(lines, args.format, ts, args.scan_seconds, attacker_ip)
        ts = idle_gap(lines, args.format, ts, args.gap_min, ips_normal)

        # 4) SQLi (несколько подозрительных запросов, точечные события)
        ts = attack_sqli(lines, args.format, ts, args.sqli_count, attacker_ip)
        ts = idle_gap(lines, args.format, ts, args.gap_min, ips_normal)

        # 5) DoS burst (короткий пик по RPS)
        ts = attack_dos(lines, args.format, ts, args.dos_seconds, args.dos_rps, dos_pool, burst=True)
        ts = idle_gap(lines, args.format, ts, args.tail_min, ips_normal)

    print("\n".join(lines))

if __name__ == "__main__":
    main()
