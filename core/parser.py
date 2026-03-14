import re
from datetime import datetime
from typing import Any, Dict, Optional

# Пример combined:
# 127.0.0.1 - - [10/Oct/2000:13:55:36 +0300] "GET /index.html?x=1 HTTP/1.1" 200 2326 "-" "UA"
LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

# Более простой common без ref/ua
LOG_RE_COMMON = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
)

# Парсинг формата времени из access-log.
def parse_time(t: str) -> datetime:
    return datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z")

# Разделяем URL на путь и query.
def split_url(url: str) -> tuple[str, str]:
    if "?" in url:
        path, query = url.split("?", 1)
    else:
        path, query = url, ""
    return path, query


def build_full_url(path: str, query: str) -> str:
    """Build full URL from path and query (single source for feature_engineering and ml_detector)."""
    return f"{path}?{query}" if query else path


# Пытаемся распарсить строку в формате combined/common.
def parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None

    m = LOG_RE.match(line) or LOG_RE_COMMON.match(line)
    if not m:
        return None

    d = m.groupdict()
    b = d["bytes"]
    d["bytes"] = int(b) if b.isdigit() else 0
    d["status"] = int(d["status"])
    d["ts"] = parse_time(d["time"])
    path, query = split_url(d["url"])
    return {
        "ip": d["ip"],
        "ts": d["ts"],
        "method": d["method"],
        "path": path,
        "query": query,
        "status": d["status"],
        "bytes": d["bytes"],
        "ua": d.get("ua", ""),
        "ref": d.get("ref", ""),
        "raw": line,
    }

def parse_file(fp) -> list[dict]:
    rows = []
    for line in fp:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="ignore")
        r = parse_line(line)
        if r:
            rows.append(r)
    return rows
