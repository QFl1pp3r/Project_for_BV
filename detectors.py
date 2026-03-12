"""
Regex-based детекторы атак.
Используется как baseline для валидации точности ML-модели.
"""

import re
import pandas as pd

MITRE = {
    "BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
    },
    "SQLI": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
    },
    "XSS": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
    },
    "DOS": {
        "tactic": "Impact",
        "technique": "Network Denial of Service",
        "technique_id": "T1498",
    },
    "ANOMALY": {
        "tactic": "Discovery / Reconnaissance",
        "technique": "Behavioral Anomaly (heuristic)",
        "technique_id": "N/A",
    },
}


SQLI_PATTERNS = [
    r"(?:\%27)|(?:')|(?:\-\-)|(?:\%23)|(?:#)",
    r"\bunion\b.*\bselect\b",
    r"\bor\b\s+1=1",
    r"\bselect\b.+\bfrom\b",
    r"\binformation_schema\b",
    r"\bsleep\(",
]

SQLI_RE = re.compile("|".join(SQLI_PATTERNS), flags=re.IGNORECASE)

XSS_PATTERNS = [
    r"<\s*script\b",
    r"%3c\s*script\b",
    r"javascript\s*:",
    r"%3c\s*img\b[^>]*onerror\s*=",
    r"\bon(?:error|load|click|mouseover|focus|mouseenter|animationstart)\s*=",
    r"document\.cookie",
    r"alert\s*\(",
]

XSS_RE = re.compile("|".join(XSS_PATTERNS), flags=re.IGNORECASE)

LOGIN_PATHS = ("/login", "/signin", "/auth", "/admin", "/wp-login.php")

# Добавляем колонку с округленным временем окна.
def _window(df: pd.DataFrame, minutes: int) -> pd.DataFrame:
    return df.assign(window=df["ts"].dt.floor(f"{minutes}min"))

# Ищем частые ошибки логина в одном окне по IP.
def detect_bruteforce(df: pd.DataFrame, win_min=5, thr=10):
    d = _window(df, win_min)
    target = d[d["path"].str.startswith(LOGIN_PATHS, na=False)]
    target = target[target["status"].isin([401, 403])]
    g = target.groupby(["ip", "window"]).size().reset_index(name="count")
    hits = g[g["count"] >= thr]

    incidents = []
    for _, r in hits.iterrows():
        incidents.append({
            "type": "BRUTE_FORCE",
            "severity": "HIGH" if r["count"] >= thr * 2 else "MEDIUM",
            "ip": r["ip"],
            "start": r["window"],
            "end": r["window"] + pd.Timedelta(minutes=win_min),
            "evidence": f"{int(r['count'])} failed logins in {win_min} min",
            **MITRE["BRUTE_FORCE"],
        })
    return incidents

# Сигнатурный поиск SQLi в URL и query.
def detect_sqli(df: pd.DataFrame):
    s = (df["path"].fillna("") + "?" + df["query"].fillna("")).astype(str)
    mask = s.str.contains(SQLI_RE)
    hits = df[mask].copy()

    incidents = []
    for _, r in hits.iterrows():
        incidents.append({
            "type": "SQLI",
            "severity": "HIGH",
            "ip": r["ip"],
            "start": r["ts"],
            "end": r["ts"],
            "evidence": f"suspected SQLi in URL: {r['path']}?{r['query']}"[:180],
            **MITRE["SQLI"],
        })
    return incidents

# Сигнатурный поиск XSS в URL и query.
def detect_xss(df: pd.DataFrame):
    s = (df["path"].fillna("") + "?" + df["query"].fillna("")).astype(str)
    mask = s.str.contains(XSS_RE, na=False)
    hits = df[mask].copy()

    incidents = []
    for _, r in hits.iterrows():
        incidents.append({
            "type": "XSS",
            "severity": "HIGH",
            "ip": r["ip"],
            "start": r["ts"],
            "end": r["ts"],
            "evidence": f"suspected XSS payload in URL: {r['path']}?{r['query']}"[:180],
            **MITRE["XSS"],
        })
    return incidents

# Находим всплески запросов в минуту на уровне всего лога.
def detect_dos(df: pd.DataFrame, win_min=1, rps_thr=200):
    d = _window(df, win_min)
    agg = d.groupby("window").size().reset_index(name="req_count")
    hits = agg[agg["req_count"] >= rps_thr]

    incidents = []
    for _, r in hits.iterrows():
        incidents.append({
            "type": "DOS",
            "severity": "HIGH",
            "ip": "MULTIPLE/UNKNOWN",
            "start": r["window"],
            "end": r["window"] + pd.Timedelta(minutes=win_min),
            "evidence": f"global req/min={int(r['req_count'])} >= {rps_thr}",
            **MITRE["DOS"],
        })
    return incidents

def run_regex_all(df: pd.DataFrame) -> list[dict]:
    """Запускает все regex-детекторы. Используется для валидации ML-модели."""
    incidents = []
    incidents += detect_sqli(df)
    incidents += detect_xss(df)
    incidents += detect_bruteforce(df)
    incidents += detect_dos(df)
    return incidents


# Backward-compatible alias for older integrations.
run_all = run_regex_all
