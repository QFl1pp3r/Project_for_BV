"""
Regex-based детекторы атак.
Используется как baseline для валидации точности ML-модели.
"""

import re
from urllib.parse import unquote
import pandas as pd

from config import DOS_RPS_THRESHOLD, MULTI_ATTACK_LABEL
from .mitre import (MITRE, SQLI_RE, XSS_RE, LOGIN_PATHS)


# Добавляем колонку с округленным временем окна.
def _window(df: pd.DataFrame, minutes: int) -> pd.DataFrame:
    return df.assign(window=df["ts"].dt.floor(f"{minutes}min"))

# Ищем частые ошибки логина в одном окне по IP.
def detect_bruteforce(df: pd.DataFrame, win_min: int = 5, thr: int = 10):
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
    decoded = s.apply(lambda value: unquote(value))
    xss_mask = decoded.str.contains(XSS_RE, na=False)
    mask = decoded.str.contains(SQLI_RE, na=False) & ~xss_mask
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
    decoded = s.apply(lambda value: unquote(value))
    mask = decoded.str.contains(XSS_RE, na=False)
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
def detect_dos(df: pd.DataFrame, win_min: int = 1, rps_thr: int = DOS_RPS_THRESHOLD):
    d = _window(df, win_min)
    agg = d.groupby("window").size().reset_index(name="req_count")
    hits = agg[agg["req_count"] >= rps_thr]

    incidents = []
    for _, r in hits.iterrows():
        incidents.append({
            "type": "DOS",
            "severity": "HIGH",
            "ip": MULTI_ATTACK_LABEL,
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
