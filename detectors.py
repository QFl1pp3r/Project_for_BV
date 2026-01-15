import re
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

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

# ML-анализ на аномалии поведения по окнам.
def detect_anomalies(df: pd.DataFrame, win_min=5, contamination=0.02):
    d = _window(df, win_min)
    d["is_4xx5xx"] = d["status"].between(400, 599)
    agg = d.groupby(["ip", "window"]).agg(
        req_count=("path", "count"),
        uniq_paths=("path", "nunique"),
        err_rate=("is_4xx5xx", "mean"),
        avg_bytes=("bytes", "mean"),
    ).reset_index()

    if len(agg) < 50:
        return []  # мало данных для ML

    X = agg[["req_count", "uniq_paths", "err_rate", "avg_bytes"]].fillna(0.0).to_numpy()
    model = IsolationForest(
        n_estimators=200,
        random_state=42,
        contamination=contamination
    )
    pred = model.fit_predict(X)  # -1 аномалия
    agg["anomaly"] = (pred == -1)

    hits = agg[agg["anomaly"]]
    incidents = []
    for _, r in hits.iterrows():
        incidents.append({
            "type": "ANOMALY",
            "severity": "LOW" if r["req_count"] < 50 else "MEDIUM",
            "ip": r["ip"],
            "start": r["window"],
            "end": r["window"] + pd.Timedelta(minutes=win_min),
            "evidence": f"anomaly features: req={int(r['req_count'])}, uniq={int(r['uniq_paths'])}, err={r['err_rate']:.2f}",
            **MITRE["ANOMALY"],
        })
    return incidents

def correlate_anomalies(df: pd.DataFrame, anomalies: list[dict]) -> list[dict]:
    """
    Пытаемся объяснить ML-анномалии через правила:
    - если в том же окне есть brute-force признаки → ANOMALY_BRUTE_FORCE + MITRE T1110
    - если в окне есть SQLi-сигнатуры → ANOMALY_SQLI + MITRE T1190
    - если в окне глобально DoS → ANOMALY_DOS + MITRE T1498
    Иначе: ANOMALY_GENERIC
    """
    if not anomalies:
        return anomalies

    # параметры должны совпадать с теми, что в детекторах
    WIN_ANOM = 5
    WIN_RULES = 5

    d = _window(df, WIN_RULES)

    # 1) Индексы окон с признаками brute force
    bf_target = d[d["path"].str.startswith(LOGIN_PATHS, na=False)]
    bf_target = bf_target[bf_target["status"].isin([401, 403])]
    bf_idx = set(
        bf_target.groupby(["ip", "window"]).size().reset_index(name="c")
        .query("c >= 10")[["ip", "window"]]
        .itertuples(index=False, name=None)
    )

    # 2) Окна, где встречалась SQLi-сигнатура (по факту события)
    s = (d["path"].fillna("") + "?" + d["query"].fillna("")).astype(str)
    sqli_hits = d[s.str.contains(SQLI_RE, na=False)]
    sqli_idx = set(sqli_hits[["ip", "window"]].itertuples(index=False, name=None))

    # 3) Окна DoS глобально (без IP)
    dos_win = set(
        _window(df, 1).groupby("window").size().reset_index(name="c")
        .query("c >= 200")["window"]
        .tolist()
    )

    # Корреляция
    out = []
    for a in anomalies:
        ip = a["ip"]
        w = pd.Timestamp(a["start"]).floor(f"{WIN_ANOM}min")
        key = (ip, w)

        if key in bf_idx:
            a = {**a,
                 "type": "ANOMALY_BRUTE_FORCE",
                 "severity": "MEDIUM",
                 **MITRE["BRUTE_FORCE"],
                 "evidence": a["evidence"] + " | correlated: brute-force pattern"}
        elif key in sqli_idx:
            a = {**a,
                 "type": "ANOMALY_SQLI",
                 "severity": "HIGH",
                 **MITRE["SQLI"],
                 "evidence": a["evidence"] + " | correlated: sqli signature"}
        elif w in dos_win:
            a = {**a,
                 "type": "ANOMALY_DOS",
                 "severity": "HIGH",
                 **MITRE["DOS"],
                 "evidence": a["evidence"] + " | correlated: global dos window"}
        else:
            a = {**a,
                 "type": "ANOMALY_GENERIC",
                 **MITRE["ANOMALY"],
                 "evidence": a["evidence"] + " | correlated: none"}
        out.append(a)

    return out

def _ts(x):
    # приводим время к pandas.Timestamp
    return pd.Timestamp(x)

def deduplicate_incidents(rule_incidents: list[dict], anomaly_incidents: list[dict]) -> list[dict]:
    """
    Убирает дубли: если rule-инцидент уже покрывает тот же MITRE technique_id
    в том же (или пересекающемся) интервале времени для того же IP,
    то коррелированную anomaly-* запись не добавляем.
    """
    # Индекс по (technique_id, ip) -> список интервалов rule
    idx: dict[tuple[str, str], list[tuple[pd.Timestamp, pd.Timestamp]]] = {}

    for inc in rule_incidents:
        tech = inc.get("technique_id", "")
        ip = inc.get("ip", "")
        if not tech or not ip:
            continue
        s, e = _ts(inc["start"]), _ts(inc["end"])
        idx.setdefault((tech, ip), []).append((s, e))

    def overlaps(a_s, a_e, b_s, b_e) -> bool:
        return max(a_s, b_s) <= min(a_e, b_e)

    filtered = []
    for a in anomaly_incidents:
        # дедупаем только коррелированные аномалии
        t = a.get("type", "")
        if not t.startswith("ANOMALY_") or t == "ANOMALY_GENERIC":
            filtered.append(a)
            continue

        tech = a.get("technique_id", "")
        ip = a.get("ip", "")
        if not tech or not ip:
            filtered.append(a)
            continue

        a_s, a_e = _ts(a["start"]), _ts(a["end"])

        # особый случай DoS: в rules ip="MULTIPLE/UNKNOWN"
        # если anomaly_dos → считаем дубликатом при совпадении по tech и любому ip MULTIPLE/UNKNOWN
        candidates = idx.get((tech, ip), []) + idx.get((tech, "MULTIPLE/UNKNOWN"), [])

        is_dup = any(overlaps(a_s, a_e, r_s, r_e) for (r_s, r_e) in candidates)
        if not is_dup:
            filtered.append(a)

    return rule_incidents + filtered

def run_all(df: pd.DataFrame):
    rule_incidents = []
    rule_incidents += detect_sqli(df)
    rule_incidents += detect_bruteforce(df)
    rule_incidents += detect_dos(df)

    anomalies = detect_anomalies(df)
    anomalies = correlate_anomalies(df, anomalies)  # если у тебя есть эта функция

    incidents = deduplicate_incidents(rule_incidents, anomalies)
    return incidents
