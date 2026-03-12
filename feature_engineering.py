"""
Feature engineering for HTTP access-log requests.

The same functions are used by offline training scripts and online inference.
"""

import math
import re
from urllib.parse import unquote

import numpy as np
import pandas as pd

SQL_KEYWORDS = (
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "create",
    "exec",
    "execute",
    "from",
    "where",
    "having",
    "group",
    "order",
    "limit",
    "sleep",
    "benchmark",
    "information_schema",
    "load_file",
    "outfile",
    "into",
    "concat",
    "char",
    "hex",
)
SQL_KEYWORD_RE = re.compile(r"\b(?:" + "|".join(SQL_KEYWORDS) + r")\b", re.IGNORECASE)

XSS_INDICATORS = re.compile(
    r"<\s*script|%3c\s*script|javascript\s*:|onerror\s*=|onload\s*=|"
    r"onclick\s*=|onmouseover\s*=|onfocus\s*=|document\.cookie|alert\s*\(",
    re.IGNORECASE,
)

ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")
SPECIAL_CHAR_RE = re.compile(r"[\'\"<>;]|--")

ATTACK_PATHS = (
    "/admin",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/.git",
    "/etc/passwd",
    "/backup",
    "/config",
    "/server-status",
    "/db.sql",
    "/admin.php",
)

LOGIN_PATHS = ("/login", "/signin", "/auth", "/admin", "/wp-login.php")

METHOD_MAP = {
    "GET": 0,
    "POST": 1,
    "PUT": 2,
    "DELETE": 3,
    "HEAD": 4,
    "OPTIONS": 5,
    "PATCH": 6,
}

FEATURE_COLUMNS = [
    "url_length",
    "query_length",
    "path_depth",
    "num_params",
    "has_special_chars",
    "special_char_ratio",
    "has_encoded_chars",
    "encoded_char_count",
    "has_sql_keywords",
    "sql_keyword_count",
    "has_script_tags",
    "has_common_attack_path",
    "method_encoded",
    "status_code",
    "status_group",
    "response_bytes",
    "is_post",
    "is_login_path",
    "hour_of_day",
    "entropy",
    "ip_req_count_5m",
    "ip_unique_paths_5m",
    "ip_error_rate_5m",
    "ip_login_fail_count_5m",
    "global_rps_1m",
]


def _build_full_url(path: str, query: str) -> str:
    return f"{path}?{query}" if query else path


def _decode_url(value: str) -> str:
    try:
        return unquote(value)
    except Exception:
        return value


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _count_sql_keywords(value: str) -> int:
    return len(SQL_KEYWORD_RE.findall(value))


def _count_special_chars(value: str) -> int:
    return len(SPECIAL_CHAR_RE.findall(value))


def prepare_request_frame(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalizes the request dataframe expected by feature extraction.
    """
    prepared = df.copy()
    defaults = {
        "ip": "",
        "path": "",
        "query": "",
        "method": "GET",
        "status": 0,
        "bytes": 0,
    }
    for column, default in defaults.items():
        if column not in prepared.columns:
            prepared[column] = default

    if "ts" not in prepared.columns:
        prepared["ts"] = pd.NaT

    prepared["path"] = prepared["path"].fillna("").astype(str)
    prepared["query"] = prepared["query"].fillna("").astype(str)
    prepared["method"] = prepared["method"].fillna("GET").astype(str).str.upper()
    prepared["status"] = pd.to_numeric(prepared["status"], errors="coerce").fillna(0).astype(int)
    prepared["bytes"] = pd.to_numeric(prepared["bytes"], errors="coerce").fillna(0).astype(int)
    prepared["ts"] = pd.to_datetime(prepared["ts"], errors="coerce")
    return prepared.reset_index(drop=True)


def extract_per_request_features(df: pd.DataFrame) -> pd.DataFrame:
    prepared = prepare_request_frame(df)
    path = prepared["path"]
    query = prepared["query"]
    full_url = pd.Series(
        [_build_full_url(path_value, query_value) for path_value, query_value in zip(path, query)],
        index=prepared.index,
    )
    decoded_url = full_url.apply(_decode_url)

    features = pd.DataFrame(index=prepared.index)
    features["url_length"] = full_url.str.len().astype(int)
    features["query_length"] = query.str.len().astype(int)
    features["path_depth"] = path.str.count("/").astype(int)
    features["num_params"] = query.apply(lambda value: value.count("&") + 1 if value else 0).astype(int)

    special_counts = decoded_url.apply(_count_special_chars)
    features["has_special_chars"] = (special_counts > 0).astype(int)
    features["special_char_ratio"] = special_counts / full_url.str.len().clip(lower=1)

    encoded_counts = full_url.apply(lambda value: len(ENCODED_RE.findall(value)))
    features["has_encoded_chars"] = (encoded_counts > 0).astype(int)
    features["encoded_char_count"] = encoded_counts.astype(int)

    sql_counts = decoded_url.apply(_count_sql_keywords)
    features["has_sql_keywords"] = (sql_counts > 0).astype(int)
    features["sql_keyword_count"] = sql_counts.astype(int)

    features["has_script_tags"] = decoded_url.apply(lambda value: int(bool(XSS_INDICATORS.search(value))))
    features["has_common_attack_path"] = path.str.lower().apply(
        lambda value: int(any(value.startswith(attack_path) for attack_path in ATTACK_PATHS))
    )

    features["method_encoded"] = prepared["method"].map(METHOD_MAP).fillna(len(METHOD_MAP)).astype(int)
    features["status_code"] = prepared["status"].astype(int)
    features["status_group"] = (features["status_code"] // 100).clip(lower=0).astype(int)
    features["response_bytes"] = prepared["bytes"].clip(lower=0).astype(int)
    features["is_post"] = prepared["method"].eq("POST").astype(int)
    features["is_login_path"] = path.str.lower().apply(
        lambda value: int(value.startswith(LOGIN_PATHS))
    ).astype(int)
    features["hour_of_day"] = prepared["ts"].dt.hour.fillna(0).astype(int)
    features["entropy"] = query.apply(_shannon_entropy)

    return features


def extract_window_features(df: pd.DataFrame, win_min: int = 5) -> pd.DataFrame:
    prepared = prepare_request_frame(df)
    features = pd.DataFrame(0.0, index=prepared.index, columns=FEATURE_COLUMNS[20:])
    if prepared.empty:
        return features

    with_windows = prepared.assign(
        __row_id=np.arange(len(prepared)),
        window=prepared["ts"].dt.floor(f"{win_min}min"),
        minute=prepared["ts"].dt.floor("1min"),
    )
    with_windows["is_error"] = with_windows["status"].between(400, 599)
    with_windows["is_login_fail"] = (
        with_windows["path"].str.lower().str.startswith(LOGIN_PATHS, na=False)
        & with_windows["status"].isin([401, 403])
    )

    ip_window_agg = (
        with_windows.groupby(["ip", "window"], dropna=False)
        .agg(
            ip_req_count_5m=("path", "size"),
            ip_unique_paths_5m=("path", "nunique"),
            ip_error_rate_5m=("is_error", "mean"),
            ip_login_fail_count_5m=("is_login_fail", "sum"),
        )
        .reset_index()
    )

    minute_agg = (
        with_windows.groupby("minute", dropna=False)
        .size()
        .div(60.0)
        .reset_index(name="global_rps_1m")
    )

    merged = with_windows.merge(ip_window_agg, on=["ip", "window"], how="left")
    merged = merged.merge(minute_agg, on="minute", how="left")
    merged = merged.sort_values("__row_id")

    return (
        merged[
            [
                "ip_req_count_5m",
                "ip_unique_paths_5m",
                "ip_error_rate_5m",
                "ip_login_fail_count_5m",
                "global_rps_1m",
            ]
        ]
        .fillna(0)
        .reset_index(drop=True)
    )


def align_feature_columns(features: pd.DataFrame) -> pd.DataFrame:
    aligned = features.copy()
    for column in FEATURE_COLUMNS:
        if column not in aligned.columns:
            aligned[column] = 0
    return aligned[FEATURE_COLUMNS].fillna(0)


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    per_request = extract_per_request_features(df)
    window_level = extract_window_features(df)
    combined = pd.concat([per_request, window_level], axis=1)
    return align_feature_columns(combined)
