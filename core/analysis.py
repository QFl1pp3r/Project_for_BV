"""
Pure analysis logic: build request dataframe and run ML/regex detection.
Used by the Flask app to keep route handlers thin.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

import pandas as pd

from .accuracy import compare_with_regex_baseline, merge_incident_sources
from config import APP_TZ
from .detectors import run_regex_all

if TYPE_CHECKING:
    from .ml_detector import MLDetector


def build_requests_df(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    ts = pd.to_datetime(df["ts"], errors="coerce", utc=True)
    df = df.assign(ts=ts.dt.tz_convert(APP_TZ))
    return df.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)


def run_analysis(
    df: pd.DataFrame,
    ml_detector: MLDetector,
) -> tuple[list[dict], Optional[dict], str, Optional[str]]:
    """
    Run regex baseline and ML detection (with fallback to regex-only on model error).
    Returns: (incidents, baseline_comparison, analysis_mode, model_error).
    """
    regex_incidents = run_regex_all(df)
    baseline_comparison = None
    model_error = None
    analysis_mode = "ml"

    try:
        ml_incidents = ml_detector.predict(df)
        incidents = merge_incident_sources(ml_incidents, regex_incidents)
        baseline_comparison = compare_with_regex_baseline(None, ml_incidents, regex_incidents)
        return incidents, baseline_comparison, analysis_mode, model_error
    except Exception as exc:
        model_error = str(exc)
        analysis_mode = "regex_fallback"
        incidents = merge_incident_sources([], regex_incidents)
        return incidents, baseline_comparison, analysis_mode, model_error
