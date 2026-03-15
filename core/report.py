"""Generate chart data as JSON-serialisable dicts for Plotly.js rendering."""

import os
from typing import Optional

import numpy as np
import pandas as pd

from config import ATTACK_COLORS, ATTACK_LABELS


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def chart_requests_over_time(df: pd.DataFrame) -> dict:
    """Return RPS (requests-per-minute) line chart data."""
    if df.empty:
        return {"empty": True, "title": "No requests found", "subtitle": "Upload a non-empty log file to build this chart."}

    series = df.set_index("ts").resample("1min").size()
    return {
        "empty": False,
        "x": [t.isoformat() for t in series.index],
        "y": series.values.tolist(),
        "title": "Requests Per Minute",
        "xlabel": "Time",
        "ylabel": "Requests",
        "color": "#0B7285",
    }


def chart_top_ips(df: pd.DataFrame, n: int = 10) -> dict:
    """Return top-N IPs horizontal bar chart data."""
    if df.empty:
        return {"empty": True, "title": "No requests found", "subtitle": "Upload a non-empty log file to build this chart."}

    series = df["ip"].value_counts().head(n).sort_values()
    return {
        "empty": False,
        "ips": series.index.astype(str).tolist(),
        "counts": series.values.tolist(),
        "title": f"Top {n} IPs By Request Count",
        "color": "#1D3557",
    }


def chart_attacks_over_time(
    incidents_df: pd.DataFrame,
    bucket: str = "5min",
    min_confidence: float = 0.0,
) -> dict:
    """Return incident timeline grouped bar chart data."""
    if incidents_df.empty:
        return {"empty": True, "title": "No attacks detected", "subtitle": "No incidents were detected for this log."}

    data = incidents_df.copy()
    data["start"] = pd.to_datetime(data["start"], errors="coerce")
    data["type"] = data["type"].fillna("").astype(str).str.upper()
    data = data.dropna(subset=["start"])

    if min_confidence > 0 and "confidence" in data.columns:
        conf = pd.to_numeric(data["confidence"], errors="coerce")
        data = data[conf.isna() | (conf >= min_confidence)]

    if data.empty:
        return {"empty": True, "title": "No attacks detected", "subtitle": "No incidents were detected for this log."}

    data["bucket"] = data["start"].dt.floor(bucket)
    pivot = data.groupby(["bucket", "type"]).size().unstack(fill_value=0).sort_index()
    if pivot.empty:
        return {"empty": True, "title": "No attacks detected", "subtitle": "No incidents were detected for this log."}

    attack_order = [label for label in ATTACK_LABELS if label != "NORMAL"]
    ordered_types = [label for label in attack_order if label in pivot.columns]
    ordered_types.extend(sorted(set(pivot.columns) - set(ordered_types)))
    pivot = pivot[ordered_types]

    x_labels = [t.isoformat() for t in pivot.index]
    series = []
    for attack_type in pivot.columns:
        series.append({
            "name": attack_type,
            "values": pivot[attack_type].values.tolist(),
            "color": ATTACK_COLORS.get(attack_type, "#457B9D"),
        })

    return {
        "empty": False,
        "x": x_labels,
        "series": series,
        "title": "Incident Timeline",
        "xlabel": "Time Buckets",
        "ylabel": "Incidents",
    }


def chart_confidence_distribution(incidents_df: pd.DataFrame) -> dict:
    """Return model confidence histogram data."""
    if incidents_df.empty or "confidence" not in incidents_df.columns:
        return {"empty": True, "title": "Confidence unavailable", "subtitle": "The model did not produce confidence scores."}

    scores = pd.to_numeric(incidents_df["confidence"], errors="coerce").dropna()
    if scores.empty:
        return {"empty": True, "title": "Confidence unavailable", "subtitle": "The model did not produce confidence scores."}

    bins = np.linspace(0, 1, 11)
    counts, edges = np.histogram(scores, bins=bins)
    bin_labels = [f"{edges[i]:.1f}-{edges[i+1]:.1f}" for i in range(len(counts))]

    return {
        "empty": False,
        "bins": bin_labels,
        "counts": counts.tolist(),
        "edges": edges.tolist(),
        "title": "Model Confidence Distribution",
        "xlabel": "Confidence",
        "ylabel": "Incidents",
        "color": "#2A9D8F",
    }


def chart_ml_vs_regex_comparison(baseline_metrics: Optional[dict]) -> dict:
    """Return ML vs Regex grouped bar chart data."""
    if not baseline_metrics:
        return {"empty": True, "title": "Comparison unavailable", "subtitle": "Train a model to compare ML output with the regex baseline."}

    comparison = baseline_metrics.get("per_type_comparison") or {}
    if not comparison:
        return {"empty": True, "title": "Comparison unavailable", "subtitle": "No incidents are available for comparison."}

    labels = list(comparison.keys())
    return {
        "empty": False,
        "labels": labels,
        "ml_values": [comparison[lbl]["ml"] for lbl in labels],
        "regex_values": [comparison[lbl]["regex"] for lbl in labels],
        "overlap_values": [comparison[lbl]["overlap"] for lbl in labels],
        "title": "ML vs Regex Baseline",
        "xlabel": "Attack Type",
        "ylabel": "Incidents",
    }


def incidents_to_csv(incidents: list[dict], out_path: str):
    pd.DataFrame(incidents).to_csv(out_path, index=False, encoding="utf-8")
