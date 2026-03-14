import os
import tempfile
from typing import Optional

os.environ.setdefault("MPLCONFIGDIR", os.path.join(tempfile.gettempdir(), "bv_mpl"))
os.environ.setdefault("XDG_CACHE_HOME", tempfile.gettempdir())

import matplotlib
matplotlib.use("Agg")

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from config import ATTACK_COLORS, ATTACK_LABELS, FIG_DPI, FIG_SIZE


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _style_axes(ax, grid_axis: str = "y"):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis=grid_axis, linestyle="--", linewidth=0.7, alpha=0.25)


def _save_plot(fig, out_path: str):
    fig.savefig(out_path, dpi=FIG_DPI, facecolor="white", bbox_inches="tight", pad_inches=0.25)
    plt.close(fig)


def _plot_empty(out_path: str, title: str, subtitle: str):
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    ax.axis("off")
    ax.text(0.5, 0.56, title, ha="center", va="center", fontsize=15, fontweight="bold")
    ax.text(0.5, 0.44, subtitle, ha="center", va="center", fontsize=10, color="#6c757d")
    _save_plot(fig, out_path)


def plot_requests_over_time(df: pd.DataFrame, out_path: str):
    if df.empty:
        _plot_empty(out_path, "No requests found", "Upload a non-empty log file to build this chart.")
        return

    series = df.set_index("ts").resample("1min").size()
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    ax.plot(series.index, series.values, color="#0B7285", linewidth=2)
    ax.fill_between(series.index, series.values, color="#0B7285", alpha=0.15)

    locator = mdates.AutoDateLocator(minticks=4, maxticks=10)
    ax.xaxis.set_major_locator(locator)
    ax.xaxis.set_major_formatter(mdates.ConciseDateFormatter(locator))
    plt.setp(ax.get_xticklabels(), rotation=20, ha="right")

    ax.set_title("Requests Per Minute", fontsize=13, fontweight="bold")
    ax.set_xlabel("Time")
    ax.set_ylabel("Requests")
    _style_axes(ax, grid_axis="y")
    _save_plot(fig, out_path)


def plot_top_ips(df: pd.DataFrame, out_path: str, n: int = 10):
    if df.empty:
        _plot_empty(out_path, "No requests found", "Upload a non-empty log file to build this chart.")
        return

    series = df["ip"].value_counts().head(n).sort_values()
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    bars = ax.barh(series.index.astype(str), series.values, color="#1D3557", alpha=0.9)
    ax.bar_label(bars, fmt="%d", padding=4, fontsize=8)
    ax.set_title(f"Top {n} IPs By Request Count", fontsize=13, fontweight="bold")
    ax.set_xlabel("Requests")
    ax.set_ylabel("IP")
    _style_axes(ax, grid_axis="x")
    _save_plot(fig, out_path)


def plot_attacks_over_time(
    incidents_df: pd.DataFrame,
    out_path: str,
    bucket: str = "5min",
    min_confidence: float = 0.0,
):
    if incidents_df.empty:
        _plot_empty(out_path, "No attacks detected", "No incidents were detected for this log.")
        return

    data = incidents_df.copy()
    data["start"] = pd.to_datetime(data["start"], errors="coerce")
    data["type"] = data["type"].fillna("").astype(str).str.upper()
    data = data.dropna(subset=["start"])
    # Filter out low-confidence incidents from the chart
    if min_confidence > 0 and "confidence" in data.columns:
        conf = pd.to_numeric(data["confidence"], errors="coerce")
        data = data[conf.isna() | (conf >= min_confidence)]

    if data.empty:
        _plot_empty(out_path, "No attacks detected", "No incidents were detected for this log.")
        return

    data["bucket"] = data["start"].dt.floor(bucket)
    pivot = data.groupby(["bucket", "type"]).size().unstack(fill_value=0).sort_index()
    if pivot.empty:
        _plot_empty(out_path, "No attacks detected", "No incidents were detected for this log.")
        return

    attack_order = [label for label in ATTACK_LABELS if label != "NORMAL"]
    ordered_types = [label for label in attack_order if label in pivot.columns]
    ordered_types.extend(sorted(set(pivot.columns) - set(ordered_types)))
    pivot = pivot[ordered_types]

    fig, ax = plt.subplots(figsize=(12.8, 6.2))
    x = mdates.date2num(pivot.index.to_pydatetime())
    n_types = len(pivot.columns)
    if len(x) > 1:
        bucket_width = max(1e-6, float(pd.Series(x).diff().dropna().median()))
    else:
        bucket_width = max(1e-6, pd.to_timedelta(bucket).total_seconds() / 86400.0)

    group_width = bucket_width * 0.82
    bar_width = group_width / max(1, n_types)
    offset_start = -group_width / 2 + bar_width / 2

    for index, attack_type in enumerate(pivot.columns):
        values = pivot[attack_type].to_numpy()
        color = ATTACK_COLORS.get(attack_type, "#457B9D")
        x_pos = x + offset_start + index * bar_width
        ax.bar(x_pos, values, width=bar_width * 0.92, color=color, label=attack_type, align="center")

    max_ticks = 10
    tick_step = max(1, len(x) // max_ticks)
    tick_idx = list(range(0, len(x), tick_step))
    tick_x = x[tick_idx]
    same_day = pivot.index.normalize().nunique() == 1
    if same_day:
        tick_labels = [pivot.index[i].strftime("%H:%M") for i in tick_idx]
    else:
        tick_labels = [pivot.index[i].strftime("%m-%d %H:%M") for i in tick_idx]
    ax.set_xticks(tick_x)
    ax.set_xticklabels(tick_labels)
    plt.setp(ax.get_xticklabels(), rotation=22, ha="right")

    ax.set_title("Incident Timeline", fontsize=13, fontweight="bold")
    ax.set_xlabel("Time Buckets")
    ax.set_ylabel("Incidents")
    ax.margins(y=0.08)
    _style_axes(ax, grid_axis="y")
    ax.legend(
        title="Attack type",
        ncol=1,
        loc="upper left",
        bbox_to_anchor=(1.01, 1.0),
        frameon=False,
        fontsize=9,
        title_fontsize=9,
    )
    fig.subplots_adjust(right=0.79, bottom=0.24, top=0.92)
    _save_plot(fig, out_path)


def plot_confidence_distribution(incidents_df: pd.DataFrame, out_path: str):
    if incidents_df.empty or "confidence" not in incidents_df.columns:
        _plot_empty(out_path, "Confidence unavailable", "The model did not produce confidence scores.")
        return

    scores = pd.to_numeric(incidents_df["confidence"], errors="coerce").dropna()
    if scores.empty:
        _plot_empty(out_path, "Confidence unavailable", "The model did not produce confidence scores.")
        return

    fig, ax = plt.subplots(figsize=FIG_SIZE)
    bins = np.linspace(0, 1, 11)
    ax.hist(scores, bins=bins, color="#2A9D8F", edgecolor="white", alpha=0.9)
    ax.set_xlim(0, 1)
    ax.set_title("Model Confidence Distribution", fontsize=13, fontweight="bold")
    ax.set_xlabel("Confidence")
    ax.set_ylabel("Incidents")
    _style_axes(ax, grid_axis="y")
    _save_plot(fig, out_path)


def plot_ml_vs_regex_comparison(baseline_metrics: Optional[dict], out_path: str):
    if not baseline_metrics:
        _plot_empty(out_path, "Comparison unavailable", "Train a model to compare ML output with the regex baseline.")
        return

    comparison = baseline_metrics.get("per_type_comparison") or {}
    if not comparison:
        _plot_empty(out_path, "Comparison unavailable", "No incidents are available for comparison.")
        return

    labels = list(comparison.keys())
    ml_values = [comparison[label]["ml"] for label in labels]
    regex_values = [comparison[label]["regex"] for label in labels]
    overlap_values = [comparison[label]["overlap"] for label in labels]

    x = np.arange(len(labels))
    width = 0.24
    fig, ax = plt.subplots(figsize=(12.8, 5.6))
    ax.bar(x - width, ml_values, width=width, label="ML", color="#0B7285")
    ax.bar(x, regex_values, width=width, label="Regex", color="#6C757D")
    ax.bar(x + width, overlap_values, width=width, label="Overlap", color="#74C69D")

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_title("ML vs Regex Baseline", fontsize=13, fontweight="bold")
    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Incidents")
    _style_axes(ax, grid_axis="y")
    ax.legend(frameon=False)
    _save_plot(fig, out_path)


def incidents_to_csv(incidents: list[dict], out_path: str):
    pd.DataFrame(incidents).to_csv(out_path, index=False, encoding="utf-8")
