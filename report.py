import os

import pandas as pd

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

FIG_SIZE = (12, 5)
FIG_DPI = 150
ATTACK_COLORS = {
    "SQLI": "#D7263D",
    "BRUTE_FORCE": "#F4A259",
    "DOS": "#7B2CBF",
}

ANOMALY_PREFIX = "ANOMALY"

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

    s = df.set_index("ts").resample("1min").size()
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    ax.plot(s.index, s.values, color="#0B7285", linewidth=2)
    ax.fill_between(s.index, s.values, color="#0B7285", alpha=0.15)

    locator = mdates.AutoDateLocator(minticks=4, maxticks=10)
    formatter = mdates.ConciseDateFormatter(locator)
    ax.xaxis.set_major_locator(locator)
    ax.xaxis.set_major_formatter(formatter)
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

    s = df["ip"].value_counts().head(n)
    s = s.sort_values()
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    bars = ax.barh(s.index.astype(str), s.values, color="#1D3557", alpha=0.9)
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
    include_anomalies: bool = False,
):
    if incidents_df.empty:
        _plot_empty(out_path, "No attacks detected", "No incidents were detected for this log.")
        return

    d = incidents_df.copy()
    d["start"] = pd.to_datetime(d["start"], errors="coerce")
    d = d.dropna(subset=["start", "type"])
    if not include_anomalies:
        d = d[~d["type"].astype(str).str.startswith(ANOMALY_PREFIX)]

    if d.empty:
        _plot_empty(out_path, "No rule-based attacks", "Only anomaly incidents were detected.")
        return

    d["bucket"] = d["start"].dt.floor(bucket)
    pivot = (
        d.groupby(["bucket", "type"])
        .size()
        .unstack(fill_value=0)
        .sort_index()
    )

    if pivot.empty:
        _plot_empty(out_path, "No attacks detected", "No incidents were detected for this log.")
        return

    # Упорядочиваем легенду по частоте встречаемости.
    ordered_types = pivot.sum(axis=0).sort_values(ascending=False).index
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

    for idx, attack_type in enumerate(pivot.columns):
        values = pivot[attack_type].to_numpy()
        color = ATTACK_COLORS.get(attack_type, "#457B9D")
        x_pos = x + offset_start + idx * bar_width
        ax.bar(
            x_pos,
            values,
            width=bar_width * 0.92,
            color=color,
            label=attack_type,
            align="center",
        )

    # Явно задаем подписи тиков, чтобы не появлялась offset-надпись даты поверх графика.
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

    ax.set_title("Attack Timeline By Type", fontsize=13, fontweight="bold")
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


def incidents_to_csv(incidents: list[dict], out_path: str):
    pd.DataFrame(incidents).to_csv(out_path, index=False, encoding="utf-8")
