import os
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional

import pandas as pd
from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from core.analysis import build_requests_df, run_analysis
from config import (
    ALLOWED_EXT,
    ATTACK_LABELS,
    GEN_DIR,
    INCIDENT_COLUMNS,
    MAX_FILE_SIZE,
    MIN_ATTACK_CONFIDENCE,
    TIME_FORMAT,
    UPLOAD_DIR,
)
from core.ml_detector import MLDetector
from core.model_metrics import load_model_metrics
from core.parser import parse_file
from core.report import (
    ensure_dir,
    incidents_to_csv,
    plot_attacks_over_time,
    plot_confidence_distribution,
    plot_requests_over_time,
    plot_top_ips,
)

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"
ml_detector = MLDetector()

ensure_dir(UPLOAD_DIR)
ensure_dir(GEN_DIR)


def allowed(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXT


def format_ts(value: object) -> str:
    if value is None:
        return ""
    try:
        return pd.Timestamp(value).strftime(TIME_FORMAT)
    except Exception:
        return str(value)


def format_pct(value: object) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{float(value) * 100:.1f}%"
    except Exception:
        return "n/a"


def build_model_metrics_view(metrics: Optional[dict]) -> Optional[dict]:
    if not metrics:
        return None

    scope_labels = {
        "internal_holdout_only": "Внутренний holdout",
    }
    view = dict(metrics)
    view["trained_at_fmt"] = format_ts(metrics.get("trained_at"))
    view["accuracy_fmt"] = format_pct(metrics.get("accuracy"))
    view["macro_precision_fmt"] = format_pct(metrics.get("macro_precision"))
    view["macro_recall_fmt"] = format_pct(metrics.get("macro_recall"))
    view["macro_f1_fmt"] = format_pct(metrics.get("macro_f1"))
    view["weighted_f1_fmt"] = format_pct(metrics.get("weighted_f1"))
    view["validation_scope_label"] = scope_labels.get(metrics.get("validation_scope"), metrics.get("validation_scope") or "n/a")

    attack_order = {label: index for index, label in enumerate(ATTACK_LABELS)}
    per_class_rows = sorted(
        metrics.get("per_class", []),
        key=lambda row: (attack_order.get(str(row.get("label")), len(attack_order)), str(row.get("label") or "")),
    )

    per_class = []
    for row in per_class_rows:
        item = dict(row)
        item["precision_fmt"] = format_pct(row.get("precision"))
        item["recall_fmt"] = format_pct(row.get("recall"))
        item["f1_fmt"] = format_pct(row.get("f1"))
        per_class.append(item)
    view["per_class"] = per_class
    return view


def validate_upload(file_obj) -> tuple[bool, str]:
    if not file_obj or file_obj.filename.strip() == "":
        return False, "Пожалуйста, выберите файл лога."
    if not allowed(file_obj.filename):
        return False, "Поддерживаются только файлы .log или .txt."
    return True, ""


def build_incidents_df(incidents: list[dict]) -> pd.DataFrame:
    if not incidents:
        return pd.DataFrame(columns=INCIDENT_COLUMNS)
    frame = pd.DataFrame(incidents)
    for column in INCIDENT_COLUMNS:
        if column not in frame.columns:
            frame[column] = None
    return frame[INCIDENT_COLUMNS]


def build_incidents_view(incidents: list[dict]) -> list[dict]:
    view = []
    for incident in incidents:
        item = dict(incident)
        item["start_fmt"] = format_ts(item.get("start"))
        item["end_fmt"] = format_ts(item.get("end"))
        confidence = item.get("confidence")
        item["confidence_fmt"] = "" if confidence is None else f"{float(confidence) * 100:.1f}%"
        item["source"] = item.get("source") or "n/a"
        view.append(item)
    return view


def build_summary(df: pd.DataFrame, incidents_df: pd.DataFrame) -> dict:
    detected_requests_total = 0
    if not incidents_df.empty and "request_count" in incidents_df.columns:
        detected_requests_total = int(pd.to_numeric(incidents_df["request_count"], errors="coerce").fillna(0).sum())

    return {
        "total_requests": int(len(df)),
        "unique_ips": int(df["ip"].nunique()),
        "time_min": format_ts(df["ts"].min()),
        "time_max": format_ts(df["ts"].max()),
        "incidents_total": int(len(incidents_df)),
        "detected_requests_total": detected_requests_total,
    }


def ordered_attack_breakdown(incidents_df: pd.DataFrame) -> list[dict]:
    if incidents_df.empty or "type" not in incidents_df.columns:
        return []

    breakdown_df = incidents_df.copy()
    breakdown_df["type"] = breakdown_df["type"].fillna("").astype(str).str.upper()
    breakdown_df["request_count"] = pd.to_numeric(
        breakdown_df.get("request_count"),
        errors="coerce",
    ).fillna(0)

    aggregated = (
        breakdown_df.groupby("type", dropna=False)
        .agg(
            incidents=("type", "size"),
            requests=("request_count", "sum"),
        )
        .reset_index()
    )

    attack_order = [label for label in ATTACK_LABELS if label != "NORMAL"]
    order_map = {label: index for index, label in enumerate(attack_order)}
    aggregated = aggregated.sort_values(
        by="type",
        key=lambda column: column.map(lambda value: order_map.get(str(value), len(order_map))),
    )

    return [
        {
            "label": str(row["type"]),
            "incidents": int(row["incidents"]),
            "requests": int(row["requests"]),
        }
        for _, row in aggregated.iterrows()
    ]


def artifact_paths(tag: str) -> dict[str, str]:
    return {
        "rps": os.path.join(GEN_DIR, f"rps_{tag}.png"),
        "topip": os.path.join(GEN_DIR, f"topip_{tag}.png"),
        "attacks": os.path.join(GEN_DIR, f"attacks_{tag}.png"),
        "confidence": os.path.join(GEN_DIR, f"confidence_{tag}.png"),
        "csv": os.path.join(GEN_DIR, f"incidents_{tag}.csv"),
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    file_obj = request.files.get("logfile")
    ok, err = validate_upload(file_obj)
    if not ok:
        flash(err)
        return redirect(url_for("index"))

    raw = file_obj.read()
    if len(raw) > MAX_FILE_SIZE:
        flash("Файл слишком большой. Лимит: 15 MB.")
        return redirect(url_for("index"))

    rows = parse_file(BytesIO(raw))
    if not rows:
        flash("Не удалось распознать формат лога. Проверьте, что это access-log.")
        return redirect(url_for("index"))

    df = build_requests_df(rows)
    if df.empty:
        flash("Лог распознан, но не удалось обработать временные метки.")
        return redirect(url_for("index"))

    incidents, _baseline_comparison, analysis_mode, model_error = run_analysis(df, ml_detector)
    model_metrics, model_metrics_error = load_model_metrics()

    incidents_df = build_incidents_df(incidents)
    summary = build_summary(df, incidents_df)
    counts = ordered_attack_breakdown(incidents_df)

    tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    paths = artifact_paths(tag)
    plot_requests_over_time(df, paths["rps"])
    plot_top_ips(df, paths["topip"])
    plot_attacks_over_time(incidents_df, paths["attacks"], min_confidence=MIN_ATTACK_CONFIDENCE)
    plot_confidence_distribution(incidents_df, paths["confidence"])
    incidents_to_csv(incidents, paths["csv"])

    return render_template(
        "report.html",
        summary=summary,
        counts=counts,
        incidents=build_incidents_view(incidents),
        analysis_mode=analysis_mode,
        model_error=model_error,
        model_metrics=build_model_metrics_view(model_metrics),
        model_metrics_error=model_metrics_error,
        chart_rps=url_for("static", filename=f"generated/rps_{tag}.png"),
        chart_topip=url_for("static", filename=f"generated/topip_{tag}.png"),
        chart_attacks=url_for("static", filename=f"generated/attacks_{tag}.png"),
        chart_confidence=url_for("static", filename=f"generated/confidence_{tag}.png"),
        csv_url=url_for("download_csv", fname=f"incidents_{tag}.csv"),
    )


@app.get("/download/<fname>")
def download_csv(fname: str):
    path = os.path.join(GEN_DIR, secure_filename(fname))
    if not os.path.exists(path):
        flash("Файл отчета не найден")
        return redirect(url_for("index"))
    return send_file(path, as_attachment=True, download_name=fname)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
