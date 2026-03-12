import os
from datetime import datetime, timezone
from io import BytesIO

import pandas as pd
from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from accuracy import annotate_ml_matches, evaluate_accuracy
from detectors import run_regex_all
from ml_detector import MLDetector
from parser import parse_file
from report import (
    ensure_dir,
    incidents_to_csv,
    plot_attacks_over_time,
    plot_confidence_distribution,
    plot_ml_vs_regex_comparison,
    plot_requests_over_time,
    plot_top_ips,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
GEN_DIR = os.path.join(BASE_DIR, "static", "generated")

ALLOWED_EXT = {".log", ".txt"}
MAX_FILE_SIZE = 15 * 1024 * 1024
APP_TZ = "Europe/Moscow"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S %z"
INCIDENT_COLUMNS = [
    "type",
    "severity",
    "ip",
    "start",
    "end",
    "confidence",
    "regex_match",
    "request_count",
    "evidence",
    "tactic",
    "technique",
    "technique_id",
]

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"
ml_detector = MLDetector()

ensure_dir(UPLOAD_DIR)
ensure_dir(GEN_DIR)


def allowed(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXT


def format_ts(value) -> str:
    if value is None:
        return ""
    try:
        return pd.Timestamp(value).strftime(TIME_FORMAT)
    except Exception:
        return str(value)


def validate_upload(file_obj) -> tuple[bool, str]:
    if not file_obj or file_obj.filename.strip() == "":
        return False, "Пожалуйста, выберите файл лога."
    if not allowed(file_obj.filename):
        return False, "Поддерживаются только файлы .log или .txt."
    return True, ""


def build_requests_df(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    ts = pd.to_datetime(df["ts"], errors="coerce", utc=True)
    df = df.assign(ts=ts.dt.tz_convert(APP_TZ))
    return df.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)


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
        view.append(item)
    return view


def build_summary(df: pd.DataFrame, incidents_df: pd.DataFrame) -> dict:
    return {
        "total_requests": int(len(df)),
        "unique_ips": int(df["ip"].nunique()),
        "time_min": format_ts(df["ts"].min()),
        "time_max": format_ts(df["ts"].max()),
        "incidents_total": int(len(incidents_df)),
    }


def artifact_paths(tag: str) -> dict[str, str]:
    return {
        "rps": os.path.join(GEN_DIR, f"rps_{tag}.png"),
        "topip": os.path.join(GEN_DIR, f"topip_{tag}.png"),
        "attacks": os.path.join(GEN_DIR, f"attacks_{tag}.png"),
        "confidence": os.path.join(GEN_DIR, f"confidence_{tag}.png"),
        "comparison": os.path.join(GEN_DIR, f"comparison_{tag}.png"),
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

    regex_incidents = run_regex_all(df)
    accuracy_metrics = None
    model_error = None
    analysis_mode = "ml"

    try:
        ml_incidents = ml_detector.predict(df)
        incidents = annotate_ml_matches(ml_incidents, regex_incidents)
        accuracy_metrics = evaluate_accuracy(df, ml_incidents, regex_incidents)
    except Exception as exc:
        model_error = str(exc)
        analysis_mode = "regex_fallback"
        incidents = []
        for incident in regex_incidents:
            item = dict(incident)
            item["confidence"] = None
            item["regex_match"] = True
            item["request_count"] = item.get("request_count") or 1
            incidents.append(item)

    incidents_df = build_incidents_df(incidents)
    summary = build_summary(df, incidents_df)
    counts = incidents_df["type"].value_counts().to_dict() if not incidents_df.empty else {}

    tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    paths = artifact_paths(tag)
    plot_requests_over_time(df, paths["rps"])
    plot_top_ips(df, paths["topip"])
    plot_attacks_over_time(incidents_df, paths["attacks"], include_anomalies=True)
    plot_confidence_distribution(incidents_df, paths["confidence"])
    plot_ml_vs_regex_comparison(accuracy_metrics, paths["comparison"])
    incidents_to_csv(incidents, paths["csv"])

    return render_template(
        "report.html",
        summary=summary,
        counts=counts,
        incidents=build_incidents_view(incidents),
        accuracy=accuracy_metrics,
        analysis_mode=analysis_mode,
        model_error=model_error,
        chart_rps=url_for("static", filename=f"generated/rps_{tag}.png"),
        chart_topip=url_for("static", filename=f"generated/topip_{tag}.png"),
        chart_attacks=url_for("static", filename=f"generated/attacks_{tag}.png"),
        chart_confidence=url_for("static", filename=f"generated/confidence_{tag}.png"),
        chart_comparison=url_for("static", filename=f"generated/comparison_{tag}.png"),
        csv_url=url_for("download_csv", fname=f"incidents_{tag}.csv"),
    )


@app.get("/download/<fname>")
def download_csv(fname):
    path = os.path.join(GEN_DIR, secure_filename(fname))
    if not os.path.exists(path):
        flash("Файл отчета не найден")
        return redirect(url_for("index"))
    return send_file(path, as_attachment=True, download_name=fname)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
