import os
from datetime import datetime, timezone
from io import BytesIO

import pandas as pd
from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from core.analysis import build_requests_df, run_analysis
from config import (
    ALLOWED_EXT,
    GEN_DIR,
    INCIDENT_COLUMNS,
    MAX_FILE_SIZE,
    MIN_ATTACK_CONFIDENCE,
    TIME_FORMAT,
    UPLOAD_DIR,
)
from core.ml_detector import MLDetector
from core.parser import parse_file
from core.report import (
    ensure_dir,
    incidents_to_csv,
    plot_attacks_over_time,
    plot_confidence_distribution,
    plot_ml_vs_regex_comparison,
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
        view.append(item)
    return view


def build_summary(df: pd.DataFrame, incidents_df: pd.DataFrame, suppressed_anomalies: int = 0) -> dict:
    return {
        "total_requests": int(len(df)),
        "unique_ips": int(df["ip"].nunique()),
        "time_min": format_ts(df["ts"].min()),
        "time_max": format_ts(df["ts"].max()),
        "incidents_total": int(len(incidents_df)),
        "suppressed_anomalies": suppressed_anomalies,
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

    incidents, baseline_comparison, analysis_mode, model_error = run_analysis(df, ml_detector)

    incidents_df = build_incidents_df(incidents)
    suppressed = sum(inc.get("suppressed_anomalies", 0) for inc in incidents)
    summary = build_summary(df, incidents_df, suppressed_anomalies=suppressed)
    counts = incidents_df["type"].value_counts().to_dict() if not incidents_df.empty else {}

    tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    paths = artifact_paths(tag)
    plot_requests_over_time(df, paths["rps"])
    plot_top_ips(df, paths["topip"])
    plot_attacks_over_time(incidents_df, paths["attacks"], include_anomalies=True, min_confidence=MIN_ATTACK_CONFIDENCE)
    plot_confidence_distribution(incidents_df, paths["confidence"])
    plot_ml_vs_regex_comparison(baseline_comparison, paths["comparison"])
    incidents_to_csv(incidents, paths["csv"])

    return render_template(
        "report.html",
        summary=summary,
        counts=counts,
        incidents=build_incidents_view(incidents),
        baseline=baseline_comparison,
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
def download_csv(fname: str):
    path = os.path.join(GEN_DIR, secure_filename(fname))
    if not os.path.exists(path):
        flash("Файл отчета не найден")
        return redirect(url_for("index"))
    return send_file(path, as_attachment=True, download_name=fname)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
