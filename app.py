import os
from datetime import datetime
from io import BytesIO

from flask import Flask, render_template, request, redirect, url_for, send_file, flash
import pandas as pd
from werkzeug.utils import secure_filename

from parser import parse_file
from detectors import run_all
from report import (
    ensure_dir,
    plot_requests_over_time,
    plot_top_ips,
    plot_attacks_over_time,
    incidents_to_csv,
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
    "evidence",
    "tactic",
    "technique",
    "technique_id",
]

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"

ensure_dir(UPLOAD_DIR)
ensure_dir(GEN_DIR)

def allowed(filename: str) -> bool:
    """Check extension before reading file contents."""
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXT


def format_ts(ts) -> str:
    """UI-friendly datetime formatting."""
    if ts is None:
        return ""
    try:
        return pd.Timestamp(ts).strftime(TIME_FORMAT)
    except Exception:
        return str(ts)


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
    return pd.DataFrame(incidents)


def build_incidents_view(incidents: list[dict]) -> list[dict]:
    view = []
    for inc in incidents:
        item = dict(inc)
        item["start_fmt"] = format_ts(inc.get("start"))
        item["end_fmt"] = format_ts(inc.get("end"))
        view.append(item)
    return view


def build_summary(df: pd.DataFrame, inc_df: pd.DataFrame) -> dict:
    return {
        "total_requests": int(len(df)),
        "unique_ips": int(df["ip"].nunique()),
        "time_min": format_ts(df["ts"].min()),
        "time_max": format_ts(df["ts"].max()),
        "incidents_total": int(len(inc_df)),
    }


def artifact_paths(tag: str) -> dict[str, str]:
    return {
        "rps": os.path.join(GEN_DIR, f"rps_{tag}.png"),
        "topip": os.path.join(GEN_DIR, f"topip_{tag}.png"),
        "attacks": os.path.join(GEN_DIR, f"attacks_{tag}.png"),
        "csv": os.path.join(GEN_DIR, f"incidents_{tag}.csv"),
    }


@app.get("/")
def index():
    return render_template("index.html")

@app.post("/analyze")
def analyze():
    f = request.files.get("logfile")
    ok, err = validate_upload(f)
    if not ok:
        flash(err)
        return redirect(url_for("index"))

    raw = f.read()
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

    incidents = run_all(df)
    inc_df = build_incidents_df(incidents)

    tag = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    paths = artifact_paths(tag)

    plot_requests_over_time(df, paths["rps"])
    plot_top_ips(df, paths["topip"])
    # График атак строим без ANOMALY*, но в таблице они сохраняются.
    plot_attacks_over_time(inc_df, paths["attacks"], include_anomalies=False)
    incidents_to_csv(incidents, paths["csv"])

    incidents_view = build_incidents_view(incidents)
    summary = build_summary(df, inc_df)
    counts = inc_df["type"].value_counts().to_dict() if len(inc_df) else {}

    return render_template(
        "report.html",
        summary=summary,
        counts=counts,
        incidents=incidents_view,
        chart_rps=url_for("static", filename=f"generated/rps_{tag}.png"),
        chart_topip=url_for("static", filename=f"generated/topip_{tag}.png"),
        chart_attacks=url_for("static", filename=f"generated/attacks_{tag}.png"),
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
    app.run(host='0.0.0.0', port=5000, debug=False)
    """
    Для запуска на хосте локально:
    app.run(host='127.0.0.1', port=5000, debug=False)
    """
