import os
from io import BytesIO
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_file, flash
import pandas as pd
from werkzeug.utils import secure_filename

from parser import parse_file
from detectors import run_all
from report import ensure_dir, plot_requests_over_time, plot_top_ips, incidents_to_csv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
GEN_DIR = os.path.join(BASE_DIR, "static", "generated")

ALLOWED_EXT = {".log", ".txt"}
MAX_FILE_SIZE = 15 * 1024 * 1024
TIME_FORMAT = "%Y-%m-%d %H:%M:%S %z"

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"

ensure_dir(UPLOAD_DIR)
ensure_dir(GEN_DIR)

def allowed(filename: str) -> bool:
    """Проверяем расширение файла до чтения содержимого."""
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXT

def format_ts(ts) -> str:
    """Единый формат даты для отчетов."""
    if ts is None:
        return ""
    try:
        return pd.Timestamp(ts).strftime(TIME_FORMAT)
    except Exception:
        return str(ts)

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/analyze")
def analyze():
    f = request.files.get("logfile")
    if not f or f.filename.strip() == "":
        flash("Пожалуйста, выберите файл лога.")
        return redirect(url_for("index"))

    if not allowed(f.filename):
        flash("Поддерживаются только файлы .log или .txt.")
        return redirect(url_for("index"))

    filename = secure_filename(f.filename)
    raw = f.read()
    if len(raw) > MAX_FILE_SIZE:
        flash("Файл слишком большой. Лимит: 15 MB.")
        return redirect(url_for("index"))

    rows = parse_file(BytesIO(raw))
    if not rows:
        flash("Не удалось распознать формат лога. Проверьте, что это access-log.")
        return redirect(url_for("index"))

    df = pd.DataFrame(rows)
    # Нормализуем время для отчетов.
    df["ts"] = pd.to_datetime(df["ts"].dt.tz_convert("Europe/Moscow"))

    incidents = run_all(df)
    inc_df = pd.DataFrame(incidents) if incidents else pd.DataFrame(columns=[
        "type","severity","ip","start","end","evidence","tactic","technique","technique_id"
    ])

    tag = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    p1 = os.path.join(GEN_DIR, f"rps_{tag}.png")
    p2 = os.path.join(GEN_DIR, f"topip_{tag}.png")
    plot_requests_over_time(df, p1)
    plot_top_ips(df, p2)


    csv_path = os.path.join(GEN_DIR, f"incidents_{tag}.csv")
    incidents_to_csv(incidents, csv_path)

    incidents_view = []
    for inc in incidents:
        inc_view = dict(inc)
        inc_view["start_fmt"] = format_ts(inc.get("start"))
        inc_view["end_fmt"] = format_ts(inc.get("end"))
        incidents_view.append(inc_view)

    summary = {
        "total_requests": int(len(df)),
        "unique_ips": int(df["ip"].nunique()),
        "time_min": format_ts(df["ts"].min()),
        "time_max": format_ts(df["ts"].max()),
        "incidents_total": int(len(inc_df)),
    }
    counts = inc_df["type"].value_counts().to_dict() if len(inc_df) else {}

    return render_template(
        "report.html",
        summary=summary,
        counts=counts,
        incidents=incidents_view,
        chart_rps=url_for("static", filename=f"generated/rps_{tag}.png"),
        chart_topip=url_for("static", filename=f"generated/topip_{tag}.png"),
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
