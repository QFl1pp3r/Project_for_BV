import os
from datetime import datetime, timezone
from io import BytesIO
from uuid import uuid4

import pandas as pd
from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from detectors import run_all
from history_store import delete_entry, get_entry, init_store, load_history, save_history, upsert_entry
from parser import parse_file
from report import (
    ensure_dir,
    incidents_to_csv,
    plot_attacks_over_time,
    plot_requests_over_time,
    plot_top_ips,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
GEN_DIR = os.path.join(BASE_DIR, "static", "generated")
DATA_DIR = os.path.join(BASE_DIR, "data")
HISTORY_FILE = os.path.join(DATA_DIR, "analysis_history.json")

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
ensure_dir(DATA_DIR)
init_store(HISTORY_FILE)


def allowed(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXT


def format_ts(ts) -> str:
    if ts is None:
        return ""
    try:
        stamp = pd.Timestamp(ts)
        if pd.isna(stamp):
            return ""
        if stamp.tzinfo is None:
            stamp = stamp.tz_localize(APP_TZ)
        else:
            stamp = stamp.tz_convert(APP_TZ)
        return stamp.strftime(TIME_FORMAT)
    except Exception:
        return str(ts)


def format_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(max(0, size_bytes))
    unit = units[0]

    for unit in units:
        if size < 1024 or unit == units[-1]:
            break
        size /= 1024

    if unit == "B":
        return f"{int(size)} {unit}"
    return f"{size:.1f} {unit}"


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
        item["start"] = format_ts(inc.get("start"))
        item["end"] = format_ts(inc.get("end"))
        item["start_fmt"] = item["start"]
        item["end_fmt"] = item["end"]
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


def build_analysis_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{ts}_{uuid4().hex[:8]}"


def build_artifact_names(analysis_id: str) -> dict[str, str]:
    return {
        "rps": f"rps_{analysis_id}.png",
        "topip": f"topip_{analysis_id}.png",
        "attacks": f"attacks_{analysis_id}.png",
        "csv": f"incidents_{analysis_id}.csv",
    }


def artifact_paths(artifacts: dict[str, str]) -> dict[str, str]:
    return {
        name: os.path.join(GEN_DIR, os.path.basename(filename))
        for name, filename in artifacts.items()
    }


def build_history_entry(
    analysis_id: str,
    filename: str,
    file_size: int,
    summary: dict,
    counts: dict,
    incidents_view: list[dict],
    artifacts: dict[str, str],
) -> dict:
    return {
        "id": analysis_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "filename": filename,
        "size_bytes": int(file_size),
        "summary": summary,
        "counts": {str(key): int(value) for key, value in counts.items()},
        "incidents": incidents_view,
        "artifacts": {name: os.path.basename(value) for name, value in artifacts.items()},
    }


def build_history_view(entries: list[dict]) -> list[dict]:
    items = []
    for entry in entries:
        artifacts = entry.get("artifacts", {})
        csv_name = os.path.basename(artifacts.get("csv", ""))
        items.append(
            {
                **entry,
                "created_at_fmt": format_ts(entry.get("created_at")),
                "size_fmt": format_size(int(entry.get("size_bytes", 0))),
                "report_url": url_for("view_analysis", analysis_id=entry["id"]),
                "csv_url": url_for("download_csv", fname=csv_name) if csv_name else None,
            }
        )
    return items


def build_report_context(entry: dict) -> dict:
    artifacts = entry.get("artifacts", {})
    return {
        "analysis_id": entry.get("id", ""),
        "source_name": entry.get("filename", "unknown.log"),
        "created_at_fmt": format_ts(entry.get("created_at")),
        "size_fmt": format_size(int(entry.get("size_bytes", 0))),
        "summary": entry.get("summary", {}),
        "counts": entry.get("counts", {}),
        "incidents": entry.get("incidents", []),
        "chart_rps": url_for("static", filename=f"generated/{os.path.basename(artifacts.get('rps', ''))}"),
        "chart_topip": url_for("static", filename=f"generated/{os.path.basename(artifacts.get('topip', ''))}"),
        "chart_attacks": url_for("static", filename=f"generated/{os.path.basename(artifacts.get('attacks', ''))}"),
        "csv_url": url_for("download_csv", fname=os.path.basename(artifacts.get("csv", ""))),
        "delete_url": url_for("delete_analysis", analysis_id=entry.get("id", "")),
        "history_url": url_for("index"),
    }


def delete_analysis_artifacts(entry: dict):
    for filename in entry.get("artifacts", {}).values():
        path = os.path.join(GEN_DIR, os.path.basename(filename))
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                continue


@app.get("/")
def index():
    history = build_history_view(load_history(HISTORY_FILE))
    return render_template("index.html", history=history)


@app.post("/analyze")
def analyze():
    file_obj = request.files.get("logfile")
    ok, err = validate_upload(file_obj)
    if not ok:
        flash(err, "warning")
        return redirect(url_for("index"))

    raw = file_obj.read()
    if len(raw) > MAX_FILE_SIZE:
        flash("Файл слишком большой. Лимит: 15 MB.", "warning")
        return redirect(url_for("index"))

    rows = parse_file(BytesIO(raw))
    if not rows:
        flash("Не удалось распознать формат лога. Проверьте, что это access-log.", "warning")
        return redirect(url_for("index"))

    df = build_requests_df(rows)
    if df.empty:
        flash("Лог распознан, но не удалось обработать временные метки.", "warning")
        return redirect(url_for("index"))

    incidents = run_all(df)
    inc_df = build_incidents_df(incidents)

    analysis_id = build_analysis_id()
    artifacts = build_artifact_names(analysis_id)
    paths = artifact_paths(artifacts)

    plot_requests_over_time(df, paths["rps"])
    plot_top_ips(df, paths["topip"])
    plot_attacks_over_time(inc_df, paths["attacks"], include_anomalies=False)
    incidents_to_csv(incidents, paths["csv"])

    incidents_view = build_incidents_view(incidents)
    summary = build_summary(df, inc_df)
    counts = inc_df["type"].value_counts().to_dict() if len(inc_df) else {}
    entry = build_history_entry(
        analysis_id=analysis_id,
        filename=file_obj.filename,
        file_size=len(raw),
        summary=summary,
        counts=counts,
        incidents_view=incidents_view,
        artifacts=artifacts,
    )
    upsert_entry(HISTORY_FILE, entry)

    flash("Анализ сохранен в истории.", "success")
    return redirect(url_for("view_analysis", analysis_id=analysis_id))


@app.get("/report/<analysis_id>")
def view_analysis(analysis_id):
    entry = get_entry(HISTORY_FILE, analysis_id)
    if not entry:
        flash("Запрошенный анализ не найден в истории.", "warning")
        return redirect(url_for("index"))
    return render_template("report.html", **build_report_context(entry))


@app.post("/analysis/<analysis_id>/delete")
def delete_analysis(analysis_id):
    removed = delete_entry(HISTORY_FILE, analysis_id)
    if removed is None:
        flash("Анализ уже удален или не найден.", "warning")
        return redirect(url_for("index"))

    delete_analysis_artifacts(removed)
    flash(f"Удален анализ файла: {removed.get('filename', analysis_id)}.", "success")
    return redirect(url_for("index"))


@app.post("/history/delete-all")
def delete_all_analyses():
    entries = load_history(HISTORY_FILE)
    if not entries:
        flash("История уже пуста.", "warning")
        return redirect(url_for("index"))

    for entry in entries:
        delete_analysis_artifacts(entry)
    save_history(HISTORY_FILE, [])

    flash("История анализов полностью очищена.", "success")
    return redirect(url_for("index"))


@app.get("/download/<fname>")
def download_csv(fname):
    path = os.path.join(GEN_DIR, secure_filename(fname))
    if not os.path.exists(path):
        flash("Файл отчета не найден", "warning")
        return redirect(url_for("index"))
    return send_file(path, as_attachment=True, download_name=fname)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
    """
    Для запуска на хосте локально:
    app.run(host='127.0.0.1', port=5000, debug=False)
    """
