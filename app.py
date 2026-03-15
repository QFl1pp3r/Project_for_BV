import os
import json
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional
from uuid import uuid4

import pandas as pd
from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, url_for
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
from history_store import delete_entry, get_entry, init_store, load_history, save_history, upsert_entry


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
HISTORY_FILE = os.path.join(DATA_DIR, "analysis_history.json")

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"
ml_detector = MLDetector()

ensure_dir(UPLOAD_DIR)
ensure_dir(GEN_DIR)
ensure_dir(DATA_DIR)
init_store(HISTORY_FILE)


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
        item["start"] = format_ts(item.get("start"))
        item["end"] = format_ts(item.get("end"))
        item["start_fmt"] = item["start"]
        item["end_fmt"] = item["end"]
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


def build_analysis_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{ts}_{uuid4().hex[:8]}"


def build_history_entry(
    analysis_id: str,
    filename: str,
    file_size: int,
    summary: dict,
    counts: list[dict],
    incidents_view: list[dict],
    artifacts: dict[str, str],
    analysis_mode: str,
    model_error: Optional[str],
) -> dict:
    return {
        "id": analysis_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "filename": filename,
        "size_bytes": int(file_size),
        "summary": summary,
        "counts": counts,
        "incidents": incidents_view,
        "artifacts": {name: os.path.basename(value) for name, value in artifacts.items()},
        "analysis_mode": analysis_mode,
        "model_error": model_error,
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
    model_metrics, model_metrics_error = load_model_metrics()
    return {
        "analysis_id": entry.get("id", ""),
        "source_name": entry.get("filename", "unknown.log"),
        "created_at_fmt": format_ts(entry.get("created_at")),
        "size_fmt": format_size(int(entry.get("size_bytes", 0))),
        "summary": entry.get("summary", {}),
        "counts": entry.get("counts", []),
        "incidents": entry.get("incidents", []),
        "analysis_mode": entry.get("analysis_mode", "ml"),
        "model_error": entry.get("model_error"),
        "model_metrics": build_model_metrics_view(model_metrics),
        "model_metrics_error": model_metrics_error,
        "chart_rps": url_for("static", filename=f"generated/{os.path.basename(artifacts.get('rps', ''))}"),
        "chart_topip": url_for("static", filename=f"generated/{os.path.basename(artifacts.get('topip', ''))}"),
        "chart_attacks": url_for("static", filename=f"generated/{os.path.basename(artifacts.get('attacks', ''))}"),
        "chart_confidence": url_for("static", filename=f"generated/{os.path.basename(artifacts.get('confidence', ''))}"),
        "csv_url": url_for("download_csv", fname=os.path.basename(artifacts.get("csv", ""))),
        "delete_url": url_for("delete_analysis", analysis_id=entry.get("id", "")),
        "history_url": url_for("index"),
    }


def delete_analysis_artifacts(entry: dict) -> None:
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

    incidents, _baseline_comparison, analysis_mode, model_error = run_analysis(df, ml_detector)
    incidents_df = build_incidents_df(incidents)
    summary = build_summary(df, incidents_df)
    counts = ordered_attack_breakdown(incidents_df)

    analysis_id = build_analysis_id()
    paths = artifact_paths(analysis_id)
    plot_requests_over_time(df, paths["rps"])
    plot_top_ips(df, paths["topip"])
    plot_attacks_over_time(incidents_df, paths["attacks"], min_confidence=MIN_ATTACK_CONFIDENCE)
    plot_confidence_distribution(incidents_df, paths["confidence"])
    incidents_to_csv(incidents, paths["csv"])

    incidents_view = build_incidents_view(incidents)
    entry = build_history_entry(
        analysis_id=analysis_id,
        filename=file_obj.filename,
        file_size=len(raw),
        summary=summary,
        counts=counts,
        analysis_mode=analysis_mode,
        model_error=model_error,
        incidents_view=incidents_view,
        artifacts=paths,
    )
    upsert_entry(HISTORY_FILE, entry)

    flash("Анализ сохранен в истории.", "success")
    return redirect(url_for("view_analysis", analysis_id=analysis_id))


@app.get("/report/<analysis_id>")
def view_analysis(analysis_id: str):
    entry = get_entry(HISTORY_FILE, analysis_id)
    if not entry:
        flash("Запрошенный анализ не найден в истории.", "warning")
        return redirect(url_for("index"))
    return render_template("report.html", **build_report_context(entry))


@app.post("/analysis/<analysis_id>/delete")
def delete_analysis(analysis_id: str):
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
def download_csv(fname: str):
    path = os.path.join(GEN_DIR, secure_filename(fname))
    if not os.path.exists(path):
        flash("Файл отчета не найден", "warning")
        return redirect(url_for("index"))
    return send_file(path, as_attachment=True, download_name=fname)


# ------------------------------
# Streaming Dashboard
# ------------------------------
def get_streaming_redis():
    """Lazy Redis connection for streaming dashboard"""
    try:
        from streaming.redis_client import r as redis_client
        redis_client.ping()
        return redis_client
    except Exception:
        return None


@app.get("/streaming")
def streaming_dashboard():
    return render_template("streaming.html")


@app.get("/api/streaming/status")
def streaming_status():
    rc = get_streaming_redis()
    if rc is None:
        return jsonify({"error": "Redis unavailable"}), 503

    THRESHOLDS = {"normal": 100, "suspicious": 250, "warning": 1000}

    all_ips = rc.hgetall("ip:counter")
    queue_size = rc.zcard("ip:queue")

    ip_list = []
    level_counts = {"normal": 0, "suspicious": 0, "warning": 0, "attack": 0}

    for ip, count_str in all_ips.items():
        count = int(count_str)
        if count <= THRESHOLDS["normal"]:
            level = "normal"
        elif count <= THRESHOLDS["suspicious"]:
            level = "suspicious"
        elif count <= THRESHOLDS["warning"]:
            level = "warning"
        else:
            level = "attack"

        level_counts[level] += 1
        ip_list.append({"ip": ip, "count": count, "level": level})

    ip_list.sort(key=lambda x: x["count"], reverse=True)

    # Последние 20 логов из всех IP (для ленты)
    recent_logs = []
    for ip_info in ip_list[:10]:
        ip = ip_info["ip"]
        logs = rc.lrange(f"logs:{ip}", -5, -1)
        for log in logs:
            recent_logs.append({"ip": ip, "level": ip_info["level"], "raw": log})

    recent_logs = recent_logs[-30:]
    recent_logs.reverse()

    # ML инциденты
    ml_incidents = []
    incidents_file = os.path.join(BASE_DIR, "logs", "ml_incidents.json")
    if os.path.exists(incidents_file):
        try:
            with open(incidents_file, "r") as f:
                lines = f.readlines()
                for line in lines[-20:]:
                    line = line.strip()
                    if line:
                        ml_incidents.append(json.loads(line))
            ml_incidents.reverse()
        except Exception:
            pass

    return jsonify({
        "total_ips": len(all_ips),
        "queue_size": queue_size,
        "level_counts": level_counts,
        "ips": ip_list[:50],
        "recent_logs": recent_logs,
        "ml_incidents": ml_incidents,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
