import time
import os
import sys
import json
from datetime import datetime

from streaming.redis_client import r

# Добавляем корень проекта в sys.path для импорта core.*
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.parser import parse_line
from core.ml_detector import MLDetector

import pandas as pd

THRESHOLDS = {
    "normal": 100,
    "suspicious": 250,
    "warning": 1000
}

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
ALL_LOGS_FILE = os.path.join(LOG_DIR, "all_logs.log")
ANOMALY_LOGS_FILE = os.path.join(LOG_DIR, "anomaly_logs.log")
ML_INCIDENTS_FILE = os.path.join(LOG_DIR, "ml_incidents.json")

# Lua скрипт — атомарно читает новые логи и обновляет указатель
FETCH_NEW_LOGS_SCRIPT = r.register_script("""
local logs_key = KEYS[1]
local flushed_key = KEYS[2]

local already_flushed = tonumber(redis.call('GET', flushed_key) or '0') or 0
local logs = redis.call('LRANGE', logs_key, already_flushed, -1)

if #logs > 0 then
    redis.call('SET', flushed_key, already_flushed + #logs)
end

return logs
""")

# ML детектор — загружаем один раз при старте
detector = None


def load_detector():
    global detector
    try:
        detector = MLDetector()
        if detector.ready:
            print("[ML] Detector loaded successfully")
        else:
            print(f"[ML] Detector not ready: {detector.load_error}")
            detector = None
    except Exception as e:
        print(f"[ML] Failed to load detector: {e}")
        detector = None


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def get_threat_level(count):
    if count <= THRESHOLDS["normal"]:
        return "normal"
    elif count <= THRESHOLDS["suspicious"]:
        return "suspicious"
    elif count <= THRESHOLDS["warning"]:
        return "warning"
    else:
        return "attack"


def flush_logs(ip, logs, threat_level):
    with open(ALL_LOGS_FILE, "a") as f:
        for line in logs:
            f.write(f"[{threat_level.upper()}] {line}\n")

    if threat_level in ("suspicious", "warning", "attack"):
        with open(ANOMALY_LOGS_FILE, "a") as f:
            for line in logs:
                f.write(f"[{threat_level.upper()}] [{ip}] {line}\n")


def run_ml_detection(ip, logs, threat_level):
    """Прогоняет логи через ML детектор для классификации атак"""
    if detector is None:
        return

    # Парсим raw log строки через существующий parser
    parsed = []
    for raw_line in logs:
        # Убираем UUID префикс, который мы добавили в middleware
        parts = raw_line.split(" ", 1)
        if len(parts) == 2:
            log_line = parts[1]  # всё после UUID
        else:
            log_line = raw_line

        result = parse_line(log_line)
        if result:
            parsed.append(result)

    if not parsed:
        return

    try:
        df = pd.DataFrame(parsed)
        incidents = detector.predict(df)

        if incidents:
            # Записываем инциденты в файл
            with open(ML_INCIDENTS_FILE, "a") as f:
                for incident in incidents:
                    entry = {
                        "detected_at": datetime.now().isoformat(),
                        "threat_level": threat_level,
                        "ip": ip,
                        "type": incident["type"],
                        "severity": incident["severity"],
                        "confidence": incident["confidence"],
                        "request_count": incident["request_count"],
                        "evidence": incident["evidence"],
                    }
                    f.write(json.dumps(entry, default=str) + "\n")

            print(f"[ML] {ip}: {len(incidents)} incident(s) detected — "
                  f"{', '.join(i['type'] for i in incidents)}")

    except Exception as e:
        print(f"[ML] Detection error for {ip}: {e}")


def route_all_ips():
    all_ips = r.hgetall("ip:counter")

    if not all_ips:
        return

    for ip, count_str in all_ips.items():
        count = int(count_str)
        threat_level = get_threat_level(count)

        logs = FETCH_NEW_LOGS_SCRIPT(
            keys=[f"logs:{ip}", f"flushed:{ip}"]
        )

        if not logs:
            continue

        # Записываем в файлы
        flush_logs(ip, logs, threat_level)

        # При уровне WARNING или ATTACK — прогоняем через ML
        if threat_level in ("warning", "attack"):
            run_ml_detection(ip, logs, threat_level)


def run_loop():
    ensure_log_dir()
    load_detector()
    print("Anomaly Router started")

    while True:
        try:
            route_all_ips()
        except Exception as e:
            print(f"Router error: {e}")
        time.sleep(5)


if __name__ == "__main__":
    run_loop()
