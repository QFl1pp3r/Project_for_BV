"""
Central configuration and constants for the BV access-log analyzer.
Single source of truth for attack labels, paths, and app/report/model settings.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
GEN_DIR = os.path.join(BASE_DIR, "static", "generated")

# Attack model labels (order must match trained CatBoost model)
ATTACK_LABELS = ("NORMAL", "SQLI", "XSS", "BRUTE_FORCE", "DOS")

# App
ALLOWED_EXT = {".log", ".txt"}
MAX_FILE_SIZE = 15 * 1024 * 1024
APP_TZ = "Europe/Moscow"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S %z"
INCIDENT_COLUMNS = [
    "type",
    "severity",
    "source",
    "ip",
    "start",
    "end",
    "confidence",
    "request_count",
    "evidence",
    "tactic",
    "technique",
    "technique_id",
]

# Report / plots
FIG_SIZE = (12, 5)
FIG_DPI = 150
ATTACK_COLORS = {
    "SQLI": "#C1121F",
    "XSS": "#E36414",
    "BRUTE_FORCE": "#F4A259",
    "DOS": "#5A189A",
}

# ML model
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "models", "attack_detector.cbm")
DEFAULT_METRICS_PATH = os.path.join(BASE_DIR, "models", "metrics.json")
MIN_ATTACK_CONFIDENCE = 0.65

# Shared label for multi-source/unknown-IP incidents (e.g. DOS)
MULTI_ATTACK_LABEL = "MULTIPLE/UNKNOWN"

# Regex detector thresholds
DOS_RPS_THRESHOLD = 200
