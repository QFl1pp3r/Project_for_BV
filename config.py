"""
Central configuration and constants for the BV access-log analyzer.
Single source of truth for attack labels, paths, and app/report/model settings.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
GEN_DIR = os.path.join(BASE_DIR, "static", "generated")

# Attack model labels (order must match trained CatBoost model)
ATTACK_LABELS = ("NORMAL", "SQLI", "XSS", "BRUTE_FORCE", "DOS", "ANOMALY")

# App
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

# Report / plots
FIG_SIZE = (12, 5)
FIG_DPI = 150
ATTACK_COLORS = {
    "SQLI": "#C1121F",
    "XSS": "#E36414",
    "BRUTE_FORCE": "#F4A259",
    "DOS": "#5A189A",
    "ANOMALY": "#6C757D",
}

# ML model
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "models", "attack_detector.cbm")
MIN_ATTACK_CONFIDENCE = 0.65
MIN_ANOMALY_CONFIDENCE = 0.85
MIN_ANOMALY_REQUEST_COUNT = 3

# Shared label for multi-source/unknown-IP incidents (e.g. DOS)
MULTI_ATTACK_LABEL = "MULTIPLE/UNKNOWN"

# Regex detector thresholds
DOS_RPS_THRESHOLD = 200
