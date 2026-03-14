"""
Comparison helpers for ML incidents vs regex baseline incidents.

Important:
These helpers do not calculate ground-truth ML quality metrics.
They only describe how much ML output overlaps with the regex baseline.
"""

from typing import Optional

import pandas as pd

from config import ATTACK_LABELS


def _normalize_type(value: Optional[str]) -> str:
    attack_type = str(value or "").upper()
    return "ANOMALY" if attack_type.startswith("ANOMALY") else attack_type


def _normalize_ip(attack_type: str, ip: Optional[str]) -> str:
    return str(ip or "UNKNOWN")


def incident_key(incident: dict) -> tuple[str, str, Optional[pd.Timestamp]]:
    attack_type = _normalize_type(incident.get("type"))
    ip = _normalize_ip(attack_type, incident.get("ip"))
    start = pd.to_datetime(incident.get("start"), errors="coerce")
    window = None if pd.isna(start) else pd.Timestamp(start).floor("5min")
    return attack_type, ip, window


def annotate_ml_matches(ml_incidents: list[dict], regex_incidents: list[dict]) -> list[dict]:
    regex_keys = {incident_key(incident) for incident in regex_incidents}
    annotated: list[dict] = []
    for incident in ml_incidents:
        item = dict(incident)
        item["regex_match"] = incident_key(incident) in regex_keys
        annotated.append(item)
    return annotated


def _incident_summary(incident: dict) -> dict:
    attack_type, ip, window = incident_key(incident)
    return {
        "type": attack_type,
        "ip": ip,
        "window": "" if window is None else window.isoformat(),
        "evidence": incident.get("evidence", ""),
        "confidence": incident.get("confidence"),
    }


def compare_with_regex_baseline(
    _df: Optional[pd.DataFrame],
    ml_incidents: list[dict],
    regex_incidents: list[dict],
) -> dict:
    ml_map = {incident_key(incident): incident for incident in ml_incidents}
    regex_map = {incident_key(incident): incident for incident in regex_incidents}

    ml_keys = set(ml_map)
    regex_keys = set(regex_map)
    overlap_keys = ml_keys & regex_keys
    ml_only_keys = ml_keys - regex_keys
    regex_only_keys = regex_keys - ml_keys
    union_size = len(ml_keys | regex_keys)

    total_ml = len(ml_keys)
    total_regex = len(regex_keys)
    overlap_count = len(overlap_keys)

    agreement_rate = 1.0 if total_ml == 0 and total_regex == 0 else overlap_count / max(union_size, 1)

    type_set = {key[0] for key in ml_keys | regex_keys}
    all_types = [t for t in ATTACK_LABELS if t in type_set] + sorted(type_set - set(ATTACK_LABELS))
    per_type_comparison = {}
    for attack_type in all_types:
        per_type_comparison[attack_type] = {
            "ml": sum(1 for key in ml_keys if key[0] == attack_type),
            "regex": sum(1 for key in regex_keys if key[0] == attack_type),
            "overlap": sum(1 for key in overlap_keys if key[0] == attack_type),
        }

    return {
        "comparison_kind": "regex_baseline_overlap",
        "total_ml": total_ml,
        "total_regex": total_regex,
        "agreement_rate": round(agreement_rate, 3),
        "overlap": overlap_count,
        "ml_only": [
            _incident_summary(ml_map[key])
            for key in sorted(ml_only_keys, key=lambda item: (item[0], item[1], "" if item[2] is None else item[2].isoformat()))
        ],
        "regex_only": [
            _incident_summary(regex_map[key])
            for key in sorted(regex_only_keys, key=lambda item: (item[0], item[1], "" if item[2] is None else item[2].isoformat()))
        ],
        "per_type_comparison": per_type_comparison,
    }


def evaluate_accuracy(
    _df: Optional[pd.DataFrame],
    ml_incidents: list[dict],
    regex_incidents: list[dict],
) -> dict:
    """Backward-compatible alias kept for older integrations."""
    return compare_with_regex_baseline(_df, ml_incidents, regex_incidents)
