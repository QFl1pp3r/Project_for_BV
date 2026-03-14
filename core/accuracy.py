"""
Comparison helpers for ML incidents vs regex baseline incidents.

Important:
These helpers do not calculate ground-truth ML quality metrics.
They only describe how much ML output overlaps with the regex baseline.
"""

from typing import Optional

import pandas as pd

from config import ATTACK_LABELS
from .mitre import MITRE, MITRE_DEFAULT

_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _normalize_type(value: Optional[str]) -> str:
    return str(value or "").upper()


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


def _sort_key(item: tuple[str, str, Optional[pd.Timestamp]]) -> tuple[str, str, str]:
    attack_type, ip, window = item
    return attack_type, ip, "" if window is None else window.isoformat()


def _coerce_timestamp(value: object) -> Optional[pd.Timestamp]:
    ts = pd.to_datetime(value, errors="coerce")
    if pd.isna(ts):
        return None
    return pd.Timestamp(ts)


def _coerce_int(value: object, default: int = 0) -> int:
    if value is None or pd.isna(value):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: object) -> Optional[float]:
    if value is None or pd.isna(value):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _highest_severity(items: list[dict]) -> Optional[str]:
    best_value = None
    best_rank = -1
    for item in items:
        severity = str(item.get("severity") or "").upper()
        rank = _SEVERITY_RANK.get(severity, 0)
        if rank > best_rank and severity:
            best_rank = rank
            best_value = severity
        elif best_value is None and severity:
            best_value = severity
    return best_value


def _merge_evidence(items: list[dict], max_parts: int = 3) -> str:
    unique_parts: list[str] = []
    for item in items:
        evidence = str(item.get("evidence") or "").strip()
        if evidence and evidence not in unique_parts:
            unique_parts.append(evidence)
    if not unique_parts:
        return ""
    if len(unique_parts) == 1:
        return unique_parts[0][:280]

    prefix = f"{len(items)} related events. "
    joined = "; ".join(unique_parts[:max_parts])
    suffix = " ..." if len(unique_parts) > max_parts else ""
    return f"{prefix}Examples: {joined}{suffix}"[:280]


def _collapse_incidents(incidents: list[dict], source_name: str) -> dict[tuple[str, str, Optional[pd.Timestamp]], dict]:
    grouped: dict[tuple[str, str, Optional[pd.Timestamp]], list[dict]] = {}
    for incident in incidents:
        grouped.setdefault(incident_key(incident), []).append(incident)

    collapsed: dict[tuple[str, str, Optional[pd.Timestamp]], dict] = {}
    for key, items in grouped.items():
        attack_type, ip, _window = key
        starts = [ts for ts in (_coerce_timestamp(item.get("start")) for item in items) if ts is not None]
        ends = [ts for ts in (_coerce_timestamp(item.get("end")) for item in items) if ts is not None]
        confidence_values = [value for value in (_coerce_float(item.get("confidence")) for item in items) if value is not None]
        request_count = 0
        for item in items:
            request_count += _coerce_int(item.get("request_count"), default=1)

        collapsed[key] = {
            "type": attack_type,
            "severity": _highest_severity(items),
            "ip": ip,
            "start": min(starts) if starts else None,
            "end": max(ends) if ends else None,
            "evidence": _merge_evidence(items),
            "confidence": max(confidence_values) if confidence_values else None,
            "request_count": request_count,
            "source": source_name,
            **MITRE.get(attack_type, MITRE_DEFAULT),
        }

    return collapsed


def _pick_best_severity(*items: Optional[dict]) -> Optional[str]:
    available = [item for item in items if item]
    if not available:
        return None
    return _highest_severity(available)


def _pick_confidence(*items: Optional[dict]) -> Optional[float]:
    values = [value for value in (_coerce_float(item.get("confidence")) for item in items if item) if value is not None]
    return max(values) if values else None


def _pick_request_count(*items: Optional[dict]) -> int:
    counts = [_coerce_int(item.get("request_count")) for item in items if item]
    return max(counts) if counts else 0


def _combine_evidence(*items: Optional[dict]) -> str:
    snippets: list[str] = []
    for item in items:
        if not item:
            continue
        evidence = str(item.get("evidence") or "").strip()
        if evidence and evidence not in snippets:
            snippets.append(evidence)
    return " | ".join(snippets)[:280]


def merge_incident_sources(ml_incidents: list[dict], regex_incidents: list[dict]) -> list[dict]:
    ml_map = _collapse_incidents(ml_incidents, "ML")
    regex_map = _collapse_incidents(regex_incidents, "Regex")
    all_keys = sorted(set(ml_map) | set(regex_map), key=_sort_key)

    merged: list[dict] = []

    for key in all_keys:
        ml_item = ml_map.get(key)
        regex_item = regex_map.get(key)
        attack_type, ip, _window = key
        starts = [item["start"] for item in (ml_item, regex_item) if item and item.get("start") is not None]
        ends = [item["end"] for item in (ml_item, regex_item) if item and item.get("end") is not None]

        has_ml = ml_item is not None
        has_regex = regex_item is not None
        if has_ml and has_regex:
            source = "ML + Regex"
        elif has_ml:
            source = "ML"
        else:
            source = "Regex"

        merged.append(
            {
                "type": attack_type,
                "severity": _pick_best_severity(ml_item, regex_item),
                "source": source,
                "ip": ip,
                "start": min(starts) if starts else None,
                "end": max(ends) if ends else None,
                "confidence": _pick_confidence(ml_item, regex_item),
                "request_count": _pick_request_count(ml_item, regex_item),
                "evidence": _combine_evidence(ml_item, regex_item),
                "detected_by_ml": has_ml,
                "detected_by_regex": has_regex,
                "regex_match": has_regex,
                **MITRE.get(attack_type, MITRE_DEFAULT),
            }
        )

    return merged


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
            for key in sorted(ml_only_keys, key=_sort_key)
        ],
        "regex_only": [
            _incident_summary(regex_map[key])
            for key in sorted(regex_only_keys, key=_sort_key)
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
