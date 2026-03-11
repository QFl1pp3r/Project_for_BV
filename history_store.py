import json
import os
from typing import Optional


def init_store(history_path: str):
    os.makedirs(os.path.dirname(history_path), exist_ok=True)
    if not os.path.exists(history_path):
        save_history(history_path, [])


def load_history(history_path: str) -> list[dict]:
    init_store(history_path)
    try:
        with open(history_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(data, list):
        return []

    entries = [item for item in data if isinstance(item, dict) and item.get("id")]
    return sorted(entries, key=lambda item: item.get("created_at", ""), reverse=True)


def save_history(history_path: str, entries: list[dict]):
    os.makedirs(os.path.dirname(history_path), exist_ok=True)
    tmp_path = f"{history_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, ensure_ascii=False, indent=2)
    os.replace(tmp_path, history_path)


def upsert_entry(history_path: str, entry: dict):
    entries = [item for item in load_history(history_path) if item.get("id") != entry.get("id")]
    entries.insert(0, entry)
    save_history(history_path, entries)


def get_entry(history_path: str, analysis_id: str) -> Optional[dict]:
    for item in load_history(history_path):
        if item.get("id") == analysis_id:
            return item
    return None


def delete_entry(history_path: str, analysis_id: str) -> Optional[dict]:
    removed = None
    remaining = []

    for item in load_history(history_path):
        if item.get("id") == analysis_id:
            removed = item
            continue
        remaining.append(item)

    if removed is not None:
        save_history(history_path, remaining)

    return removed
