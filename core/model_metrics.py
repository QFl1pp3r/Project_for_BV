"""
Helpers for reading and normalizing stored CatBoost training metrics.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from config import ATTACK_LABELS, DEFAULT_METRICS_PATH


def _as_float(value: object) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: object) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def load_model_metrics(metrics_path: str = DEFAULT_METRICS_PATH) -> tuple[Optional[dict], Optional[str]]:
    if not os.path.exists(metrics_path):
        return None, f"Файл метрик не найден: {metrics_path}"

    try:
        with open(metrics_path, "r", encoding="utf-8") as file_obj:
            raw = json.load(file_obj)
    except Exception as exc:
        return None, f"Не удалось прочитать метрики модели: {exc}"

    validation = raw.get("internal_validation") or raw
    macro_avg = validation.get("macro_avg") or raw.get("macro_avg") or {}
    weighted_avg = validation.get("weighted_avg") or raw.get("weighted_avg") or {}
    per_class = validation.get("per_class") or raw.get("per_class") or {}
    class_order = raw.get("classes") or list(per_class.keys())
    expected_classes = list(ATTACK_LABELS)
    if class_order and class_order != expected_classes:
        return None, (
            "Файл метрик несовместим с текущей схемой классов. "
            f"Ожидались {expected_classes}, получены {class_order}. "
            "Пересоберите датасет и переобучите модель."
        )

    per_class_rows = []
    for label in class_order:
        class_metrics = per_class.get(label) or {}
        per_class_rows.append(
            {
                "label": label,
                "precision": _as_float(class_metrics.get("precision")),
                "recall": _as_float(class_metrics.get("recall")),
                "f1": _as_float(class_metrics.get("f1-score")),
                "support": _as_int(class_metrics.get("support")),
            }
        )

    metrics = {
        "trained_at": raw.get("trained_at"),
        "dataset_path": raw.get("dataset_path"),
        "validation_scope": raw.get("primary_validation_scope"),
        "split_mode": raw.get("split_mode"),
        "train_size": _as_int(raw.get("train_size")),
        "test_size": _as_int(raw.get("test_size")),
        "iterations": _as_int(raw.get("iterations")),
        "depth": _as_int(raw.get("depth")),
        "learning_rate": _as_float(raw.get("learning_rate")),
        "accuracy": _as_float(validation.get("accuracy", raw.get("accuracy"))),
        "macro_precision": _as_float(macro_avg.get("precision")),
        "macro_recall": _as_float(macro_avg.get("recall")),
        "macro_f1": _as_float(macro_avg.get("f1-score")),
        "weighted_f1": _as_float(weighted_avg.get("f1-score")),
        "per_class": per_class_rows,
    }
    return metrics, None
