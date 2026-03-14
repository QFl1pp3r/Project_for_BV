"""
CatBoost-based inference for HTTP access-log attack detection.
"""
import os
from typing import Optional

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier

from config import (
    DEFAULT_MODEL_PATH,
    MIN_ANOMALY_CONFIDENCE,
    MIN_ANOMALY_REQUEST_COUNT,
    MIN_ATTACK_CONFIDENCE,
    MULTI_ATTACK_LABEL,
)
from .feature_engineering import align_feature_columns, extract_features
from .parser import build_full_url
from .mitre import MITRE


def _coerce_predictions(values) -> np.ndarray:
    flat = np.asarray(values, dtype=object).reshape(-1)
    return np.array([str(item[0] if isinstance(item, (list, tuple, np.ndarray)) else item) for item in flat])


def _severity_from_confidence(confidence: float) -> str:
    if confidence >= 0.9:
        return "HIGH"
    if confidence >= 0.7:
        return "MEDIUM"
    return "LOW"


class MLDetector:
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, strict: bool = False):
        self.model_path = model_path
        self.model = CatBoostClassifier()
        self.classes: list[str] = []
        self.ready = False
        self.load_error: Optional[str] = None
        self._load(strict=strict)

    def _load(self, strict: bool) -> None:
        if not os.path.exists(self.model_path):
            self.load_error = f"Model file not found: {self.model_path}"
            if strict:
                raise FileNotFoundError(self.load_error)
            return

        try:
            self.model.load_model(self.model_path)
            self.classes = [str(label) for label in getattr(self.model, "classes_", [])]
            self.ready = True
        except Exception as exc:
            self.load_error = f"Failed to load CatBoost model: {exc}"
            if strict:
                raise RuntimeError(self.load_error) from exc

    def predict_requests(self, df: pd.DataFrame) -> pd.DataFrame:
        if not self.ready:
            raise RuntimeError(self.load_error or "ML model is not loaded.")

        requests = df.copy().reset_index(drop=True)
        features = align_feature_columns(extract_features(requests))
        probabilities = np.asarray(self.model.predict_proba(features), dtype=float)

        if probabilities.ndim != 2 or probabilities.shape[0] != len(requests):
            raise RuntimeError("Unexpected probability matrix shape returned by CatBoost.")

        if self.classes:
            predicted_idx = probabilities.argmax(axis=1)
            predictions = np.array([self.classes[index] for index in predicted_idx], dtype=object)
            confidences = probabilities[np.arange(len(requests)), predicted_idx]
        else:
            predictions = _coerce_predictions(self.model.predict(features))
            confidences = probabilities.max(axis=1)

        requests["ml_label"] = predictions
        requests["ml_confidence"] = confidences.astype(float)
        low_confidence_attack = (requests["ml_label"] != "NORMAL") & (requests["ml_confidence"] < MIN_ATTACK_CONFIDENCE)
        low_confidence_anomaly = (requests["ml_label"] == "ANOMALY") & (requests["ml_confidence"] < MIN_ANOMALY_CONFIDENCE)
        requests.loc[low_confidence_attack | low_confidence_anomaly, "ml_label"] = "NORMAL"
        return requests

    def predict(self, df: pd.DataFrame) -> list[dict]:
        if df.empty:
            return []

        requests = self.predict_requests(df)
        attack_requests = requests[requests["ml_label"] != "NORMAL"].copy()
        if attack_requests.empty:
            return []

        attack_requests["window"] = attack_requests["ts"].dt.floor("5min")
        attack_requests["group_ip"] = attack_requests["ip"].fillna("UNKNOWN").astype(str)
        attack_requests.loc[attack_requests["ml_label"] == "DOS", "group_ip"] = MULTI_ATTACK_LABEL

        incidents: list[dict] = []
        suppressed_count = 0
        for (group_ip, attack_type, window), group in attack_requests.groupby(
            ["group_ip", "ml_label", "window"],
            sort=True,
            dropna=False,
        ):
            request_count = len(group)
            incident_confidence = float(group["ml_confidence"].max())

            # Filter out ANOMALY incidents with too few requests (likely false positives)
            if attack_type == "ANOMALY" and request_count < MIN_ANOMALY_REQUEST_COUNT:
                suppressed_count += 1
                continue

            sample_urls = []
            for _, row in group.head(3).iterrows():
                sample_urls.append(build_full_url(row.get("path") or "", row.get("query") or "")[:80])

            evidence = (
                f"{request_count} request(s) classified as {attack_type}. "
                f"Samples: {'; '.join(sample_urls)}"
            )[:280]

            mitre = MITRE.get(attack_type, MITRE["ANOMALY"])
            incidents.append(
                {
                    "type": str(attack_type),
                    "severity": _severity_from_confidence(incident_confidence),
                    "ip": group_ip,
                    "start": group["ts"].min(),
                    "end": group["ts"].max(),
                    "evidence": evidence,
                    "confidence": round(incident_confidence, 3),
                    "request_count": int(request_count),
                    "suppressed_anomalies": 0,
                    **mitre,
                }
            )

        if suppressed_count and incidents:
            incidents[0]["suppressed_anomalies"] = suppressed_count

        incidents.sort(key=lambda incident: (pd.Timestamp(incident["start"]), incident["type"], incident["ip"]))
        return incidents
