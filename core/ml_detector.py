"""
CatBoost-based inference for HTTP access-log attack detection.
"""
import os
from typing import Optional
from urllib.parse import unquote

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier

from config import (
    ATTACK_LABELS,
    DEFAULT_MODEL_PATH,
    MIN_ATTACK_CONFIDENCE,
    MULTI_ATTACK_LABEL,
)
from .feature_engineering import align_feature_columns, extract_features
from .mitre import MITRE, MITRE_DEFAULT, SQLI_RE, XSS_RE
from .parser import build_full_url


def _coerce_predictions(values) -> np.ndarray:
    flat = np.asarray(values, dtype=object).reshape(-1)
    return np.array([str(item[0] if isinstance(item, (list, tuple, np.ndarray)) else item) for item in flat])


def _severity_from_confidence(confidence: float) -> str:
    if confidence >= 0.9:
        return "HIGH"
    if confidence >= 0.7:
        return "MEDIUM"
    return "LOW"


def _build_signature_masks(requests: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    full_url = (requests["path"].fillna("") + "?" + requests["query"].fillna("")).astype(str)
    decoded_url = full_url.apply(lambda value: unquote(value))
    xss_mask = decoded_url.str.contains(XSS_RE, na=False)
    sqli_mask = decoded_url.str.contains(SQLI_RE, na=False) & ~xss_mask
    return sqli_mask, xss_mask


def _apply_signature_overrides(
    requests: pd.DataFrame,
    sqli_mask: pd.Series,
    xss_mask: pd.Series,
) -> pd.DataFrame:
    # Strong regex signatures should win over ambiguous model-only labels.
    unsupported_content_attack = (
        ((requests["ml_label"] == "SQLI") & ~sqli_mask)
        | ((requests["ml_label"] == "XSS") & ~xss_mask)
    )
    requests.loc[unsupported_content_attack, "ml_label"] = "NORMAL"

    if xss_mask.any():
        requests.loc[xss_mask, "ml_label"] = "XSS"
        requests.loc[xss_mask, "ml_confidence"] = requests.loc[xss_mask, "ml_confidence"].clip(
            lower=MIN_ATTACK_CONFIDENCE
        )

    if sqli_mask.any():
        requests.loc[sqli_mask, "ml_label"] = "SQLI"
        requests.loc[sqli_mask, "ml_confidence"] = requests.loc[sqli_mask, "ml_confidence"].clip(
            lower=MIN_ATTACK_CONFIDENCE
        )

    return requests


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
            expected_classes = list(ATTACK_LABELS)
            if self.classes and self.classes != expected_classes:
                self.load_error = (
                    "Incompatible CatBoost model classes. "
                    f"Expected {expected_classes}, got {self.classes}. "
                    "Regenerate the dataset and retrain the model."
                )
                self.ready = False
                if strict:
                    raise RuntimeError(self.load_error)
                return
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
        requests.loc[low_confidence_attack, "ml_label"] = "NORMAL"
        sqli_mask, xss_mask = _build_signature_masks(requests)
        requests = _apply_signature_overrides(requests, sqli_mask=sqli_mask, xss_mask=xss_mask)
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
        for (group_ip, attack_type, window), group in attack_requests.groupby(
            ["group_ip", "ml_label", "window"],
            sort=True,
            dropna=False,
        ):
            request_count = len(group)
            incident_confidence = float(group["ml_confidence"].max())

            sample_urls = []
            for _, row in group.head(3).iterrows():
                sample_urls.append(build_full_url(row.get("path") or "", row.get("query") or "")[:80])

            evidence = (
                f"{request_count} request(s) classified as {attack_type}. "
                f"Samples: {'; '.join(sample_urls)}"
            )[:280]

            mitre = MITRE.get(attack_type, MITRE_DEFAULT)
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
                    **mitre,
                }
            )

        incidents.sort(key=lambda incident: (pd.Timestamp(incident["start"]), incident["type"], incident["ip"]))
        return incidents
