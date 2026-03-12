#!/usr/bin/env python3
"""
Train a CatBoost multi-class model for access-log attack detection.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import pandas as pd
from catboost import CatBoostClassifier, Pool
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit, train_test_split

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from feature_engineering import FEATURE_COLUMNS, align_feature_columns

LABEL_ORDER = ["NORMAL", "SQLI", "XSS", "BRUTE_FORCE", "DOS", "ANOMALY"]


def _class_weights(y_train: pd.Series, class_names: list[str]) -> list[float]:
    counts = y_train.value_counts()
    max_count = counts.max()
    return [float(max_count / counts.get(label, max_count)) for label in class_names]


def split_dataset_frame(
    df: pd.DataFrame,
    test_size: float,
    random_seed: int,
    split_mode: str,
) -> tuple[pd.Index, pd.Index, str]:
    y = df["label"].astype(str)
    groups = None
    if "split_group" in df.columns and df["split_group"].nunique(dropna=True) > 1:
        groups = df["split_group"].fillna("MISSING").astype(str)

    use_group_split = split_mode == "group" or (split_mode == "auto" and groups is not None)
    labels = set(y.unique())

    if use_group_split:
        if groups is None:
            raise ValueError("Group split requested, but dataset does not contain a usable 'split_group' column.")
        for attempt in range(256):
            splitter = GroupShuffleSplit(
                n_splits=1,
                test_size=test_size,
                random_state=random_seed + attempt,
            )
            train_idx, test_idx = next(splitter.split(df, y, groups))
            y_train = set(y.iloc[train_idx].unique())
            y_test = set(y.iloc[test_idx].unique())
            if labels.issubset(y_train) and labels.issubset(y_test):
                return pd.Index(train_idx), pd.Index(test_idx), "group"
        if split_mode == "group":
            raise ValueError("Unable to build a group split that keeps all classes in both train and test.")

    train_idx, test_idx = train_test_split(
        df.index,
        test_size=test_size,
        random_state=random_seed,
        stratify=y,
    )
    return pd.Index(train_idx), pd.Index(test_idx), "row"


def train_model(
    dataset_path: str,
    output_path: str,
    metrics_path: str,
    iterations: int = 1000,
    depth: int = 8,
    learning_rate: float = 0.05,
    test_size: float = 0.2,
    random_seed: int = 42,
    split_mode: str = "auto",
):
    print(f"Loading dataset: {dataset_path}")
    df = pd.read_csv(dataset_path)
    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column.")

    y = df["label"].astype(str)
    class_names = [label for label in LABEL_ORDER if label in set(y.unique())]
    if not class_names:
        raise ValueError("No supported labels found in dataset.")

    print(f"Dataset shape: {df.shape}")
    print("Class distribution:")
    print(y.value_counts().sort_index())

    train_idx, test_idx, effective_split_mode = split_dataset_frame(
        df=df,
        test_size=test_size,
        random_seed=random_seed,
        split_mode=split_mode,
    )
    X = align_feature_columns(df.drop(columns=["label"], errors="ignore"))
    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]
    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    class_weights = _class_weights(y_train, class_names)
    print(f"Train rows: {len(X_train)}, test rows: {len(X_test)}")
    print(f"Split mode: {effective_split_mode}")
    print(f"Class names: {class_names}")
    print(f"Class weights: {class_weights}")

    model = CatBoostClassifier(
        iterations=iterations,
        depth=depth,
        learning_rate=learning_rate,
        loss_function="MultiClass",
        eval_metric="Accuracy",
        class_names=class_names,
        class_weights=class_weights,
        random_seed=random_seed,
        verbose=100,
        early_stopping_rounds=50,
        use_best_model=True,
    )

    train_pool = Pool(X_train, y_train)
    test_pool = Pool(X_test, y_test)
    model.fit(train_pool, eval_set=test_pool)

    predictions = model.predict(X_test)
    y_pred = pd.Series(predictions.reshape(-1)).astype(str)
    report = classification_report(y_test, y_pred, labels=class_names, output_dict=True, zero_division=0)
    matrix = confusion_matrix(y_test, y_pred, labels=class_names)

    print("\nClassification report:")
    print(classification_report(y_test, y_pred, labels=class_names, zero_division=0))

    feature_importance = model.get_feature_importance()
    importance_pairs = sorted(
        zip(FEATURE_COLUMNS, feature_importance),
        key=lambda item: item[1],
        reverse=True,
    )
    print("Top feature importance:")
    for name, score in importance_pairs[:10]:
        print(f"  {name:28s} {score:8.3f}")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(metrics_path) or ".", exist_ok=True)
    model.save_model(output_path)
    print(f"Saved model to {output_path}")

    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_path": dataset_path,
        "train_size": len(X_train),
        "test_size": len(X_test),
        "iterations": iterations,
        "depth": depth,
        "learning_rate": learning_rate,
        "split_mode": effective_split_mode,
        "accuracy": report.get("accuracy", 0.0),
        "macro_avg": report.get("macro avg", {}),
        "weighted_avg": report.get("weighted avg", {}),
        "per_class": {label: report.get(label, {}) for label in class_names},
        "feature_importance": {name: float(score) for name, score in importance_pairs},
        "confusion_matrix": matrix.tolist(),
        "classes": class_names,
    }
    with open(metrics_path, "w", encoding="utf-8") as file_obj:
        json.dump(metrics, file_obj, indent=2, ensure_ascii=False)
    print(f"Saved metrics to {metrics_path}")


def main():
    parser = argparse.ArgumentParser(description="Train CatBoost model for HTTP attack detection")
    parser.add_argument("--dataset", default="data/dataset.csv", help="Dataset CSV path")
    parser.add_argument("--output", default="models/attack_detector.cbm", help="Output model path")
    parser.add_argument("--metrics", default="models/metrics.json", help="Output metrics path")
    parser.add_argument("--iterations", type=int, default=1000, help="CatBoost iterations")
    parser.add_argument("--depth", type=int, default=8, help="Tree depth")
    parser.add_argument("--learning-rate", type=float, default=0.05, help="Learning rate")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split ratio")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--split-mode",
        choices=["auto", "row", "group"],
        default="auto",
        help="Split strategy for train/test (default: auto)",
    )
    args = parser.parse_args()

    train_model(
        dataset_path=args.dataset,
        output_path=args.output,
        metrics_path=args.metrics,
        iterations=args.iterations,
        depth=args.depth,
        learning_rate=args.learning_rate,
        test_size=args.test_size,
        random_seed=args.seed,
        split_mode=args.split_mode,
    )


if __name__ == "__main__":
    main()
