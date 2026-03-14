#!/usr/bin/env python3
"""
Train a CatBoost multi-class model for access-log attack detection.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import pandas as pd
from catboost import CatBoostClassifier, Pool
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit, train_test_split

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import ATTACK_LABELS
from core.feature_engineering import FEATURE_COLUMNS, align_feature_columns

LABEL_ORDER = list(ATTACK_LABELS)


def _validate_label_schema(labels: pd.Series, dataset_role: str) -> list[str]:
    observed = {str(label) for label in labels.astype(str).unique()}
    unsupported_labels = sorted(observed - set(ATTACK_LABELS))
    if unsupported_labels:
        raise ValueError(
            f"{dataset_role} contains unsupported labels for the current class schema: "
            f"{unsupported_labels}. Regenerate the dataset before training."
        )

    missing_labels = [label for label in ATTACK_LABELS if label not in observed]
    if missing_labels:
        raise ValueError(
            f"{dataset_role} is missing required labels for the current 5-class schema: "
            f"{missing_labels}. Regenerate the dataset before training."
        )

    return [label for label in LABEL_ORDER if label in observed]


def _class_weights(y_train: pd.Series, class_names: list[str]) -> list[float]:
    counts = y_train.value_counts()
    max_count = counts.max()
    return [float(max_count / counts.get(label, max_count)) for label in class_names]


def _temporal_groups(df: pd.DataFrame) -> Optional[pd.Series]:
    if "split_group" in df.columns and df["split_group"].nunique(dropna=True) > 1:
        return df["split_group"].fillna("MISSING").astype(str)

    for column in ("event_ts", "ts"):
        if column not in df.columns:
            continue
        ts = pd.to_datetime(df[column], errors="coerce", utc=True)
        if ts.nunique(dropna=True) <= 1:
            continue
        return ts.dt.floor("30min").dt.strftime("%Y-%m-%dT%H:%M:%S%z").fillna("MISSING")

    return None


def _time_split_indices(
    df: pd.DataFrame,
    y: pd.Series,
    test_size: float,
) -> Optional[tuple[pd.Index, pd.Index]]:
    groups = _temporal_groups(df)
    if groups is None:
        return None

    ordered_groups = sorted(groups.unique())
    if len(ordered_groups) < 2:
        return None

    labels = set(y.unique())
    best_candidate = None
    for cut in range(1, len(ordered_groups)):
        train_groups = set(ordered_groups[:cut])
        train_mask = groups.isin(train_groups)
        test_mask = ~train_mask
        if not train_mask.any() or not test_mask.any():
            continue

        y_train = set(y.loc[train_mask].unique())
        y_test = set(y.loc[test_mask].unique())
        if not labels.issubset(y_train) or not labels.issubset(y_test):
            continue

        test_ratio = float(test_mask.mean())
        candidate = (
            abs(test_ratio - test_size),
            abs(len(ordered_groups) - 2 * cut),
            pd.Index(df.index[train_mask]),
            pd.Index(df.index[test_mask]),
        )
        if best_candidate is None or candidate[:2] < best_candidate[:2]:
            best_candidate = candidate

    if best_candidate is None:
        return None

    return best_candidate[2], best_candidate[3]


def _evaluate_predictions(
    y_true: pd.Series,
    y_pred: pd.Series,
    class_names: list[str],
) -> dict:
    report = classification_report(y_true, y_pred, labels=class_names, output_dict=True, zero_division=0)
    matrix = confusion_matrix(y_true, y_pred, labels=class_names)
    return {
        "accuracy": float(report.get("accuracy", 0.0)),
        "macro_avg": report.get("macro avg", {}),
        "weighted_avg": report.get("weighted avg", {}),
        "per_class": {label: report.get(label, {}) for label in class_names},
        "confusion_matrix": matrix.tolist(),
    }


def _evaluate_labeled_frame(
    model: CatBoostClassifier,
    df: pd.DataFrame,
    class_names: list[str],
    dataset_role: str,
) -> dict:
    if "label" not in df.columns:
        raise ValueError("Validation dataset must contain a 'label' column.")

    y_true = df["label"].astype(str)
    unsupported_labels = sorted(set(y_true.unique()) - set(class_names))
    if unsupported_labels:
        raise ValueError(
            f"{dataset_role} contains unsupported labels for the current model schema: "
            f"{unsupported_labels}."
        )
    X = align_feature_columns(df.drop(columns=["label"], errors="ignore"))
    predictions = model.predict(X)
    y_pred = pd.Series(predictions.reshape(-1)).astype(str)
    metrics = _evaluate_predictions(y_true, y_pred, class_names)
    metrics["dataset_role"] = dataset_role
    metrics["rows"] = int(len(df))
    metrics["label_distribution"] = {label: int(count) for label, count in y_true.value_counts().sort_index().items()}
    return metrics


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

    labels = set(y.unique())
    use_time_split = split_mode == "time" or (split_mode == "auto" and _temporal_groups(df) is not None)
    use_group_split = split_mode == "group" or (split_mode == "auto" and groups is not None)

    if use_time_split:
        split_result = _time_split_indices(df, y, test_size=test_size)
        if split_result is not None:
            return split_result[0], split_result[1], "time"
        if split_mode == "time":
            raise ValueError("Unable to build a temporal split that keeps all classes in both train and test.")

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
    validation_dataset_path: Optional[str] = None,
):
    print(f"Loading dataset: {dataset_path}")
    df = pd.read_csv(dataset_path)
    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column.")

    y = df["label"].astype(str)
    class_names = _validate_label_schema(y, "Dataset")
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
        eval_metric="TotalF1:average=Macro",
        class_names=class_names,
        class_weights=class_weights,
        random_seed=random_seed,
        verbose=100,
        early_stopping_rounds=100,
        use_best_model=True,
        l2_leaf_reg=3,
    )

    train_pool = Pool(X_train, y_train)
    test_pool = Pool(X_test, y_test)
    model.fit(train_pool, eval_set=test_pool)

    predictions = model.predict(X_test)
    y_pred = pd.Series(predictions.reshape(-1)).astype(str)
    internal_validation = _evaluate_predictions(y_test, y_pred, class_names)

    print("\nClassification report:")
    print(classification_report(y_test, y_pred, labels=class_names, zero_division=0))

    # Per-class quality check against targets
    TARGET_F1 = 0.80
    TARGET_PRECISION = 0.80
    TARGET_RECALL = 0.90
    per_class = internal_validation.get("per_class", {})
    print("\nPer-class quality check (F1>80%, Precision>80%, Recall>90%):")
    all_pass = True
    for label in class_names:
        metrics_cls = per_class.get(label, {})
        f1 = metrics_cls.get("f1-score", 0)
        prec = metrics_cls.get("precision", 0)
        rec = metrics_cls.get("recall", 0)
        ok = f1 >= TARGET_F1 and prec >= TARGET_PRECISION and rec >= TARGET_RECALL
        status = "PASS" if ok else "FAIL"
        if not ok:
            all_pass = False
        print(f"  {label:15s} F1={f1:.3f} P={prec:.3f} R={rec:.3f} [{status}]")
    if all_pass:
        print("  All classes PASS quality targets.")
    else:
        print("  WARNING: Some classes FAIL quality targets!")

    feature_importance = model.get_feature_importance()
    importance_pairs = sorted(
        zip(FEATURE_COLUMNS, feature_importance),
        key=lambda item: item[1],
        reverse=True,
    )
    print("Top feature importance:")
    for name, score in importance_pairs[:10]:
        print(f"  {name:28s} {score:8.3f}")

    external_validation = {"status": "not_provided"}
    if validation_dataset_path:
        print(f"\nLoading external validation dataset: {validation_dataset_path}")
        validation_df = pd.read_csv(validation_dataset_path)
        external_validation = _evaluate_labeled_frame(
            model=model,
            df=validation_df,
            class_names=class_names,
            dataset_role="external_validation",
        )
        print("External validation accuracy:")
        print(f"  accuracy={external_validation['accuracy']:.4f}, rows={external_validation['rows']}")
    else:
        print("\nExternal validation dataset was not provided.")
        print("Reported quality metrics remain limited to the internal holdout split.")

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
        "split_mode_requested": split_mode,
        "validation_dataset_path": validation_dataset_path,
        "accuracy": internal_validation.get("accuracy", 0.0),
        "macro_avg": internal_validation.get("macro_avg", {}),
        "weighted_avg": internal_validation.get("weighted_avg", {}),
        "per_class": internal_validation.get("per_class", {}),
        "feature_importance": {name: float(score) for name, score in importance_pairs},
        "confusion_matrix": internal_validation.get("confusion_matrix", []),
        "classes": class_names,
        "primary_validation_scope": "external_validation" if validation_dataset_path else "internal_holdout_only",
        "internal_validation": {
            **internal_validation,
            "dataset_role": "internal_holdout",
            "rows": int(len(X_test)),
            "label_distribution": {label: int(count) for label, count in y_test.value_counts().sort_index().items()},
        },
        "external_validation": external_validation,
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
        choices=["auto", "row", "group", "time"],
        default="auto",
        help="Split strategy for train/test (auto prefers time -> group -> row)",
    )
    parser.add_argument(
        "--validation-dataset",
        default=None,
        help="Optional labeled CSV used only for external offline validation",
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
        validation_dataset_path=args.validation_dataset,
    )


if __name__ == "__main__":
    main()
