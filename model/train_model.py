"""Train the phishing detector and save a pre-trained model file."""
from __future__ import annotations

import csv
import pickle
import random
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from model.feature_extractor import extract_url_features, validate_url
from model.simple_model import SimpleURLModel

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "url_dataset.csv"
MODEL_PATH = BASE_DIR / "model" / "phishing_detector.joblib"


def load_dataset() -> tuple[list[dict[str, int | float | str | bool]], list[int]]:
    feature_rows: list[dict[str, int | float | str | bool]] = []
    labels: list[int] = []
    with DATA_PATH.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            normalized_url = validate_url(row["url"])
            feature_rows.append(extract_url_features(normalized_url))
            labels.append(int(row["label"]))
    return feature_rows, labels


def stratified_split(
    feature_rows: list[dict[str, int | float | str | bool]],
    labels: list[int],
    test_ratio: float = 0.2,
) -> tuple[
    list[dict[str, int | float | str | bool]],
    list[dict[str, int | float | str | bool]],
    list[int],
    list[int],
]:
    rng = random.Random(42)
    grouped: dict[int, list[tuple[dict[str, int | float | str | bool], int]]] = {0: [], 1: []}
    for row, label in zip(feature_rows, labels):
        grouped[int(label)].append((row, label))

    train_pairs: list[tuple[dict[str, int | float | str | bool], int]] = []
    test_pairs: list[tuple[dict[str, int | float | str | bool], int]] = []
    for pairs in grouped.values():
        rng.shuffle(pairs)
        split_index = max(1, int(len(pairs) * (1 - test_ratio)))
        train_pairs.extend(pairs[:split_index])
        test_pairs.extend(pairs[split_index:])

    rng.shuffle(train_pairs)
    rng.shuffle(test_pairs)
    train_rows = [row for row, _ in train_pairs]
    test_rows = [row for row, _ in test_pairs]
    train_labels = [label for _, label in train_pairs]
    test_labels = [label for _, label in test_pairs]
    return train_rows, test_rows, train_labels, test_labels


def accuracy_score(labels: list[int], predictions: list[int]) -> float:
    if not labels:
        return 0.0
    correct = sum(int(prediction == label) for prediction, label in zip(predictions, labels))
    return correct / len(labels)


def train_model() -> Path:
    feature_rows, labels = load_dataset()
    train_rows, test_rows, train_labels, test_labels = stratified_split(feature_rows, labels)

    model = SimpleURLModel().fit(train_rows, train_labels)
    train_probs = model.predict_proba(train_rows)
    test_probs = model.predict_proba(test_rows)
    train_predictions = [int(probability >= 0.5) for probability in train_probs]
    test_predictions = [int(probability >= 0.5) for probability in test_probs]
    train_accuracy = accuracy_score(train_labels, train_predictions)
    test_accuracy = accuracy_score(test_labels, test_predictions)

    payload = {
        "model_type": "GaussianNaiveBayes",
        "model": model,
        "trained_samples": len(feature_rows),
        "metrics": {
            "train_accuracy": round(float(train_accuracy), 4),
            "test_accuracy": round(float(test_accuracy), 4),
            "train_samples": len(train_rows),
            "test_samples": len(test_rows),
        },
    }
    with MODEL_PATH.open("wb") as model_file:
        pickle.dump(payload, model_file)

    print(f"Saved trained model to {MODEL_PATH}")
    print(f"Train accuracy: {train_accuracy:.2%} ({sum(train_predictions[i] == train_labels[i] for i in range(len(train_labels)))}/{len(train_labels)})")
    print(f"Test accuracy: {test_accuracy:.2%} ({sum(test_predictions[i] == test_labels[i] for i in range(len(test_labels)))}/{len(test_labels)})")
    return MODEL_PATH


if __name__ == "__main__":
    train_model()
