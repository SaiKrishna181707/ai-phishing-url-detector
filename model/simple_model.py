"""Pure-Python model wrapper used for phishing URL classification."""
from __future__ import annotations

from dataclasses import dataclass, field
from math import exp, log, pi

from model.feature_extractor import MODEL_FEATURES


@dataclass
class SimpleURLModel:
    """Gaussian naive Bayes model with a small domain-memory bias."""

    priors: dict[int, float] = field(default_factory=dict)
    means: dict[int, dict[str, float]] = field(default_factory=dict)
    variances: dict[int, dict[str, float]] = field(default_factory=dict)
    safe_domains: set[str] = field(default_factory=set)
    scam_domains: set[str] = field(default_factory=set)

    def fit(self, feature_rows: list[dict[str, int | float | str | bool]], labels: list[int]) -> "SimpleURLModel":
        if not feature_rows:
            raise ValueError("Training data cannot be empty.")

        grouped: dict[int, list[dict[str, int | float | str | bool]]] = {0: [], 1: []}
        for row, label in zip(feature_rows, labels):
            grouped[int(label)].append(row)

        total = len(labels)
        for label, rows in grouped.items():
            if not rows:
                raise ValueError("Training data must include both safe and scam samples.")
            self.priors[label] = len(rows) / total
            self.means[label] = {}
            self.variances[label] = {}
            for feature in MODEL_FEATURES:
                values = [float(row.get(feature, 0.0)) for row in rows]
                mean = sum(values) / len(values)
                variance = sum((value - mean) ** 2 for value in values) / len(values)
                self.means[label][feature] = mean
                self.variances[label][feature] = max(variance, 1e-6)

        self.safe_domains = {str(row.get("registered_domain", "")) for row in grouped[0] if row.get("registered_domain")}
        self.scam_domains = {str(row.get("registered_domain", "")) for row in grouped[1] if row.get("registered_domain")}
        return self

    def predict_proba(
        self,
        feature_row: dict[str, int | float | str | bool] | list[dict[str, int | float | str | bool]],
    ) -> float | list[float]:
        rows = feature_row if isinstance(feature_row, list) else [feature_row]
        probabilities = [self._predict_single(row) for row in rows]
        return probabilities if isinstance(feature_row, list) else float(probabilities[0])

    def _predict_single(self, row: dict[str, int | float | str | bool]) -> float:
        safe_log = log(self.priors.get(0, 0.5))
        scam_log = log(self.priors.get(1, 0.5))

        for feature in MODEL_FEATURES:
            value = float(row.get(feature, 0.0))
            safe_log += self._gaussian_log_likelihood(
                value,
                self.means[0][feature],
                self.variances[0][feature],
            )
            scam_log += self._gaussian_log_likelihood(
                value,
                self.means[1][feature],
                self.variances[1][feature],
            )

        registered_domain = str(row.get("registered_domain", ""))
        if registered_domain in self.scam_domains and registered_domain not in self.safe_domains:
            scam_log += 0.8
        elif registered_domain in self.safe_domains and registered_domain not in self.scam_domains:
            safe_log += 0.6

        difference = max(min(scam_log - safe_log, 60), -60)
        return 1.0 / (1.0 + exp(-difference))

    @staticmethod
    def _gaussian_log_likelihood(value: float, mean: float, variance: float) -> float:
        return -0.5 * log(2 * pi * variance) - ((value - mean) ** 2) / (2 * variance)
