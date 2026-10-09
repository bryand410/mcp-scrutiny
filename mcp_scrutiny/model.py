"""A tiny logistic-regression classifier, in pure Python.

Why not scikit-learn? Because the scanner has to run inside a customer's CI
container next to the MCP config it audits. A security tool that pulls a 90 MB
scientific stack to evaluate 27 numbers is a supply-chain liability in itself.
The whole model below is a dot product, and it trains in under a second.

The model is deliberately small and interpretable: 27 named features, 27
weights, one bias. When it flags a tool, the report can say *which* features
drove the decision and by how much.
"""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .features import FEATURE_NAMES, extract_features, vectorise

__all__ = ["MODEL_PATH", "LogisticModel", "load_default_model", "train"]

MODEL_PATH = Path(__file__).with_name("data") / "model.json"


@dataclass
class LogisticModel:
    """Standardised logistic regression over the feature vector."""

    features: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    weights: list[float] = field(default_factory=list)
    bias: float = 0.0
    mean: list[float] = field(default_factory=list)
    std: list[float] = field(default_factory=list)
    threshold: float = 0.5
    version: str = "1"
    metrics: dict[str, Any] = field(default_factory=dict)

    # -- inference ---------------------------------------------------------- #

    def _standardise(self, x: Sequence[float]) -> list[float]:
        return [
            (float(v) - (self.mean[i] if i < len(self.mean) else 0.0))
            / (self.std[i] if i < len(self.std) and self.std[i] else 1.0)
            for i, v in enumerate(x)
        ]

    def decision(self, x: Sequence[float]) -> float:
        z = self.bias
        zs = self._standardise(x)
        for w, v in zip(self.weights, zs, strict=False):
            z += w * v
        return z

    def predict_proba(self, x: Sequence[float]) -> float:
        return _sigmoid(self.decision(x))

    def score_tool(self, tool: Any) -> float:
        return self.predict_proba(vectorise(extract_features(tool)))

    def explain(self, x: Sequence[float], limit: int = 5) -> list[tuple[str, float]]:
        """Per-feature contribution to the log-odds, largest magnitude first."""
        zs = self._standardise(x)
        contribs = [
            (self.features[i] if i < len(self.features) else f"f{i}", self.weights[i] * v)
            for i, v in enumerate(zs)
        ]
        contribs.sort(key=lambda kv: abs(kv[1]), reverse=True)
        return contribs[:limit]

    def is_malicious(self, x: Sequence[float]) -> bool:
        return self.predict_proba(x) >= self.threshold

    # -- persistence -------------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "features": self.features,
            "weights": self.weights,
            "bias": self.bias,
            "mean": self.mean,
            "std": self.std,
            "threshold": self.threshold,
            "metrics": self.metrics,
        }

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> LogisticModel:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        model = cls(
            features=list(data.get("features", FEATURE_NAMES)),
            weights=list(data.get("weights", [])),
            bias=float(data.get("bias", 0.0)),
            mean=list(data.get("mean", [])),
            std=list(data.get("std", [])),
            threshold=float(data.get("threshold", 0.5)),
            version=str(data.get("version", "1")),
            metrics=dict(data.get("metrics", {})),
        )
        if len(model.weights) != len(model.features):
            raise ValueError(f"model is corrupt: {len(model.weights)} weights for {len(model.features)} features")
        return model


def load_default_model() -> LogisticModel | None:
    """Load the shipped model, or ``None`` if it has not been trained yet."""
    try:
        return LogisticModel.load(MODEL_PATH)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        return None


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


# --------------------------------------------------------------------------- #
# Training
# --------------------------------------------------------------------------- #


def train(
    samples: Sequence[tuple[Any, int]],
    *,
    epochs: int = 3000,
    lr: float = 0.5,
    l2: float = 1e-3,
    threshold: float = 0.5,
    verbose: bool = False,
) -> LogisticModel:
    """Fit the classifier.

    ``samples`` is a sequence of ``(text_or_tool, label)`` where label is 1 for
    a description that tries to steer the model and 0 for one that describes a
    function. Text is accepted directly so the corpus stays readable.
    """
    if not samples:
        raise ValueError("no training samples")

    rows: list[list[float]] = []
    labels: list[int] = []
    for item, label in samples:
        feats = extract_features(item) if not isinstance(item, str) else extract_features(_FakeTool(item))
        rows.append(vectorise(feats))
        labels.append(int(label))

    n_features = len(FEATURE_NAMES)
    mean, std = _standardise_stats(rows, n_features)
    xs = [
        [(row[i] - mean[i]) / (std[i] or 1.0) for i in range(n_features)]
        for row in rows
    ]

    pos = sum(labels)
    neg = len(labels) - pos
    # Balance the classes: in the wild, poisoned tools are ~1% of the corpus,
    # so an unweighted fit would just learn to say "benign" and score 99%.
    w_pos = len(labels) / (2 * pos) if pos else 1.0
    w_neg = len(labels) / (2 * neg) if neg else 1.0
    weights = [0.0] * n_features
    bias = 0.0

    for epoch in range(epochs):
        grad_w = [0.0] * n_features
        grad_b = 0.0
        total = 0.0
        for x, y in zip(xs, labels, strict=False):
            z = bias + sum(w * v for w, v in zip(weights, x, strict=False))
            p = _sigmoid(z)
            weight = w_pos if y == 1 else w_neg
            err = (p - y) * weight
            total += weight * _logloss(p, y)
            for i, v in enumerate(x):
                grad_w[i] += err * v
            grad_b += err
        n = len(xs)
        for i in range(n_features):
            weights[i] -= lr * (grad_w[i] / n + l2 * weights[i])
        bias -= lr * (grad_b / n)
        if verbose and epoch % 250 == 0:
            print(f"epoch {epoch:5d}  loss={total / n:.4f}")

    model = LogisticModel(
        features=list(FEATURE_NAMES),
        weights=weights,
        bias=bias,
        mean=mean,
        std=std,
        threshold=threshold,
        version="1",
    )
    model.metrics = evaluate(model, rows, labels, threshold)
    return model


def evaluate(model: LogisticModel, rows: Sequence[Sequence[float]], labels: Sequence[int],
             threshold: float = 0.5) -> dict[str, Any]:
    """Confusion matrix and derived rates at the operating threshold."""
    tp = fp = tn = fn = 0
    scores: list[tuple[float, int]] = []
    for row, y in zip(rows, labels, strict=False):
        p = model.predict_proba(row)
        scores.append((p, y))
        if p >= threshold:
            tp += y == 1
            fp += y == 0
        else:
            tn += y == 0
            fn += y == 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "samples": len(labels),
        "positives": sum(labels),
        "threshold": threshold,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / len(labels), 4) if labels else 0.0,
        "roc_auc": round(_roc_auc(scores), 4),
    }


def _roc_auc(scores: Sequence[tuple[float, int]]) -> float:
    """Rank-based AUC (Mann-Whitney U), no external dependency."""
    pos = [s for s, y in scores if y == 1]
    neg = [s for s, y in scores if y == 0]
    if not pos or not neg:
        return 0.0
    wins = sum(
        1.0 if p > n else 0.5 if p == n else 0.0
        for p in pos for n in neg
    )
    return wins / (len(pos) * len(neg))


def _logloss(p: float, y: int) -> float:
    p = min(max(p, 1e-12), 1 - 1e-12)
    return -(y * math.log(p) + (1 - y) * math.log(1 - p))


def cross_validate(
    samples: Sequence[tuple[Any, int]],
    *,
    k: int = 5,
    epochs: int = 2000,
    lr: float = 0.5,
    l2: float = 1e-3,
) -> dict[str, Any]:
    """Stratified k-fold cross-validation.

    The headline number a security detector should be judged on is *not* its
    training accuracy. A 31-feature model on a 100-example corpus can reach
    100% on the data it was fitted to and still be useless. This function is
    what the README quotes.
    """
    import random

    pos = [s for s in samples if s[1] == 1]
    neg = [s for s in samples if s[1] == 0]
    rng = random.Random(0)
    rng.shuffle(pos)
    rng.shuffle(neg)

    folds: list[list[tuple[Any, int]]] = [[] for _ in range(k)]
    for i, item in enumerate(pos):
        folds[i % k].append(item)
    for i, item in enumerate(neg):
        folds[i % k].append(item)

    tp = fp = tn = fn = 0
    for i in range(k):
        train_set = [s for j, fold in enumerate(folds) if j != i for s in fold]
        test_set = folds[i]
        model = train(train_set, epochs=epochs, lr=lr, l2=l2)
        for item, y in test_set:
            feats = extract_features(item) if not isinstance(item, str) else extract_features(_FakeTool(item))
            predicted = 1 if model.predict_proba(vectorise(feats)) >= 0.5 else 0
            if predicted == 1:
                tp += y == 1
                fp += y == 0
            else:
                tn += y == 0
                fn += y == 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "folds": k,
        "samples": len(samples),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / len(samples), 4) if samples else 0.0,
    }


def _standardise_stats(rows: Sequence[Sequence[float]], n_features: int) -> tuple[list[float], list[float]]:
    mean: list[float] = []
    std: list[float] = []
    n = len(rows) or 1
    for i in range(n_features):
        column = [row[i] for row in rows]
        mu = sum(column) / n
        var = sum((v - mu) ** 2 for v in column) / n
        mean.append(mu)
        std.append(math.sqrt(var) or 1.0)
    return mean, std


class _FakeTool:
    """Adapter so raw description strings can go through the same extractor."""

    __slots__ = ("annotations", "description", "input_schema", "name")

    def __init__(self, description: str, name: str = "") -> None:
        self.name = name
        self.description = description
        self.input_schema: dict[str, Any] = {}
        self.annotations: dict[str, Any] = {}
