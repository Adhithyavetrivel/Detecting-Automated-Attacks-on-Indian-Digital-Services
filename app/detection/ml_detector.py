"""
ML-based anomaly detection using Isolation Forest.

Design principle (per project spec): AI is a SECOND layer on top of the
rule-based engine, not a replacement for it, and every ML verdict must
come with a plain-language explanation — never a bare "AI detected
attack."

Isolation Forest is an unsupervised algorithm: it doesn't need labeled
"attack" examples (which we don't have). It works by randomly partitioning
the feature space and observing that anomalous points are, on average,
isolated into their own tiny partition in fewer random splits than normal
points — hence "isolation." Its output score is turned into a human
explanation by comparing the flagged sample's features against the
training data's own mean/std, in `_explain`.
"""

import logging
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("netsentinel.detection.ml")

FEATURE_NAMES = [
    "packets_per_second",
    "bytes_per_second",
    "unique_dst_ips",
    "unique_dst_ports",
    "avg_packet_size",
    "tcp_count",
    "icmp_count",
]


@dataclass
class MLResult:
    is_anomalous: bool
    anomaly_score: float  # higher = more anomalous (we flip sklearn's sign for intuitiveness)
    explanation: str


class TrafficAnomalyDetector:
    """
    Wraps a scikit-learn IsolationForest trained on historical
    TrafficRecord feature vectors.

    `contamination` is the expected fraction of anomalous samples in
    training data — 0.05 (5%) is a reasonable starting default for
    network traffic and is intentionally conservative (favors fewer
    false positives) for a project meant to be demoed live.
    """

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            contamination=contamination, random_state=random_state, n_estimators=100
        )
        self._is_fitted = False
        self._training_mean: np.ndarray | None = None
        self._training_std: np.ndarray | None = None

    def fit(self, feature_rows: list[list[float]]) -> None:
        """
        Train (or retrain) on a batch of historical traffic feature
        vectors, each ordered per FEATURE_NAMES.

        Needs a reasonable amount of history to be meaningful — the
        service layer calling this should skip fitting (and skip
        prediction) until enough TrafficRecord rows exist, rather than
        train on a handful of points and produce noise.
        """
        X = np.array(feature_rows)
        self.model.fit(X)
        self._training_mean = X.mean(axis=0)
        self._training_std = X.std(axis=0) + 1e-9  # avoid divide-by-zero
        self._is_fitted = True
        logger.info("Isolation Forest fitted on %d samples", len(feature_rows))

    def predict(self, feature_row: list[float]) -> MLResult:
        """
        Score a single new traffic sample against the fitted model.

        Raises RuntimeError if called before `fit()` — a caller forgetting
        to train first should fail loudly, not silently return "normal".
        """
        if not self._is_fitted:
            raise RuntimeError("TrafficAnomalyDetector.predict() called before fit()")

        X = np.array([feature_row])
        raw_prediction = self.model.predict(X)[0]  # sklearn: -1 = anomaly, 1 = normal
        raw_score = self.model.decision_function(X)[0]  # higher = more normal in sklearn

        is_anomalous = raw_prediction == -1
        # Flip sign so that in OUR output, higher score = more anomalous,
        # which is the more intuitive convention for a dashboard/alert.
        anomaly_score = round(-raw_score, 4)

        explanation = self._explain(feature_row) if is_anomalous else "Traffic within normal range."
        return MLResult(is_anomalous=is_anomalous, anomaly_score=anomaly_score, explanation=explanation)

    def _explain(self, feature_row: list[float]) -> str:
        """
        Build a human-readable explanation by finding which feature(s)
        deviate most (in standard deviations) from the training mean —
        this is what keeps the output as "traffic volume is 4.8x higher
        than baseline" instead of an opaque score.
        """
        assert self._training_mean is not None and self._training_std is not None

        deviations = (np.array(feature_row) - self._training_mean) / self._training_std
        # Rank features by absolute deviation, explain the top 2.
        ranked = sorted(
            zip(FEATURE_NAMES, feature_row, deviations, self._training_mean),
            key=lambda t: abs(t[2]),
            reverse=True,
        )

        parts = []
        for name, value, deviation, mean in ranked[:2]:
            if abs(deviation) < 1.0:
                continue
            direction = "higher" if deviation > 0 else "lower"
            multiple = (value / mean) if mean > 0 else None
            if multiple is not None and direction == "higher":
                parts.append(f"{name.replace('_', ' ')} is {multiple:.1f}x higher than baseline")
            else:
                parts.append(
                    f"{name.replace('_', ' ')} is {abs(deviation):.1f} standard deviations {direction} than baseline"
                )

        if not parts:
            return "Traffic pattern deviates from baseline across multiple minor features."
        return "; ".join(parts) + "."
