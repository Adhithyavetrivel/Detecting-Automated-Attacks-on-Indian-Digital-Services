"""Tests for ML-based anomaly detection."""

import pytest

from app.detection.ml_detector import TrafficAnomalyDetector


def test_ml_detector_fit_and_predict():
    detector = TrafficAnomalyDetector()

    # Generate 40 "normal" samples
    normal_samples = [
        [100, 50000, 5, 10, 300, 80, 2] for _ in range(40)
    ]
    detector.fit(normal_samples)

    # A normal-looking sample should score as normal
    normal_test = [105, 48000, 5, 11, 310, 85, 1]
    result_normal = detector.predict(normal_test)
    assert result_normal.is_anomalous is False
    assert "normal range" in result_normal.explanation.lower()

    # A clear anomaly (10x more traffic) should be flagged
    anomalous_test = [1000, 500000, 25, 50, 300, 800, 20]
    result_anomaly = detector.predict(anomalous_test)
    assert result_anomaly.is_anomalous is True
    assert "higher than baseline" in result_anomaly.explanation


def test_ml_detector_requires_fit():
    detector = TrafficAnomalyDetector()
    sample = [100, 50000, 5, 10, 300, 80, 2]

    with pytest.raises(RuntimeError, match="called before fit"):
        detector.predict(sample)


def test_ml_detector_explanation_identifies_top_deviations():
    detector = TrafficAnomalyDetector()
    normal_samples = [[100, 50000, 5, 10, 300, 80, 2] for _ in range(40)]
    detector.fit(normal_samples)

    # Anomalous sample with very high packets_per_second and bytes_per_second
    anomaly = [800, 400000, 5, 10, 300, 80, 2]
    result = detector.predict(anomaly)

    assert result.is_anomalous
    # The explanation should mention the two most-deviating features
    explanation = result.explanation.lower()
    assert "higher" in explanation
