"""Unit tests for ai_predictive forecasting utilities."""

import unittest

from ai_predictive import (
    moving_average_forecast,
    predict,
    prepare_time_series,
    trend_forecast,
)


class TestAIPredictive(unittest.TestCase):
    """Tests for ai_predictive time-series preparation and forecast helpers."""

    def test_prepare_time_series(self):
        """Keeps numeric-like values and filters invalid entries from records."""
        records = [{"value": 10}, {"value": "20"}, {"value": None}, {"value": "bad"}]
        series = prepare_time_series(records)
        self.assertEqual(series, [10.0, 20.0])

    def test_moving_average_forecast(self):
        """Produces expected horizon length and first moving-average value."""
        series = [10.0, 20.0, 30.0]
        preds = moving_average_forecast(series, window=3, horizon=2)
        self.assertEqual(len(preds), 2)
        self.assertAlmostEqual(preds[0], 20.0)

    def test_trend_forecast(self):
        """Projects an upward trend for an increasing input series."""
        series = [10.0, 20.0, 30.0, 40.0]
        preds = trend_forecast(series, horizon=2)
        self.assertEqual(len(preds), 2)
        self.assertTrue(preds[0] > 40.0)

    def test_predict_insufficient(self):
        """Returns insufficient-data status when record history is too short."""
        records = [{"value": 1}, {"value": 2}]
        result = predict(records)
        self.assertEqual(result["status"], "insufficient_data")

    def test_predict_ok(self):
        """Returns ok status and includes both forecast strategy outputs."""
        records = [{"value": 1}, {"value": 2}, {"value": 3}, {"value": 4}]
        result = predict(records, horizon=2)
        self.assertEqual(result["status"], "ok")
        self.assertIn("moving_average", result["predictions"])
        self.assertIn("trend", result["predictions"])


if __name__ == "__main__":
    unittest.main()
