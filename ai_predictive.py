"""
Baseline predictive analytics utilities.

Implements lightweight forecasting without external ML dependencies:
- historical series extraction
- moving-average forecast
- simple linear-trend forecast (least squares)

Designed for deterministic unit testing and incremental enhancement.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def _to_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def prepare_time_series(records: List[Dict[str, Any]], value_key: str = "value") -> List[float]:
    """
    Extract a numeric time series from ordered records.
    Non-numeric entries are skipped.
    """
    series: List[float] = []
    for row in records:
        if not isinstance(row, dict):
            continue
        val = _to_float(row.get(value_key))
        if val is not None:
            series.append(val)
    return series


def moving_average_forecast(series: List[float], window: int = 3, horizon: int = 1) -> List[float]:
    """
    Recursive moving-average forecast.
    """
    if window <= 0:
        raise ValueError("window must be > 0")
    if horizon <= 0:
        raise ValueError("horizon must be > 0")
    if len(series) < window:
        raise ValueError("series length must be >= window")

    working = list(series)
    preds: List[float] = []
    for _ in range(horizon):
        next_val = sum(working[-window:]) / window
        preds.append(next_val)
        working.append(next_val)
    return preds


def _linear_regression_coefficients(series: List[float]) -> Tuple[float, float]:
    """
    Returns slope (m) and intercept (b) for y = m*x + b.
    """
    n = len(series)
    if n < 2:
        raise ValueError("series length must be >= 2 for trend forecast")

    x_vals = list(range(n))
    x_mean = sum(x_vals) / n
    y_mean = sum(series) / n

    numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, series))
    denominator = sum((x - x_mean) ** 2 for x in x_vals)
    if denominator == 0:
        raise ValueError("cannot compute regression with zero denominator")

    m = numerator / denominator
    b = y_mean - m * x_mean
    return m, b


def trend_forecast(series: List[float], horizon: int = 1) -> List[float]:
    """
    Forecasts future points using a fitted linear trend.
    """
    if horizon <= 0:
        raise ValueError("horizon must be > 0")
    m, b = _linear_regression_coefficients(series)
    n = len(series)
    return [m * (n + i) + b for i in range(horizon)]


def predict(
    records: List[Dict[str, Any]],
    value_key: str = "value",
    horizon: int = 3,
) -> Dict[str, Any]:
    """
    End-to-end prediction wrapper.
    """
    series = prepare_time_series(records, value_key=value_key)
    if len(series) < 3:
        return {
            "status": "insufficient_data",
            "message": "Need at least 3 data points for baseline forecasting.",
            "series_length": len(series),
            "predictions": {},
        }

    ma_preds = moving_average_forecast(series, window=min(3, len(series)), horizon=horizon)
    tr_preds = trend_forecast(series, horizon=horizon)

    return {
        "status": "ok",
        "series_length": len(series),
        "predictions": {
            "moving_average": ma_preds,
            "trend": tr_preds,
        },
    }
