"""
Automated report generation utilities for AI analysis outputs.

Supports:
- textual executive summaries
- CSV serialization
- JSON-ready dictionaries
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any, Dict, List


def _safe_get(d: Dict[str, Any], key: str, default: Any = None) -> Any:
    return d.get(key, default) if isinstance(d, dict) else default


def generate_text_report(
    analysis_result: Dict[str, Any],
    predictive_result: Dict[str, Any],
    risk_result: Dict[str, Any],
) -> str:
    """Generate a human-readable multi-section report from analysis outputs."""
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    metrics = _safe_get(analysis_result, "metrics", {})
    sector = _safe_get(analysis_result, "sector", {})
    distribution = _safe_get(analysis_result, "distribution", {})

    lines: List[str] = [
        "Equity Shield Advocates - AI Insights Report",
        f"Generated At: {timestamp}",
        "",
        "=== Key Metrics ===",
        f"Total Companies: {_safe_get(metrics, 'total_companies', 'N/A')}",
        f"Total Valuation: {_safe_get(metrics, 'total_valuation', 'N/A')}",
        f"Average Return %: {_safe_get(metrics, 'average_return_pct', 'N/A')}",
        f"Average Risk Score: {_safe_get(metrics, 'average_risk_score', 'N/A')}",
        "",
        "=== Sector Summary ===",
        f"Sector Count: {_safe_get(sector, 'sector_count', 'N/A')}",
        "",
        "=== Distribution ===",
        f"By Sector: {_safe_get(distribution, 'distribution_by_sector', {})}",
        f"By Valuation Bucket: {_safe_get(distribution, 'distribution_by_valuation_bucket', {})}",
        "",
        "=== Predictive Signals ===",
        f"Prediction Status: {_safe_get(predictive_result, 'status', 'N/A')}",
        f"Predictions: {_safe_get(predictive_result, 'predictions', {})}",
        "",
        "=== Risk & Compliance ===",
        f"Risk Result: {risk_result}",
        "",
        "=== Suggested Strategy ===",
        "1) Rebalance toward sectors with stable returns and lower risk scores.",
        "2) Flag high-risk entities for compliance review.",
        "3) Use trend projections as directional signals, not standalone decisions.",
    ]

    return "\n".join(lines)


def generate_csv_report_rows(analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build row dictionaries used for CSV sector performance export."""
    sector_items = _safe_get(
        _safe_get(analysis_result, "sector", {}),
        "sector_performance",
        [],
    )
    rows: List[Dict[str, Any]] = []
    for item in sector_items:
        rows.append(
            {
                "sector": _safe_get(item, "sector", "Unknown"),
                "company_count": _safe_get(item, "company_count", 0),
                "avg_return_pct": _safe_get(item, "avg_return_pct"),
                "avg_valuation": _safe_get(item, "avg_valuation"),
            }
        )
    return rows


def generate_csv_report(analysis_result: Dict[str, Any]) -> str:
    """Serialize sector performance rows into CSV text."""
    rows = generate_csv_report_rows(analysis_result)
    output = io.StringIO()
    fieldnames = ["sector", "company_count", "avg_return_pct", "avg_valuation"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return output.getvalue()


def generate_json_report(
    analysis_result: Dict[str, Any],
    predictive_result: Dict[str, Any],
    risk_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Generate a JSON-ready report payload containing metadata and sections."""
    return {
        "report_metadata": {
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "report_type": "ai_enhancement_summary",
        },
        "analysis": analysis_result,
        "predictive": predictive_result,
        "risk": risk_result,
    }


def generate_full_report_bundle(
    analysis_result: Dict[str, Any],
    predictive_result: Dict[str, Any],
    risk_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Return a bundle containing text, CSV, and JSON report representations."""
    return {
        "text": generate_text_report(analysis_result, predictive_result, risk_result),
        "csv": generate_csv_report(analysis_result),
        "json": generate_json_report(analysis_result, predictive_result, risk_result),
    }
