"""
AI analysis utilities for corporate structure datasets.

This module provides deterministic, testable analytics helpers that summarize:
- sector performance
- company distributions
- key portfolio metrics

Data contract (flexible, best-effort):
Input can be either:
1) list[dict] of company records, or
2) dict with a list under one of: "companies", "data", "records"

Expected record keys (optional, with graceful fallbacks):
- company_name | name
- sector
- valuation | market_cap | value
- return_pct | performance_pct | ytd_return_pct
- risk_score
"""

from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean
from typing import Any, Dict, List, Optional


def _extract_records(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("companies", "data", "records"):
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


def _to_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _get_first(record: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record:
            return record.get(key)
    return None


def summarize_sector_performance(payload: Any) -> Dict[str, Any]:
    """
    Aggregates average return and average valuation by sector.
    """
    records = _extract_records(payload)
    bucket: Dict[str, Dict[str, List[float]]] = defaultdict(
        lambda: {"returns": [], "valuations": []}
    )

    for record in records:
        sector = _get_first(record, "sector") or "Unknown"
        # Ensure sector is represented even when return/valuation are missing.
        _ = bucket[sector]
        ret = _to_float(_get_first(record, "return_pct", "performance_pct", "ytd_return_pct"))
        val = _to_float(_get_first(record, "valuation", "market_cap", "value"))

        if ret is not None:
            bucket[sector]["returns"].append(ret)
        if val is not None:
            bucket[sector]["valuations"].append(val)

    sectors: List[Dict[str, Any]] = []
    for sector, values in bucket.items():
        avg_return = mean(values["returns"]) if values["returns"] else None
        avg_valuation = mean(values["valuations"]) if values["valuations"] else None
        sort_return = avg_return if avg_return is not None else float("-inf")
        sectors.append(
            {
                "sector": sector,
                "company_count": len(values["returns"]) if values["returns"] else 0,
                "avg_return_pct": avg_return,
                "avg_valuation": avg_valuation,
                "_sort_return": sort_return,
            }
        )

    sectors.sort(key=lambda x: x["_sort_return"], reverse=True)
    for item in sectors:
        item.pop("_sort_return", None)
    return {"sector_performance": sectors, "sector_count": len(sectors)}


def summarize_company_distribution(payload: Any) -> Dict[str, Any]:
    """
    Summarizes company counts by sector and valuation buckets.
    """
    records = _extract_records(payload)
    by_sector: Dict[str, int] = {}
    valuation_buckets: Dict[str, int] = {"small": 0, "mid": 0, "large": 0, "unknown": 0}

    for record in records:
        sector = _get_first(record, "sector") or "Unknown"
        by_sector[sector] = by_sector.get(sector, 0) + 1

        valuation = _to_float(_get_first(record, "valuation", "market_cap", "value"))
        if valuation is None:
            valuation_buckets["unknown"] = valuation_buckets["unknown"] + 1
        elif valuation < 2e9:
            valuation_buckets["small"] = valuation_buckets["small"] + 1
        elif valuation < 10e9:
            valuation_buckets["mid"] = valuation_buckets["mid"] + 1
        else:
            valuation_buckets["large"] = valuation_buckets["large"] + 1

    return {
        "total_companies": len(records),
        "distribution_by_sector": by_sector,
        "distribution_by_valuation_bucket": valuation_buckets,
    }


def summarize_key_metrics(payload: Any) -> Dict[str, Any]:
    """
    Computes top-level metrics used for investment/risk reporting.
    """
    records = _extract_records(payload)
    valuations: List[float] = []
    returns: List[float] = []
    risks: List[float] = []

    for record in records:
        val = _to_float(_get_first(record, "valuation", "market_cap", "value"))
        ret = _to_float(_get_first(record, "return_pct", "performance_pct", "ytd_return_pct"))
        risk = _to_float(_get_first(record, "risk_score"))

        if val is not None:
            valuations.append(val)
        if ret is not None:
            returns.append(ret)
        if risk is not None:
            risks.append(risk)

    return {
        "total_companies": len(records),
        "total_valuation": sum(valuations) if valuations else 0.0,
        "average_return_pct": mean(returns) if returns else None,
        "average_risk_score": mean(risks) if risks else None,
        "max_valuation": max(valuations) if valuations else None,
        "min_valuation": min(valuations) if valuations else None,
    }


def run_full_analysis(payload: Any) -> Dict[str, Any]:
    """
    Convenience orchestrator for all summaries.
    """
    return {
        "sector": summarize_sector_performance(payload),
        "distribution": summarize_company_distribution(payload),
        "metrics": summarize_key_metrics(payload),
    }
