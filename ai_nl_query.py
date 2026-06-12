"""
Natural language query parsing and routing for corporate analytics.

This module converts user text into:
- intent
- extracted entities/filters
- normalized structured query objects

It is intentionally lightweight and deterministic for backend integration and testing.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


INTENT_KEYWORDS = {
    "sector_performance": ["sector performance", "best sector", "worst sector", "sector returns"],
    "company_distribution": ["distribution", "how many companies", "company count", "breakdown"],
    "key_metrics": ["key metrics", "summary metrics", "portfolio metrics", "overall performance"],
    "risk_assessment": ["risk", "risk score", "compliance risk", "high risk"],
    "predict": ["predict", "forecast", "projection", "future trend"],
    "report": ["report", "generate report", "export report", "summary report"],
}


SECTOR_HINTS = [
    "technology",
    "healthcare",
    "finance",
    "energy",
    "consumer",
    "industrial",
    "real estate",
    "utilities",
]


def _normalize(text: str) -> str:
    return " ".join(text.strip().lower().split())


def detect_intent(query: str) -> str:
    """Detect the best-matching intent label from a natural language query."""
    normalized = _normalize(query)
    for intent, keywords in INTENT_KEYWORDS.items():
        for phrase in keywords:
            if phrase in normalized:
                return intent
    return "unknown"


def extract_entities(query: str) -> Dict[str, Any]:
    """Extract structured entities such as sectors, top_n, year, and risk_level."""
    normalized = _normalize(query)
    entities: Dict[str, Any] = {}

    matched_sectors: List[str] = [s for s in SECTOR_HINTS if s in normalized]
    if matched_sectors:
        entities["sectors"] = matched_sectors

    top_match = re.search(r"\btop\s+(\d+)\b", normalized)
    if top_match:
        entities["top_n"] = int(top_match.group(1))

    year_match = re.search(r"\b(20\d{2})\b", normalized)
    if year_match:
        entities["year"] = int(year_match.group(1))

    high_risk = any(token in normalized for token in ["high risk", "critical risk"])
    if high_risk:
        entities["risk_level"] = "high"

    return entities


def parse_nl_query(query: str) -> Dict[str, Any]:
    """Parse a natural language query into intent, entities, and confidence."""
    intent = detect_intent(query)
    entities = extract_entities(query)

    return {
        "raw_query": query,
        "intent": intent,
        "entities": entities,
        "confidence": 0.85 if intent != "unknown" else 0.2,
    }


def to_structured_query(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Map parsed query output to an executable backend action and filters."""
    intent = parsed.get("intent", "unknown")
    entities = parsed.get("entities", {})

    action_map = {
        "sector_performance": "analyze_sector_performance",
        "company_distribution": "analyze_company_distribution",
        "key_metrics": "analyze_key_metrics",
        "risk_assessment": "run_risk_assessment",
        "predict": "run_predictive_model",
        "report": "generate_report",
        "unknown": "fallback_help",
    }

    return {
        "action": action_map.get(intent, "fallback_help"),
        "filters": entities,
        "meta": {
            "intent": intent,
            "confidence": parsed.get("confidence", 0.0),
        },
    }


def handle_query(query: str) -> Dict[str, Any]:
    """End-to-end handler that returns parsed and structured query payloads."""
    parsed = parse_nl_query(query)
    structured = to_structured_query(parsed)
    return {
        "parsed": parsed,
        "structured_query": structured,
    }
