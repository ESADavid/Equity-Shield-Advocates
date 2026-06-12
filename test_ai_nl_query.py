"""Unit tests for natural-language query parsing and structuring helpers."""

import unittest

from ai_nl_query import (
    detect_intent,
    extract_entities,
    handle_query,
    parse_nl_query,
    to_structured_query,
)


class TestAINLQuery(unittest.TestCase):
    """Tests for ai_nl_query public helper functions."""

    def test_detect_intent(self):
        """Detects expected intent labels from representative input queries."""
        self.assertEqual(
            detect_intent("show sector performance for technology"),
            "sector_performance",
        )
        self.assertEqual(detect_intent("generate report for 2025"), "report")

    def test_extract_entities(self):
        """Extracts top_n, year, sector, and risk-level entities from text."""
        entities = extract_entities(
            "show top 5 technology companies in 2025 with high risk"
        )
        self.assertEqual(entities.get("top_n"), 5)
        self.assertEqual(entities.get("year"), 2025)
        self.assertIn("technology", entities.get("sectors", []))
        self.assertEqual(entities.get("risk_level"), "high")

    def test_parse_nl_query(self):
        """Builds a parsed payload containing intent and entities keys."""
        parsed = parse_nl_query("forecast finance trend")
        self.assertIn("intent", parsed)
        self.assertIn("entities", parsed)

    def test_to_structured_query(self):
        """Converts parsed NL payload into expected structured query shape."""
        parsed = {"intent": "predict", "entities": {"year": 2025}, "confidence": 0.9}
        structured = to_structured_query(parsed)
        self.assertEqual(structured["action"], "run_predictive_model")
        self.assertEqual(structured["filters"]["year"], 2025)

    def test_handle_query(self):
        """Returns both parsed output and structured query for full flow."""
        result = handle_query("generate report for healthcare sector")
        self.assertIn("parsed", result)
        self.assertIn("structured_query", result)


if __name__ == "__main__":
    unittest.main()
