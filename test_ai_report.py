"""Unit tests for AI report generation helpers."""

import unittest

from ai_report import (
    generate_csv_report,
    generate_csv_report_rows,
    generate_full_report_bundle,
    generate_json_report,
    generate_text_report,
)


ANALYSIS_RESULT = {
    "sector": {
        "sector_count": 2,
        "sector_performance": [
            {
                "sector": "Technology",
                "company_count": 2,
                "avg_return_pct": 12.5,
                "avg_valuation": 3_000_000_000,
            },
            {
                "sector": "Finance",
                "company_count": 1,
                "avg_return_pct": 8.0,
                "avg_valuation": 12_000_000_000,
            },
        ],
    },
    "distribution": {
        "distribution_by_sector": {"Technology": 2, "Finance": 1},
        "distribution_by_valuation_bucket": {"small": 1, "mid": 1, "large": 1, "unknown": 0},
    },
    "metrics": {
        "total_companies": 3,
        "total_valuation": 18_000_000_000,
        "average_return_pct": 10.5,
        "average_risk_score": 4.0,
    },
}

PREDICTIVE_RESULT = {"status": "ok", "predictions": {"moving_average": [10.0], "trend": [11.0]}}
RISK_RESULT = {"overall_risk": "medium", "high_risk_entities": 1}


class TestAIReport(unittest.TestCase):
    """Tests for text, CSV, JSON, and bundled report outputs."""

    def test_generate_text_report(self):
        """Generates readable text report containing key expected sections."""
        text = generate_text_report(ANALYSIS_RESULT, PREDICTIVE_RESULT, RISK_RESULT)
        self.assertIn("AI Insights Report", text)
        self.assertIn("Total Companies", text)

    def test_generate_csv_report_rows(self):
        """Builds sector rows with expected ordering and shape."""
        rows = generate_csv_report_rows(ANALYSIS_RESULT)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["sector"], "Technology")

    def test_generate_csv_report(self):
        """CSV report should include the expected header row."""
        csv_text = generate_csv_report(ANALYSIS_RESULT)
        self.assertIn("sector,company_count,avg_return_pct,avg_valuation", csv_text)

    def test_generate_json_report(self):
        """Returns JSON payload with analysis, predictive, and risk sections."""
        payload = generate_json_report(ANALYSIS_RESULT, PREDICTIVE_RESULT, RISK_RESULT)
        self.assertIn("analysis", payload)
        self.assertIn("predictive", payload)
        self.assertIn("risk", payload)

    def test_generate_full_report_bundle(self):
        """Returns bundle containing text, CSV, and JSON renderings."""
        bundle = generate_full_report_bundle(ANALYSIS_RESULT, PREDICTIVE_RESULT, RISK_RESULT)
        self.assertIn("text", bundle)
        self.assertIn("csv", bundle)
        self.assertIn("json", bundle)


if __name__ == "__main__":
    unittest.main()
