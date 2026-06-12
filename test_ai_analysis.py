import unittest

from ai_analysis import (
    run_full_analysis,
    summarize_company_distribution,
    summarize_key_metrics,
    summarize_sector_performance,
)


SAMPLE_DATA = [
    {"company_name": "A", "sector": "Technology", "valuation": 1_000_000_000, "return_pct": 10.0, "risk_score": 3.0},
    {"company_name": "B", "sector": "Technology", "valuation": 5_000_000_000, "return_pct": 15.0, "risk_score": 4.0},
    {"company_name": "C", "sector": "Finance", "valuation": 12_000_000_000, "return_pct": 8.0, "risk_score": 5.0},
    {"company_name": "D", "sector": "Healthcare", "valuation": None, "return_pct": None, "risk_score": None},
]


class TestAIAnalysis(unittest.TestCase):
    def test_sector_performance(self):
        result = summarize_sector_performance(SAMPLE_DATA)
        self.assertIn("sector_performance", result)
        self.assertGreaterEqual(result["sector_count"], 3)

    def test_company_distribution(self):
        result = summarize_company_distribution(SAMPLE_DATA)
        self.assertEqual(result["total_companies"], 4)
        self.assertIn("Technology", result["distribution_by_sector"])

    def test_key_metrics(self):
        result = summarize_key_metrics(SAMPLE_DATA)
        self.assertEqual(result["total_companies"], 4)
        self.assertIsNotNone(result["total_valuation"])
        self.assertIsNotNone(result["average_return_pct"])

    def test_full_analysis(self):
        result = run_full_analysis(SAMPLE_DATA)
        self.assertIn("sector", result)
        self.assertIn("distribution", result)
        self.assertIn("metrics", result)


if __name__ == "__main__":
    unittest.main()
