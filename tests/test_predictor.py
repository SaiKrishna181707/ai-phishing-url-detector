from __future__ import annotations

import unittest
from pathlib import Path

from backend.schemas import IntelligenceChecks, VirusTotalSummary
from backend.services.predictor import PredictorService


class DummyIntelligenceService:
    def __init__(self, checks: IntelligenceChecks) -> None:
        self.checks = checks

    def inspect(self, url: str) -> IntelligenceChecks:
        return self.checks


class PredictorServiceTests(unittest.TestCase):
    def test_suspicious_brand_url_scores_as_scam(self) -> None:
        checks = IntelligenceChecks(
            dns_resolves=False,
            dns_error="DNS lookup failed",
            domain_age_days=12,
            registrar=None,
            whois_checked=True,
            whois_error=None,
            ssl_checked=True,
            ssl_valid=False,
            ssl_issuer=None,
            ssl_expires_at=None,
            ssl_error="SSL certificate validation failed",
            redirect_checked=True,
            redirect_count=2,
            redirect_chain=["https://secure-login-paypa1.com/verify", "https://fraud-paypal.top/login"],
            final_url="https://fraud-paypal.top/login",
            external_redirect=True,
            redirect_error=None,
            virustotal=VirusTotalSummary(enabled=True, checked=True, malicious=3, suspicious=2),
        )
        service = PredictorService(
            model_path=Path("missing-model.joblib"),
            intelligence_service=DummyIntelligenceService(checks),
        )

        result = service.predict("https://secure-login-paypa1.com/verify")
        self.assertEqual(result.prediction, "Scam")
        self.assertGreater(result.scam_probability, 0.8)
        self.assertIn("Scam risk", result.explanation)

    def test_stable_url_scores_as_safe(self) -> None:
        checks = IntelligenceChecks(
            dns_resolves=True,
            dns_error=None,
            domain_age_days=4000,
            registrar="Example Registrar",
            whois_checked=True,
            whois_error=None,
            ssl_checked=True,
            ssl_valid=True,
            ssl_issuer="Example CA",
            ssl_expires_at="Jan  1 00:00:00 2030 GMT",
            ssl_error=None,
            redirect_checked=True,
            redirect_count=0,
            redirect_chain=["https://github.com/openai"],
            final_url="https://github.com/openai",
            external_redirect=False,
            redirect_error=None,
            virustotal=VirusTotalSummary(enabled=True, checked=True, malicious=0, suspicious=0, harmless=25),
        )
        service = PredictorService(
            model_path=Path("missing-model.joblib"),
            intelligence_service=DummyIntelligenceService(checks),
        )

        result = service.predict("https://github.com/openai")
        self.assertEqual(result.prediction, "Safe")
        self.assertGreater(result.safe_probability, 0.6)
        self.assertIn("Safe likelihood", result.explanation)


if __name__ == "__main__":
    unittest.main()
