from __future__ import annotations

import unittest

from model.feature_extractor import extract_url_features, validate_url


class FeatureExtractorTests(unittest.TestCase):
    def test_invalid_tld_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_url("bfsiehbf.cndn/wdn")

    def test_missing_scheme_is_normalized(self) -> None:
        normalized = validate_url("github.com/openai")
        self.assertEqual(normalized, "http://github.com/openai")

    def test_brand_impersonation_is_detected(self) -> None:
        features = extract_url_features(validate_url("https://secure-login-paypa1.com/verify"))
        self.assertGreaterEqual(int(features["brand_impersonation_count"]), 1)


if __name__ == "__main__":
    unittest.main()
