"""Prediction service with model loading and real-time intelligence checks."""
from __future__ import annotations

import logging
import pickle
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from backend.config import BLACKLIST_PATH, MODEL_PATH
from backend.schemas import IntelligenceChecks, PredictionResponse
from backend.services.intelligence import UrlIntelligenceService
from model.feature_extractor import (
    explain_features,
    extract_url_features,
    get_registered_domain,
    is_official_brand_domain,
    validate_url,
)

logger = logging.getLogger(__name__)


@dataclass
class PredictorService:
    model_path: Path = MODEL_PATH
    blacklist_path: Path = BLACKLIST_PATH
    intelligence_service: UrlIntelligenceService = field(default_factory=UrlIntelligenceService)
    _bundle: dict[str, object] | None = None
    _blacklist_cache: set[str] | None = None

    def load_model(self) -> dict[str, object] | None:
        if self._bundle is not None:
            return self._bundle
        if not self.model_path.exists():
            logger.warning("Model bundle was not found at %s", self.model_path)
            return None
        try:
            with self.model_path.open("rb") as model_file:
                self._bundle = pickle.load(model_file)
        except Exception as exc:
            logger.warning("Failed to load model bundle: %s", exc)
            self._bundle = None
        return self._bundle

    def load_blacklist(self) -> set[str]:
        if self._blacklist_cache is not None:
            return self._blacklist_cache
        if not self.blacklist_path.exists():
            self._blacklist_cache = set()
            return self._blacklist_cache
        self._blacklist_cache = {
            line.strip().lower()
            for line in self.blacklist_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        return self._blacklist_cache

    def predict(self, raw_url: str) -> PredictionResponse:
        normalized_url = validate_url(raw_url)
        features = extract_url_features(normalized_url)
        registered_domain = str(features.get("registered_domain", "")) or get_registered_domain(
            urlparse(normalized_url).hostname or ""
        )
        intelligence = self.intelligence_service.inspect(normalized_url)
        final_domain = get_registered_domain(urlparse(intelligence.final_url or normalized_url).hostname or "")
        blacklist = self.load_blacklist()
        blacklist_match = registered_domain in blacklist or final_domain in blacklist

        heuristic_score = self.rule_based_probability(features, intelligence, blacklist_match)
        model_score: float | None = None
        bundle = self.load_model()
        if bundle and bundle.get("model") is not None:
            try:
                model_score = float(bundle["model"].predict_proba(features))
            except Exception as exc:
                logger.warning("Model inference failed for %s: %s", normalized_url, exc)

        scam_probability = self.combine_probabilities(
            heuristic_score=heuristic_score,
            model_score=model_score,
            features=features,
            intelligence=intelligence,
            blacklist_match=blacklist_match,
        )
        safe_probability = round(1.0 - scam_probability, 4)
        prediction = "Scam" if scam_probability >= 0.5 else "Safe"
        confidence = scam_probability if prediction == "Scam" else safe_probability
        reasons = self.build_reasons(features, intelligence, blacklist_match)
        explanation = self.build_explanation(
            prediction=prediction,
            scam_probability=scam_probability,
            safe_probability=safe_probability,
            reasons=reasons,
            blacklist_match=blacklist_match,
            intelligence=intelligence,
        )

        return PredictionResponse(
            url=normalized_url,
            domain=registered_domain,
            prediction=prediction,
            risk_level=self.risk_level(scam_probability),
            confidence=round(confidence, 4),
            scam_probability=scam_probability,
            safe_probability=safe_probability,
            model_score=round(model_score, 4) if model_score is not None else None,
            heuristic_score=heuristic_score,
            explanation=explanation,
            blacklist_match=blacklist_match,
            reasons=reasons,
            features=features,
            intelligence=intelligence,
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def combine_probabilities(
        heuristic_score: float,
        model_score: float | None,
        features: dict[str, int | float | str | bool],
        intelligence: IntelligenceChecks,
        blacklist_match: bool,
    ) -> float:
        score = heuristic_score if model_score is None else ((heuristic_score * 0.55) + (model_score * 0.45))

        if blacklist_match:
            score = max(score, 0.96)

        vt = intelligence.virustotal
        if vt.checked and vt.malicious > 0:
            score = max(score, min(0.62 + (vt.malicious * 0.08) + (vt.suspicious * 0.04), 0.99))
        elif vt.checked and vt.suspicious > 0:
            score = max(score, min(0.56 + (vt.suspicious * 0.05), 0.92))
        elif vt.checked and vt.harmless >= 12 and vt.malicious == 0 and vt.suspicious == 0:
            score -= 0.08

        if intelligence.domain_age_days is not None:
            if intelligence.domain_age_days < 30:
                score += 0.12
            elif intelligence.domain_age_days < 180:
                score += 0.07
            elif intelligence.domain_age_days > 3650:
                score -= 0.06

        if intelligence.ssl_checked and intelligence.ssl_valid is False:
            score += 0.05
        if intelligence.dns_resolves is False:
            score += 0.08
        if intelligence.external_redirect:
            score += 0.08
        if intelligence.redirect_count >= 2:
            score += 0.05
        if int(features["contains_ip_like_host"]) == 1:
            score = max(score, 0.74)
        if int(features["brand_impersonation_count"]) > 0 and int(features["suspicious_keyword_count"]) > 0:
            score += 0.06
        if is_official_brand_domain(str(features.get("registered_domain", ""))) and int(features["brand_impersonation_count"]) == 0:
            score -= 0.08

        return max(0.01, min(round(score, 4), 0.99))

    @staticmethod
    def rule_based_probability(
        features: dict[str, int | float | str | bool],
        intelligence: IntelligenceChecks,
        blacklist_match: bool,
    ) -> float:
        score = 0.09
        score += 0.36 if blacklist_match else 0.0
        score += 0.09 if int(features["has_https"]) == 0 else -0.03
        score += min(int(features["suspicious_keyword_count"]) * 0.045, 0.20)
        score += min(int(features["brand_impersonation_count"]) * 0.12, 0.32)
        score += min(int(features["special_char_count"]) * 0.006, 0.08)
        score += min(int(features["digit_count"]) * 0.007, 0.07)
        score += min(int(features["subdomain_count"]) * 0.035, 0.14)
        score += min(int(features["redirect_param_count"]) * 0.09, 0.18)
        score += 0.22 if int(features["contains_ip_like_host"]) == 1 else 0.0
        score += 0.12 if int(features["has_suspicious_tld"]) == 1 else 0.0
        score += 0.15 if int(features["has_at_symbol"]) == 1 else 0.0
        score += 0.11 if int(features["has_punycode"]) == 1 else 0.0
        score += 0.08 if int(features["uses_shortener"]) == 1 else 0.0
        score += 0.14 if int(features["host_looks_random"]) == 1 else 0.0
        score += 0.06 if float(features["host_entropy"]) > 3.4 else 0.0
        score += 0.05 if float(features["url_entropy"]) > 3.9 else 0.0
        score += 0.06 if int(features["url_length"]) > 90 else -0.01
        score += 0.03 if int(features["path_depth"]) > 4 else 0.0
        if is_official_brand_domain(str(features.get("registered_domain", ""))) and int(features["brand_impersonation_count"]) == 0:
            score -= 0.08
        if intelligence.dns_resolves is True:
            score -= 0.02
        return max(0.01, min(score, 0.99))

    @staticmethod
    def build_reasons(
        features: dict[str, int | float | str | bool],
        intelligence: IntelligenceChecks,
        blacklist_match: bool,
    ) -> list[str]:
        weighted_reasons: list[tuple[int, str]] = []
        vt = intelligence.virustotal

        if blacklist_match:
            weighted_reasons.append((100, "The domain matches a locally blacklisted threat indicator."))
        if vt.checked and vt.malicious > 0:
            weighted_reasons.append(
                (
                    98,
                    f"VirusTotal reports {vt.malicious} malicious and {vt.suspicious} suspicious detections for this URL.",
                )
            )
        elif vt.checked and vt.suspicious > 0:
            weighted_reasons.append((90, f"VirusTotal flagged the URL as suspicious on {vt.suspicious} engines."))
        if int(features["brand_impersonation_count"]) > 0:
            weighted_reasons.append((88, "The hostname looks like it is impersonating a well-known brand."))
        if int(features["contains_ip_like_host"]) == 1:
            weighted_reasons.append((86, "The URL uses a raw IP address instead of a registered domain."))
        if int(features["host_looks_random"]) == 1:
            weighted_reasons.append((84, "The hostname looks randomly generated rather than human-readable."))
        if intelligence.domain_age_days is not None and intelligence.domain_age_days < 180:
            weighted_reasons.append(
                (
                    82,
                    f"The domain is only about {intelligence.domain_age_days} days old, which is a common scam signal.",
                )
            )
        if intelligence.ssl_checked and intelligence.ssl_valid is False:
            weighted_reasons.append((80, "The HTTPS certificate could not be validated successfully."))
        if intelligence.dns_resolves is False:
            weighted_reasons.append((78, "The hostname does not resolve cleanly in DNS."))
        if intelligence.external_redirect:
            weighted_reasons.append((74, "The URL redirects to a different domain, which can hide the true destination."))
        if intelligence.redirect_count >= 2:
            weighted_reasons.append(
                (72, f"The link follows a {intelligence.redirect_count}-hop redirect chain before landing.")
            )
        if int(features["suspicious_keyword_count"]) > 0:
            weighted_reasons.append((68, "The URL contains phishing-style wording such as verify, secure, or reset."))
        if int(features["has_suspicious_tld"]) == 1:
            weighted_reasons.append((66, "The top-level domain is often associated with throwaway or abusive links."))
        if int(features["has_https"]) == 0:
            weighted_reasons.append((62, "The submitted link uses HTTP instead of HTTPS."))

        if not weighted_reasons:
            for reason in explain_features(features, blacklist_match):
                weighted_reasons.append((50, reason))
            if vt.checked and vt.malicious == 0 and vt.suspicious == 0:
                weighted_reasons.append((48, "VirusTotal did not report malicious detections for this URL."))
            if intelligence.ssl_checked and intelligence.ssl_valid is True:
                weighted_reasons.append((46, "The HTTPS certificate validated successfully."))
            if intelligence.domain_age_days is not None and intelligence.domain_age_days >= 365:
                weighted_reasons.append(
                    (44, f"The domain has existed for about {intelligence.domain_age_days} days, which is reassuring.")
                )
            if intelligence.dns_resolves is True:
                weighted_reasons.append((42, "The hostname resolves normally in DNS."))
            if intelligence.redirect_checked and intelligence.redirect_count == 0:
                weighted_reasons.append((40, "The link does not bounce through a redirect chain."))

        weighted_reasons.sort(key=lambda item: item[0], reverse=True)
        return [message for _, message in weighted_reasons[:6]]

    @staticmethod
    def build_explanation(
        prediction: str,
        scam_probability: float,
        safe_probability: float,
        reasons: list[str],
        blacklist_match: bool,
        intelligence: IntelligenceChecks,
    ) -> str:
        if prediction == "Scam":
            summary = "This URL triggered more risk signals than trust signals."
            if blacklist_match or (intelligence.virustotal.checked and intelligence.virustotal.malicious > 0):
                summary = "This URL triggered strong reputation signals in addition to suspicious structure."
            elif intelligence.external_redirect:
                summary = "This URL combines structural red flags with a redirect pattern that can mask the final destination."
            intro = f"Scam risk {scam_probability * 100:.2f}%."
        else:
            summary = "The URL looks comparatively legitimate across the checks that completed, but automated analysis can never guarantee safety."
            intro = f"Safe likelihood {safe_probability * 100:.2f}% with scam risk {scam_probability * 100:.2f}%."
        detail = " ".join(reasons[:2])
        return f"{intro} {summary} {detail}".strip()

    @staticmethod
    def risk_level(scam_probability: float) -> str:
        if scam_probability >= 0.85:
            return "Critical"
        if scam_probability >= 0.65:
            return "High"
        if scam_probability >= 0.40:
            return "Guarded"
        return "Low"
