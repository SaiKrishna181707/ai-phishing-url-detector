"""Shared request and response schemas."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class URLRequest:
    url: str


@dataclass
class VirusTotalSummary:
    enabled: bool
    checked: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    failure: int = 0
    analysis_id: str | None = None
    permalink: str | None = None
    queued: bool = False
    error: str | None = None


@dataclass
class IntelligenceChecks:
    dns_resolves: bool | None
    dns_error: str | None
    domain_age_days: int | None
    registrar: str | None
    whois_checked: bool
    whois_error: str | None
    ssl_checked: bool
    ssl_valid: bool | None
    ssl_issuer: str | None
    ssl_expires_at: str | None
    ssl_error: str | None
    redirect_checked: bool
    redirect_count: int
    redirect_chain: list[str] = field(default_factory=list)
    final_url: str | None = None
    external_redirect: bool = False
    redirect_error: str | None = None
    virustotal: VirusTotalSummary = field(
        default_factory=lambda: VirusTotalSummary(enabled=False, checked=False)
    )


@dataclass
class PredictionResponse:
    url: str
    domain: str
    prediction: str
    risk_level: str
    confidence: float
    scam_probability: float
    safe_probability: float
    model_score: float | None
    heuristic_score: float
    explanation: str
    blacklist_match: bool
    reasons: list[str]
    features: dict[str, int | float | str | bool]
    intelligence: IntelligenceChecks
    scanned_at: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
