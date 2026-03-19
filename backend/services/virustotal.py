"""VirusTotal API client used for optional real-time reputation checks."""
from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass, field

from backend.config import (
    REQUEST_TIMEOUT_SECONDS,
    USER_AGENT,
    VT_API_KEY,
    VT_BASE_URL,
    VT_POLL_ATTEMPTS,
    VT_POLL_INTERVAL_SECONDS,
)
from backend.schemas import VirusTotalSummary

try:
    import requests
except Exception:  # pragma: no cover - handled gracefully at runtime
    requests = None

logger = logging.getLogger(__name__)


@dataclass
class VirusTotalClient:
    api_key: str = VT_API_KEY
    base_url: str = VT_BASE_URL
    timeout: float = REQUEST_TIMEOUT_SECONDS
    poll_attempts: int = VT_POLL_ATTEMPTS
    poll_interval_seconds: float = VT_POLL_INTERVAL_SECONDS
    _cache: dict[str, tuple[float, VirusTotalSummary]] = field(default_factory=dict, init=False)

    def lookup_url(self, url: str) -> VirusTotalSummary:
        if not self.api_key:
            return VirusTotalSummary(
                enabled=False,
                checked=False,
                error="VirusTotal API key is not configured.",
            )
        if requests is None:
            return VirusTotalSummary(
                enabled=True,
                checked=False,
                error="The requests dependency is not installed.",
            )

        cached = self._cache.get(url)
        if cached and (time.time() - cached[0]) < 900:
            return cached[1]

        try:
            report_payload = self._request_json("GET", f"/urls/{self._encode_url_id(url)}")
            if report_payload is None:
                analysis_id = self._submit_url(url)
                if analysis_id is None:
                    result = VirusTotalSummary(
                        enabled=True,
                        checked=False,
                        error="VirusTotal did not return an analysis id.",
                    )
                else:
                    analysis_payload = self._poll_analysis(analysis_id)
                    result = self._build_summary_from_analysis(analysis_payload, analysis_id)
            else:
                result = self._build_summary_from_report(report_payload)
        except Exception as exc:
            logger.warning("VirusTotal lookup failed for %s: %s", url, exc)
            result = VirusTotalSummary(enabled=True, checked=False, error=str(exc))

        self._cache[url] = (time.time(), result)
        return result

    def _request_json(self, method: str, path: str, **kwargs) -> dict[str, object] | None:
        response = requests.request(
            method,
            f"{self.base_url}{path}",
            timeout=self.timeout,
            headers={
                "x-apikey": self.api_key,
                "User-Agent": USER_AGENT,
            },
            **kwargs,
        )
        if response.status_code == 404:
            return None
        if response.status_code == 429:
            raise RuntimeError("VirusTotal free-tier rate limit reached. Please try again shortly.")
        response.raise_for_status()
        return response.json()

    def _submit_url(self, url: str) -> str | None:
        payload = self._request_json("POST", "/urls", data={"url": url})
        data = (payload or {}).get("data", {})
        analysis_id = data.get("id")
        return str(analysis_id) if analysis_id else None

    def _poll_analysis(self, analysis_id: str) -> dict[str, object] | None:
        if self.poll_attempts <= 0:
            return None
        latest_payload: dict[str, object] | None = None
        for _ in range(self.poll_attempts):
            latest_payload = self._request_json("GET", f"/analyses/{analysis_id}")
            attributes = ((latest_payload or {}).get("data", {}) or {}).get("attributes", {})
            if attributes.get("status") == "completed":
                return latest_payload
            time.sleep(self.poll_interval_seconds)
        return latest_payload

    @staticmethod
    def _build_summary_from_report(payload: dict[str, object]) -> VirusTotalSummary:
        data = (payload or {}).get("data", {}) or {}
        attributes = data.get("attributes", {}) or {}
        stats = attributes.get("last_analysis_stats", {}) or {}
        report_id = data.get("id")
        return VirusTotalSummary(
            enabled=True,
            checked=bool(stats or report_id),
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            timeout=int(stats.get("timeout", 0)),
            failure=int(stats.get("failure", 0)),
            analysis_id=str(report_id) if report_id else None,
            permalink=f"https://www.virustotal.com/gui/url/{report_id}" if report_id else None,
        )

    @staticmethod
    def _build_summary_from_analysis(
        payload: dict[str, object] | None,
        analysis_id: str,
    ) -> VirusTotalSummary:
        attributes = (((payload or {}).get("data", {}) or {}).get("attributes", {}) or {})
        stats = attributes.get("stats", {}) or {}
        status = str(attributes.get("status", "")).lower()
        return VirusTotalSummary(
            enabled=True,
            checked=bool(stats or analysis_id),
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            timeout=int(stats.get("timeout", 0)),
            failure=int(stats.get("failure", 0)),
            analysis_id=analysis_id,
            queued=status != "completed",
            error=None if status == "completed" else "VirusTotal scan was submitted and is still processing.",
        )

    @staticmethod
    def _encode_url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
