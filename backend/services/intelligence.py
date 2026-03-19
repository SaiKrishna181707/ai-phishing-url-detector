"""Network and infrastructure intelligence checks for scanned URLs."""
from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlparse

from backend.config import REQUEST_TIMEOUT_SECONDS, SOCKET_TIMEOUT_SECONDS, USER_AGENT
from backend.schemas import IntelligenceChecks
from backend.services.virustotal import VirusTotalClient
from model.feature_extractor import get_registered_domain

try:
    import requests
except Exception:  # pragma: no cover - handled gracefully at runtime
    requests = None

try:
    import whois
except Exception:  # pragma: no cover - handled gracefully at runtime
    whois = None

logger = logging.getLogger(__name__)

if requests is not None:
    try:  # pragma: no cover - cosmetic warning suppression
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    except Exception:
        pass


@dataclass
class UrlIntelligenceService:
    timeout: float = REQUEST_TIMEOUT_SECONDS
    socket_timeout: float = SOCKET_TIMEOUT_SECONDS
    vt_client: VirusTotalClient = field(default_factory=VirusTotalClient)

    def inspect(self, url: str) -> IntelligenceChecks:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        registered_domain = get_registered_domain(host)
        dns_resolves, dns_error = self.check_dns(host, parsed.port or self._default_port(parsed.scheme))
        redirect_checked, redirect_count, redirect_chain, final_url, external_redirect, redirect_error = (
            self.check_redirects(url)
        )
        whois_checked, domain_age_days, registrar, whois_error = self.check_domain_age(registered_domain)
        ssl_checked, ssl_valid, ssl_issuer, ssl_expires_at, ssl_error = self.check_ssl(host, parsed.scheme)
        virustotal = self.vt_client.lookup_url(url)

        return IntelligenceChecks(
            dns_resolves=dns_resolves,
            dns_error=dns_error,
            domain_age_days=domain_age_days,
            registrar=registrar,
            whois_checked=whois_checked,
            whois_error=whois_error,
            ssl_checked=ssl_checked,
            ssl_valid=ssl_valid,
            ssl_issuer=ssl_issuer,
            ssl_expires_at=ssl_expires_at,
            ssl_error=ssl_error,
            redirect_checked=redirect_checked,
            redirect_count=redirect_count,
            redirect_chain=redirect_chain,
            final_url=final_url,
            external_redirect=external_redirect,
            redirect_error=redirect_error,
            virustotal=virustotal,
        )

    def check_dns(self, host: str, port: int) -> tuple[bool | None, str | None]:
        if not host:
            return None, "No hostname was available for DNS validation."
        try:
            ip_address(host)
            return True, None
        except ValueError:
            pass
        try:
            original_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.socket_timeout)
            socket.getaddrinfo(host, port)
            return True, None
        except socket.gaierror as exc:
            return False, f"DNS lookup failed: {exc}"
        except OSError as exc:
            return None, f"DNS lookup failed unexpectedly: {exc}"
        finally:
            socket.setdefaulttimeout(original_timeout)

    def check_redirects(
        self,
        url: str,
    ) -> tuple[bool, int, list[str], str, bool, str | None]:
        if requests is None:
            return False, 0, [url], url, False, "The requests dependency is not installed."
        try:
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=self.timeout,
                headers={"User-Agent": USER_AGENT},
                stream=True,
                verify=False,
            )
            chain = [item.url for item in response.history] + [response.url]
            final_url = response.url
            response.close()
            origin_domain = get_registered_domain(urlparse(url).hostname or "")
            final_domain = get_registered_domain(urlparse(final_url).hostname or "")
            external_redirect = bool(origin_domain and final_domain and origin_domain != final_domain)
            return True, max(len(chain) - 1, 0), chain or [url], final_url, external_redirect, None
        except Exception as exc:
            return False, 0, [url], url, False, f"Redirect analysis failed: {exc}"

    def check_domain_age(self, registered_domain: str) -> tuple[bool, int | None, str | None, str | None]:
        if not registered_domain:
            return False, None, None, "Registered domain was not available for WHOIS lookup."
        try:
            ip_address(registered_domain)
            return False, None, None, "WHOIS lookups are not available for raw IP hosts."
        except ValueError:
            pass
        if whois is None:
            return False, None, None, "The python-whois dependency is not installed."
        try:
            result = whois.whois(registered_domain)
            creation_date = self._pick_datetime(getattr(result, "creation_date", None) or result.get("creation_date"))
            registrar = getattr(result, "registrar", None) or result.get("registrar")
            if creation_date is None:
                return True, None, str(registrar) if registrar else None, "WHOIS did not return a creation date."
            age_days = max((datetime.now(timezone.utc) - creation_date.astimezone(timezone.utc)).days, 0)
            return True, age_days, str(registrar) if registrar else None, None
        except Exception as exc:
            return True, None, None, f"WHOIS lookup failed: {exc}"

    def check_ssl(
        self,
        host: str,
        scheme: str,
    ) -> tuple[bool, bool | None, str | None, str | None, str | None]:
        if scheme.lower() != "https":
            return False, None, None, None, "Submitted URL does not use HTTPS."
        if not host:
            return False, None, None, None, "No hostname was available for SSL validation."
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=self.socket_timeout) as connection:
                with context.wrap_socket(connection, server_hostname=host) as secure_socket:
                    certificate = secure_socket.getpeercert()
            issuer = self._extract_certificate_name(certificate.get("issuer"))
            expires_at = str(certificate.get("notAfter")) if certificate.get("notAfter") else None
            return True, True, issuer, expires_at, None
        except ssl.SSLError as exc:
            return True, False, None, None, f"SSL certificate validation failed: {exc}"
        except OSError as exc:
            return False, None, None, None, f"SSL check unavailable: {exc}"

    @staticmethod
    def _default_port(scheme: str) -> int:
        return 443 if scheme.lower() == "https" else 80

    @staticmethod
    def _pick_datetime(value: object) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, list):
            for item in value:
                picked = UrlIntelligenceService._pick_datetime(item)
                if picked is not None:
                    return picked
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return None

    @staticmethod
    def _extract_certificate_name(issuer: object) -> str | None:
        if not isinstance(issuer, tuple):
            return None
        for part in issuer:
            if not isinstance(part, tuple):
                continue
            for item in part:
                if isinstance(item, tuple) and len(item) == 2 and item[0] == "commonName":
                    return str(item[1])
        return None
