"""Feature extraction and URL validation utilities."""
from __future__ import annotations

import math
import re
from ipaddress import ip_address
from urllib.parse import parse_qs, urlparse, urlunparse

SUSPICIOUS_KEYWORDS = {
    "account",
    "bank",
    "bonus",
    "confirm",
    "gift",
    "invoice",
    "login",
    "pay",
    "payment",
    "recover",
    "refund",
    "reset",
    "secure",
    "signin",
    "unlock",
    "update",
    "urgent",
    "verify",
    "wallet",
}
SUSPICIOUS_TLDS = {"buzz", "click", "gq", "icu", "live", "support", "top", "work", "xyz", "zip"}
COMMON_TLDS = {
    "ai",
    "app",
    "biz",
    "blog",
    "cc",
    "cloud",
    "co",
    "com",
    "company",
    "dev",
    "edu",
    "gov",
    "info",
    "io",
    "me",
    "mil",
    "net",
    "online",
    "org",
    "pro",
    "shop",
    "site",
    "store",
    "tech",
    "us",
    "world",
}
SPECIAL_CHARACTERS = set("@-_?=&%./:#")
SHORTENER_DOMAINS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tinyurl.com",
}
MULTIPART_SUFFIXES = {
    "ac.in",
    "co.in",
    "co.jp",
    "co.kr",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.mx",
    "com.sg",
    "com.tr",
    "gov.uk",
    "org.uk",
}
OFFICIAL_BRAND_DOMAINS = {
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "apple": {"apple.com", "icloud.com"},
    "bankofamerica": {"bankofamerica.com"},
    "binance": {"binance.com"},
    "chase": {"chase.com"},
    "coinbase": {"coinbase.com"},
    "dhl": {"dhl.com"},
    "dropbox": {"dropbox.com"},
    "fedex": {"fedex.com"},
    "github": {"github.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "instagram": {"instagram.com"},
    "irs": {"irs.gov"},
    "linkedin": {"linkedin.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "netflix": {"netflix.com"},
    "openai": {"openai.com"},
    "paypal": {"paypal.com"},
    "steam": {"steampowered.com"},
}
MODEL_FEATURES = [
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "has_https",
    "special_char_count",
    "digit_count",
    "hyphen_count",
    "dot_count",
    "subdomain_count",
    "path_depth",
    "suspicious_keyword_count",
    "brand_impersonation_count",
    "contains_ip_like_host",
    "has_suspicious_tld",
    "has_at_symbol",
    "has_punycode",
    "uses_shortener",
    "host_looks_random",
    "redirect_param_count",
    "host_entropy",
    "url_entropy",
]

DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9-]{1,63}$")


def validate_url(url: str) -> str:
    candidate = (url or "").strip()
    if not candidate:
        raise ValueError("Please enter a URL to analyze.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = f"http://{candidate}"

    parsed = urlparse(candidate)
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValueError("Please enter a valid URL, for example https://example.com.")

    _validate_hostname(hostname)
    normalized_netloc = hostname
    if parsed.port:
        normalized_netloc = f"{hostname}:{parsed.port}"
    normalized_path = parsed.path or "/"

    return urlunparse(
        (
            parsed.scheme.lower(),
            normalized_netloc,
            normalized_path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def get_registered_domain(hostname: str) -> str:
    host = (hostname or "").lower().strip(".")
    if not host:
        return ""
    try:
        ip_address(host)
        return host
    except ValueError:
        pass

    parts = host.split(".")
    if len(parts) <= 2:
        return host

    multipart_suffix = ".".join(parts[-2:])
    if multipart_suffix in MULTIPART_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def extract_url_features(url: str) -> dict[str, int | float | str | bool]:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    registered_domain = get_registered_domain(hostname)
    tld = registered_domain.rsplit(".", 1)[-1] if "." in registered_domain else registered_domain
    compact_url = _compact_string(url.lower())
    query_keys = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True)}

    return {
        "url_length": len(url),
        "host_length": len(hostname),
        "path_length": len(parsed.path or ""),
        "query_length": len(parsed.query or ""),
        "has_https": int(parsed.scheme == "https"),
        "special_char_count": sum(char in SPECIAL_CHARACTERS for char in url),
        "digit_count": sum(char.isdigit() for char in url),
        "hyphen_count": url.count("-"),
        "dot_count": hostname.count("."),
        "subdomain_count": max(len(hostname.split(".")) - len(registered_domain.split(".")), 0),
        "path_depth": len([part for part in (parsed.path or "").split("/") if part]),
        "suspicious_keyword_count": sum(keyword in compact_url for keyword in SUSPICIOUS_KEYWORDS),
        "brand_impersonation_count": _brand_impersonation_count(hostname, registered_domain),
        "contains_ip_like_host": int(_is_ip_host(hostname)),
        "has_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "has_at_symbol": int("@" in url),
        "has_punycode": int("xn--" in hostname),
        "uses_shortener": int(registered_domain in SHORTENER_DOMAINS),
        "host_looks_random": int(_looks_random(hostname, registered_domain)),
        "redirect_param_count": sum(
            1
            for key in query_keys
            if key in {"continue", "dest", "destination", "next", "redirect", "return", "target", "url"}
        ),
        "host_entropy": round(_shannon_entropy(_compact_string(hostname)), 4),
        "url_entropy": round(_shannon_entropy(_compact_string(url.lower())), 4),
        "domain": hostname,
        "registered_domain": registered_domain,
    }


def explain_features(features: dict[str, int | float | str | bool], blacklist_match: bool) -> list[str]:
    reasons: list[str] = []
    if blacklist_match:
        reasons.append("Domain matched a locally blacklisted phishing or scam host.")
    if int(features["brand_impersonation_count"]) > 0:
        reasons.append("The hostname resembles a brand-impersonation pattern.")
    if int(features["host_looks_random"]) == 1:
        reasons.append("The hostname looks algorithmically generated or unusually random.")
    if int(features["contains_ip_like_host"]) == 1:
        reasons.append("The URL uses an IP address instead of a normal registered domain.")
    if int(features["has_suspicious_tld"]) == 1:
        reasons.append("The top-level domain is often abused in throwaway or malicious links.")
    if int(features["redirect_param_count"]) > 0:
        reasons.append("The query string contains redirect-style parameters that can hide a destination.")
    if int(features["has_https"]) == 0:
        reasons.append("The submitted link uses HTTP instead of HTTPS.")
    if int(features["suspicious_keyword_count"]) > 0:
        reasons.append("The URL contains phishing-style wording such as verify, secure, or reset.")
    if not reasons:
        reasons.append("The URL structure looks comparatively normal and does not expose major lexical red flags.")
    return reasons


def is_official_brand_domain(registered_domain: str) -> bool:
    return any(registered_domain in domains for domains in OFFICIAL_BRAND_DOMAINS.values())


def _validate_hostname(hostname: str) -> None:
    try:
        ip_address(hostname)
        return
    except ValueError:
        pass

    if len(hostname) > 253 or "." not in hostname:
        raise ValueError("Please enter a valid public URL with a full domain name.")

    labels = hostname.split(".")
    for label in labels:
        if not DOMAIN_LABEL_PATTERN.match(label) or label.startswith("-") or label.endswith("-"):
            raise ValueError("Please enter a valid URL with a properly formatted domain.")

    tld = labels[-1]
    if not _is_recognized_tld(tld):
        raise ValueError("Please enter a valid URL with a recognized domain suffix.")


def _is_recognized_tld(tld: str) -> bool:
    return tld in COMMON_TLDS or (len(tld) == 2 and tld.isalpha()) or tld in SUSPICIOUS_TLDS


def _brand_impersonation_count(hostname: str, registered_domain: str) -> int:
    if not hostname:
        return 0
    host_skeleton = _normalize_confusable_text(_compact_string(hostname))
    score = 0
    for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
        if brand in host_skeleton and registered_domain not in official_domains:
            score += 1
    return score


def _is_ip_host(hostname: str) -> bool:
    try:
        ip_address(hostname)
        return True
    except ValueError:
        return False


def _looks_random(hostname: str, registered_domain: str) -> bool:
    if _is_ip_host(hostname):
        return True
    host_core = _compact_string(registered_domain.split(".")[0] if registered_domain else hostname)
    if len(host_core) < 8:
        return False
    vowel_count = sum(char in "aeiou" for char in host_core)
    vowel_ratio = vowel_count / len(host_core)
    entropy = _shannon_entropy(host_core)
    consonant_runs = max((len(match.group(0)) for match in re.finditer(r"[bcdfghjklmnpqrstvwxyz]+", host_core)), default=0)
    digit_ratio = sum(char.isdigit() for char in host_core) / len(host_core)
    return entropy > 3.25 and (vowel_ratio < 0.28 or consonant_runs >= 5 or digit_ratio >= 0.25)


def _normalize_confusable_text(text: str) -> str:
    return (
        text.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("7", "t")
        .replace("8", "b")
    )


def _compact_string(value: str) -> str:
    return "".join(char for char in value.lower() if char.isalnum())


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
