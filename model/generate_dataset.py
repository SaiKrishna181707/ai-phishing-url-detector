"""Generate a larger phishing URL dataset for local model training."""
from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from model.feature_extractor import validate_url

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "url_dataset.csv"

SAFE_DOMAINS = [
    "accounts.google.com",
    "amazon.com",
    "apple.com",
    "bankofamerica.com",
    "bbc.com",
    "binance.com",
    "chase.com",
    "cloudflare.com",
    "coursera.org",
    "developer.mozilla.org",
    "docs.python.org",
    "dropbox.com",
    "fedex.com",
    "github.com",
    "gmail.com",
    "irs.gov",
    "linkedin.com",
    "microsoft.com",
    "netflix.com",
    "news.ycombinator.com",
    "nasa.gov",
    "office.com",
    "openai.com",
    "outlook.com",
    "paypal.com",
    "reddit.com",
    "stackoverflow.com",
    "steampowered.com",
    "support.google.com",
    "wikipedia.org",
    "youtube.com",
]
SAFE_PATHS = [
    "/",
    "/account",
    "/account/security",
    "/billing",
    "/browse",
    "/checkout",
    "/dashboard",
    "/docs/api",
    "/feed",
    "/help",
    "/learn/python",
    "/login",
    "/orders",
    "/payments",
    "/research",
    "/security",
    "/signin",
    "/support",
]
SAFE_QUERIES = [
    "",
    "?lang=en",
    "?page=1",
    "?ref=app",
    "?source=mobile",
    "?tab=security",
]
SCAM_BRANDS = [
    "amazon",
    "apple",
    "bankofamerica",
    "binance",
    "chase",
    "coinbase",
    "dhl",
    "dropbox",
    "facebook",
    "fedex",
    "google",
    "instagram",
    "irs",
    "microsoft",
    "netflix",
    "office365",
    "outlook",
    "paypal",
    "steam",
]
SCAM_BAITS = [
    "account",
    "alert",
    "bonus",
    "confirm",
    "invoice",
    "login",
    "payment",
    "recover",
    "refund",
    "secure",
    "signin",
    "unlock",
    "update",
    "verify",
    "wallet",
]
SCAM_TLDS = ["biz", "buzz", "cc", "click", "icu", "live", "shop", "support", "top", "work", "xyz", "zip"]
SCAM_PATHS = [
    "/account/review",
    "/bonus/redeem",
    "/confirm/payment",
    "/invoice/view",
    "/login/session",
    "/password/reset",
    "/secure/update",
    "/signin/verify",
    "/wallet/claim",
    "/webscr/login",
]
REGIONS = ["global", "intl", "secure", "support", "team", "verify"]


def build_safe_urls() -> list[str]:
    urls: set[str] = set()
    for domain in SAFE_DOMAINS:
        for path in SAFE_PATHS:
            for query in SAFE_QUERIES:
                urls.add(f"https://{domain}{path}{query}")
                if len(urls) >= 340:
                    return sorted(urls)
    return sorted(urls)


def build_scam_urls() -> list[str]:
    rng = random.Random(42)
    urls: set[str] = set()

    for brand in SCAM_BRANDS:
        for bait in SCAM_BAITS:
            for tld in SCAM_TLDS:
                path = rng.choice(SCAM_PATHS)
                region = rng.choice(REGIONS)
                urls.add(f"http://secure-{brand}-{bait}.{tld}{path}")
                urls.add(f"https://{brand}-{bait}-{region}.{tld}{path}?session={rng.randint(1000, 9999)}")
                urls.add(f"http://login.{brand}-{bait}.{tld}{path}?continue=verify")
                urls.add(f"https://{brand}-{bait}-center.com{path}?id={rng.randint(10000, 99999)}")
                urls.add(f"http://{brand}-{bait}-{rng.randint(100, 999)}.{tld}{path}")
                if len(urls) >= 340:
                    break
            if len(urls) >= 340:
                break
        if len(urls) >= 340:
            break

    for _ in range(40):
        octets = ".".join(str(rng.randint(11, 220)) for _ in range(4))
        path = rng.choice(SCAM_PATHS)
        urls.add(f"http://{octets}{path}?redirect=login")
        token = "".join(rng.choice("bcdfghjklmnpqrstvwxyz123456789") for _ in range(10))
        urls.add(f"https://{token}-{rng.choice(SCAM_BAITS)}.xyz{path}")
        urls.add(f"https://{token}.support{path}?account=verify")

    return sorted(urls)[:360]


def write_dataset() -> Path:
    rows = [(url, 0) for url in build_safe_urls()] + [(url, 1) for url in build_scam_urls()]
    validated_rows: list[tuple[str, int]] = []
    for url, label in rows:
        validated_rows.append((validate_url(url), label))

    with DATA_PATH.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["url", "label"])
        writer.writerows(validated_rows)

    print(f"Wrote {len(validated_rows)} samples to {DATA_PATH}")
    return DATA_PATH


if __name__ == "__main__":
    write_dataset()
