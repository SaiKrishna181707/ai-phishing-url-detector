"""Central configuration for the phishing URL detector."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"
FRONTEND_DIR = BASE_DIR / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
TEMPLATES_DIR = FRONTEND_DIR / "templates"
MODEL_DIR = BASE_DIR / "model"
DATA_DIR = BASE_DIR / "data"
MODEL_PATH = MODEL_DIR / "phishing_detector.joblib"
BLACKLIST_PATH = MODEL_DIR / "blacklist.txt"
LOG_PATH = BASE_DIR / "backend" / "requests.log"


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


_load_dotenv(ENV_PATH)

HOST = os.getenv("APP_HOST", "127.0.0.1")
PORT = int(os.getenv("APP_PORT", "8000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "5.5"))
SOCKET_TIMEOUT_SECONDS = float(os.getenv("SOCKET_TIMEOUT_SECONDS", "4.0"))
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
VT_BASE_URL = os.getenv("VT_BASE_URL", "https://www.virustotal.com/api/v3").rstrip("/")
VT_POLL_ATTEMPTS = max(int(os.getenv("VT_POLL_ATTEMPTS", "2")), 0)
VT_POLL_INTERVAL_SECONDS = float(os.getenv("VT_POLL_INTERVAL_SECONDS", "1.2"))
USER_AGENT = os.getenv("APP_USER_AGENT", "AI-Phishing-URL-Detector/3.0")
