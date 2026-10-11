import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass


@dataclass(frozen=True)
class Settings:
    db_path: str = os.getenv("QRSHIELD_DB", "qrshield.db")
    enable_network: bool = os.getenv("ENABLE_NETWORK_CHECKS", "true").lower() == "true"
    gsb_api_key: str = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    vt_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    urlhaus_key: str = os.getenv("URLHAUS_AUTH_KEY", "")
    allowed_origins: tuple = tuple(
        o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()
    )
    rate_limit_per_min: int = int(os.getenv("RATE_LIMIT_PER_MIN", "30"))
    max_upload_bytes: int = 5 * 1024 * 1024
    cache_ttl_seconds: int = 6 * 3600


settings = Settings()
