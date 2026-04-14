from dataclasses import dataclass
import os


def _get_int(name: str, default: int) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        return int(raw_value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    app_env: str
    store_backend: str
    sqlite_path: str
    correlation_window_seconds: int
    brute_force_threshold: int
    exfil_bytes_threshold: int
    resource_hijack_threshold: int
    offhours_start: int
    offhours_end: int
    alert_min_risk: int
    llm_mode: str
    llm_http_url: str
    llm_api_key: str
    llm_model: str


def get_settings() -> Settings:
    return Settings(
        app_env=os.getenv("APP_ENV", "dev"),
        store_backend=os.getenv("STORE_BACKEND", "sqlite").lower(),
        sqlite_path=os.getenv("SQLITE_PATH", "/tmp/cloudguard.db"),
        correlation_window_seconds=_get_int("CORRELATION_WINDOW_SECONDS", 300),
        brute_force_threshold=_get_int("BRUTE_FORCE_THRESHOLD", 8),
        exfil_bytes_threshold=_get_int("EXFIL_BYTES_THRESHOLD", 50 * 1024 * 1024),
        resource_hijack_threshold=_get_int("RESOURCE_HIJACK_THRESHOLD", 10),
        offhours_start=_get_int("OFFHOURS_START", 20),
        offhours_end=_get_int("OFFHOURS_END", 6),
        alert_min_risk=_get_int("ALERT_MIN_RISK", 45),
        llm_mode=os.getenv("LLM_MODE", "template").lower(),
        llm_http_url=os.getenv("LLM_HTTP_URL", ""),
        llm_api_key=os.getenv("LLM_API_KEY", ""),
        llm_model=os.getenv("LLM_MODEL", "agent-default"),
    )
