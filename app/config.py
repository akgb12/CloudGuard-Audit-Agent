from dataclasses import dataclass
import os


def _get_int(name: str, default: int) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        return int(raw_value)
    except ValueError:
        return default


def _get_bool(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
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
    llm_provider: str
    ollama_base_url: str
    ollama_model: str
    openai_api_key: str
    openai_model: str
    langchain_verbose: bool
    agent_memory_sqlite_path: str


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
        llm_provider=os.getenv("LLM_PROVIDER", "ollama").lower(),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
        openai_api_key=os.getenv("OPENAI_API_KEY", ""),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        langchain_verbose=_get_bool("LANGCHAIN_VERBOSE", False),
        agent_memory_sqlite_path=os.getenv("AGENT_MEMORY_SQLITE_PATH", "/tmp/agent_memory.db"),
    )
