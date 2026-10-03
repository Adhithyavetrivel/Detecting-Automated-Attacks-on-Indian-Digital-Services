"""
NetSentinel configuration.

All runtime settings are loaded from environment variables (via a .env file
in development). This avoids hardcoding secrets or environment-specific
values (like which network interface to sniff) directly in source code —
the same value gets pulled from a different .env on a different machine.

CCNA/Networking note:
    MONITOR_INTERFACE below refers to a NIC name (e.g. "eth0", "ens33").
    On Linux you can list your interfaces with `ip addr` — this is the
    modern replacement for the older `ifconfig` command.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Strongly-typed application settings.

    Using Pydantic here means misconfigured values (e.g. a non-integer
    port) fail fast at startup with a clear error, instead of causing a
    confusing crash later deep inside the monitoring loop.
    """

    # --- General ---
    app_name: str = "NetSentinel"
    app_env: str = "development"  # development | production
    debug: bool = True

    # --- Database ---
    # SQLite is the default so Phase 1 runs with zero external setup.
    # Swap this for a postgresql+psycopg://... URL later without touching
    # any application code, since SQLAlchemy abstracts the dialect.
    database_url: str = "sqlite:///./netsentinel.db"

    # --- Security / Auth (used from Phase 10 onward, defined now so the
    # .env.example is complete and nothing has to be retrofitted later) ---
    secret_key: str = "CHANGE_ME_INSECURE_DEFAULT_DO_NOT_USE_IN_PRODUCTION"
    access_token_expire_minutes: int = 60
    algorithm: str = "HS256"

    # --- Networking / Monitoring (used from Phase 2 onward) ---
    # A private RFC1918 range is the correct default for a home/lab network.
    monitor_subnet: str = "192.168.1.0/24"
    monitor_interface: str = "eth0"
    ping_timeout_seconds: float = 1.0
    ping_interval_seconds: int = 30

    # --- SNMP (used from Phase 8 onward) ---
    snmp_community: str = "public"
    snmp_port: int = 161
    snmp_timeout_seconds: float = 2.0

    # --- Detection thresholds (used from Phase 6 onward) ---
    port_scan_port_threshold: int = 15
    port_scan_window_seconds: int = 10
    excessive_connections_threshold: int = 100

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """
    Return a cached Settings instance.

    lru_cache means the .env file is parsed once per process, not on every
    request — settings are treated as immutable configuration, not
    per-request state.
    """
    return Settings()
