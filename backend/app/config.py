from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment / .env file.

    Never hard-code secrets. All values can be overridden via environment
    variables or the .env file at the repository root.
    """

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # ---- Application ----
    APP_NAME: str = "Veylora - AI Autonomous Vulnerability Assessment Platform"
    APP_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    DEBUG: bool = True

    # ---- Database (defaults to local SQLite so the project runs out of the box) ----
    DATABASE_URL: str = "sqlite:///./app.db"

    # ---- Task queue (Redis optional; falls back to in-process executor) ----
    REDIS_URL: str | None = None
    CELERY_BROKER_URL: str | None = None
    CELERY_RESULT_BACKEND: str | None = None
    TASK_EXECUTOR: str = "local"  # "local" | "celery"

    # ---- Graph database (Neo4j optional; falls back to SQLite-backed engine) ----
    NEO4J_URI: str | None = None
    NEO4J_USERNAME: str | None = None
    NEO4J_PASSWORD: str | None = None

    # ---- Security ----
    JWT_SECRET: str = "CHANGE_ME_development_secret_not_for_production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    OTP_TTL_MINUTES: int = 10
    OTP_LENGTH: int = 6
    # When True the generated OTP is returned in the API response / logged to
    # console. Intended for development and lab environments WITHOUT real SMTP.
    # Production deployments set EMAIL_ENABLED=true and DEV_OTP_RETURN=false.
    DEV_OTP_RETURN: bool = True

    # ---- Email (used for OTP verification) ----
    EMAIL_ENABLED: bool = False
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""

    # ---- AI provider ----
    AI_PROVIDER: str = "rule"  # "rule" | "ollama" | "openai" | "local"
    AI_API_KEY: str = ""
    AI_MODEL: str = "llama3.2"
    AI_BASE_URL: str = "http://localhost:11434"

    # ---- Validation ----
    VALIDATION_DEFAULT_LEVEL: int = 1
    VALIDATION_REQUIRE_APPROVAL: bool = True

    # ---- Evidence ----
    EVIDENCE_DIR: str = "evidence_store"

    # ---- Rate limiting ----
    RATE_LIMIT_MAX: int = 120
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # ---- Seed admin ----
    SEED_ADMIN_EMAIL: str = "admin@secops.io"
    SEED_ADMIN_PASSWORD: str = "Admin@12345"

    # ---- Lab / active testing ----
    ACTIVE_TESTING_ENABLED: bool = True
    MAX_TARGETS_PER_ASSESSMENT: int = 500
    MAX_SCAN_CONCURRENCY: int = 4
    # Adapters used for a scan when the caller does not pick one explicitly.
    # Defaults to the deterministic simulated-lab adapter so the platform is
    # instantly demonstrable in an isolated lab; set to "nmap,nuclei" to prefer
    # real tools (they still require the tools to be installed and in scope).
    DEFAULT_SCAN_ADAPTERS: str = "simulated-lab"

    @property
    def evidence_path(self) -> Path:
        return Path(self.EVIDENCE_DIR)

    @property
    def is_postgres(self) -> bool:
        return self.DATABASE_URL.startswith("postgres")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()