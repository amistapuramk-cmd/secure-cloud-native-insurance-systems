from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    SECRET_KEY: str = "dev-only-secret-change-me-please-0123456789"
    DATA_ENCRYPTION_KEY: str = ""  # Fernet key; derived from SECRET_KEY if empty (dev only)
    DATABASE_URL: str = "sqlite:///./insurance.db"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ADMIN_EMAIL: str = "admin@example.com"
    ADMIN_PASSWORD: str = "ChangeMe!12345"
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_SECONDS: int = 300


settings = Settings()
