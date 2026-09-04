from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://railsentinel:railsentinel@localhost:5432/railsentinel"
    secret_key: str = "replace-with-a-long-random-dev-secret"
    access_token_expire_minutes: int = 60
    jwt_algorithm: str = "HS256"
    admin_username: str = "admin"
    admin_password: str = "replace-with-a-dev-admin-password"
    threat_green_max: float = 30
    threat_yellow_max: float = 60
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [part.strip() for part in self.cors_origins.split(",") if part.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
