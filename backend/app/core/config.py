"""
sinX Threat Hunter - Configuration Management
Centralized configuration using Pydantic Settings
"""

from pydantic_settings import BaseSettings
from pydantic import PostgresDsn, RedisDsn
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Application
    APP_NAME: str = "sinX Threat Hunter"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"

    # Security
    SECRET_KEY: str = os.urandom(32).hex()
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",  # Web dashboard
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",  # Web dashboard
    ]

    # Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "sinx"
    POSTGRES_PASSWORD: str = "sinx_hunter_secure_2024"
    POSTGRES_DB: str = "threat_hunter"

    @property
    def DATABASE_URL(self) -> str:
        # SQLite option (uncomment for quick testing without PostgreSQL)
        return "sqlite+aiosqlite:///./threat_hunter.db"

        # PostgreSQL option (default, recommended for production)
        # return f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    @property
    def REDIS_URL(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # SIEM
    SYSLOG_UDP_PORT: int = 514
    SYSLOG_TCP_PORT: int = 601
    LOG_RETENTION_DAYS: int = 30
    LOG_ARCHIVE_DAYS: int = 365

    # Threat Intelligence
    FEED_UPDATE_INTERVAL: int = 60  # minutes
    ALIENVAULT_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None

    # Detection
    DETECTION_INTERVAL: int = 10  # seconds
    MAX_ALERTS_PER_HOUR: int = 1000

    # Performance
    MAX_WORKERS: int = 4
    BATCH_SIZE: int = 1000
    QUEUE_MAX_SIZE: int = 10000

    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings()
