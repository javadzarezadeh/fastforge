"""
Configuration module for FastForge application.
Centralizes environment variables and application settings.
"""

import os
from typing import List, Optional


class Config:
    """Configuration class to manage application settings"""

    # App settings
    APP_NAME: str = os.getenv("APP_NAME", "FastForge")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    ENV: str = os.getenv("ENV", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Security settings
    SECRET_KEY: Optional[str] = os.getenv("SECRET_KEY")
    ADMIN_SECRET_KEY: Optional[str] = os.getenv("ADMIN_SECRET_KEY")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    )
    OTP_EXPIRE_MINUTES: int = int(os.getenv("OTP_EXPIRE_MINUTES", "5"))

    # Database settings
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"postgresql+psycopg://{os.getenv('POSTGRES_USER', 'postgres')}:{os.getenv('POSTGRES_PASSWORD', 'password')}@{os.getenv('DB_HOST', 'db')}:{os.getenv('DB_PORT', '5432')}/{os.getenv('POSTGRES_DB', 'fastforge')}",
    )

    # Redis settings
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    # CORS settings
    ALLOWED_ORIGINS: List[str] = os.getenv("ALLOWED_ORIGINS", "").split(",")
    ALLOWED_HOSTS: List[str] = os.getenv("ALLOWED_HOSTS", "*").split(",")

    # SMS service settings
    SMS_SERVICE_TYPE: str = os.getenv("SMS_SERVICE_TYPE", "mock")  # mock, twilio, etc.

    @classmethod
    def validate(cls):
        """Validate required configuration values"""
        required_vars = ["SECRET_KEY"]
        if cls.ENV == "production":
            required_vars.append("ADMIN_SECRET_KEY")

        for var in required_vars:
            value = getattr(cls, var)
            if not value or value in [
                "your-secure-random-key-here",
                "your-admin-secret-key-here",
            ]:
                raise ValueError(
                    f"Environment variable {var} must be set to a secure value"
                )

    @classmethod
    def get_database_url(cls) -> str:
        """Get the appropriate database URL based on environment"""
        # Use the DATABASE_URL from environment variables, which can contain
        # the proper docker connection string with environment variables
        return cls.DATABASE_URL


# Validate configuration on import, but skip in test environment
if os.getenv("TESTING") != "True":
    Config.validate()
