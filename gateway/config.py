"""
Gateway configuration using pydantic-settings.
"""

from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8080
    upstream_url: str = "http://demo-app:3000"
    waf_mode: Literal["monitor", "block"] = "block"
    ml_threshold: float = 0.75
    max_body_inspect_bytes: int = 16384
    fail_mode: Literal["open", "closed"] = "closed"
    db_url: str = "sqlite:///./data/waf.db"
    log_queue_max_size: int = 10000


settings = GatewaySettings()
