import socket
from typing import Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "postgresql+asyncpg://cognithhorn:cognithhorn@pgbouncer:5432/cognithhorn"
    redis_sentinel_hosts: str = "redis-sentinel:26379"
    redis_master_name: str = "mymaster"
    redis_password: Optional[str] = None
    gemini_api_key: str = ""
    github_token: str = ""
    github_repo: str = ""
    upstream_url: str = "http://upstream:80"
    control_plane_url: str = "http://control-plane:8090"
    worker_port: int = 9000
    worker_id: str = ""
    sensitivity_threshold: float = 0.7
    onnx_model_path: str = "/app/models/model.onnx"
    max_body_size_kb: int = 64
    certs_dir: str = "/certs"
    enable_self_healing: bool = False
    log_level: str = "INFO"
    # Security: API key for the control plane management API.
    # Set to a random secret (e.g. `openssl rand -hex 32`).
    # If empty, auth is skipped with a WARNING — dev-only.
    control_plane_api_key: str = ""
    # Security: 32-byte base64 key for encrypting TLS private keys at rest.
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # If empty, key_pem is stored plaintext with a WARNING.
    key_encryption_secret: str = ""

    @model_validator(mode="after")
    def _set_worker_id(self) -> "Settings":
        if not self.worker_id:
            self.worker_id = socket.gethostname()
        return self


settings = Settings()
