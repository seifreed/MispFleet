"""Server configuration models."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, Field, model_validator

from mispfleet.models.common import ServerRole

CredentialProviderName = Literal["env", "keyring", "prompt", "memory"]


class RetryConfig(BaseModel):
    """Retry and backoff policy for HTTP requests."""

    max_attempts: int = Field(default=4, ge=1)
    initial_delay: float = Field(default=0.5, ge=0.0)
    multiplier: float = Field(default=2.0, ge=1.0)
    max_delay: float = Field(default=30.0, ge=0.0)
    jitter: bool = True
    respect_retry_after: bool = True


class CredentialReference(BaseModel):
    """Reference to a secret; the secret value itself is never stored here."""

    provider: CredentialProviderName
    key: str


class ServerConfig(BaseModel):
    """Configuration of a single MISP server within the fleet."""

    name: str = Field(min_length=1)
    url: AnyHttpUrl
    credential: CredentialReference
    enabled: bool = True
    read_only: bool = False
    verify_tls: bool = True
    ca_bundle: Path | None = None
    client_certificate: Path | None = None
    client_key: Path | None = None
    tags: set[str] = Field(default_factory=set)
    groups: set[str] = Field(default_factory=set)
    role: ServerRole = ServerRole.GENERAL
    request_timeout: float = Field(default=30.0, gt=0.0)
    connect_timeout: float = Field(default=10.0, gt=0.0)
    concurrency: int = Field(default=5, ge=1)
    rate_limit: float | None = Field(default=None, gt=0.0)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    proxy: str | None = None
    allow_insecure_http: bool = False
    http2: bool = False
    max_keepalive_connections: int | None = Field(default=None, ge=1)
    keepalive_expiry: float | None = Field(default=None, gt=0.0)
    max_response_bytes: int = Field(default=50_000_000, ge=1)

    @model_validator(mode="after")
    def _require_https_unless_explicitly_insecure(self) -> ServerConfig:
        if self.url.scheme != "https" and not self.allow_insecure_http:
            raise ValueError(
                f"server {self.name!r} uses insecure scheme {self.url.scheme!r}; "
                "set allow_insecure_http: true to accept the risk explicitly"
            )
        return self
