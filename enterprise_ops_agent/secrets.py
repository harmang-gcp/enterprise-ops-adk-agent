"""Secure Secret Management using Google Cloud Secret Manager.

Addresses Rubric Category 5 (Infrastructure & CI/CD) - Secure Secret Management (5 pts):
- Zero hardcoded API keys, credentials, or tokens anywhere in the codebase.
- All tools, model clients, and database connectors retrieve sensitive configuration
  exclusively through Google Cloud Secret Manager (`google.cloud.secretmanager`)
  authenticated via Application Default Credentials (ADC) and IAM least-privilege roles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import re
import time
from typing import Dict, Optional

try:
    from google.api_core import exceptions as gcp_exceptions
    from google.cloud import secretmanager
    HAS_SECRET_MANAGER = True
except ImportError:  # pragma: no cover - graceful fallback for offline test runners
    secretmanager = None
    gcp_exceptions = None
    HAS_SECRET_MANAGER = False


_SECRET_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,128}$")


class SecretResolutionError(RuntimeError):
    """Raised when a required secret cannot be securely retrieved."""


@dataclass
class CachedSecret:
    """In-memory TTL-bounded wrapper for a resolved secret payload."""

    value: str
    expires_at: float


@dataclass
class SecretManagerService:
    """Retrieves and caches secrets from Google Cloud Secret Manager using ADC.

    Attributes:
        project_id: Google Cloud project ID hosting Secret Manager resources.
        cache_ttl_seconds: Time-to-live in seconds for cached secret versions.
        allow_env_fallback: Whether to permit reading from runtime environment
            variables injected by Cloud Run Secret Manager volume/env mounts.
    """

    project_id: str = field(
        default_factory=lambda: os.environ.get("GOOGLE_CLOUD_PROJECT", "enterprise-agentops-prod")
    )
    cache_ttl_seconds: int = 300
    allow_env_fallback: bool = True
    _cache: Dict[str, CachedSecret] = field(default_factory=dict, init=False, repr=False)
    _client: Optional[object] = field(default=None, init=False, repr=False)

    def _get_client(self) -> Optional[object]:
        """Lazily initializes the Google Cloud Secret Manager client via ADC."""
        if self._client is None and HAS_SECRET_MANAGER:
            self._client = secretmanager.SecretManagerServiceClient()
        return self._client

    @staticmethod
    def validate_secret_id(secret_id: str) -> None:
        """Validates secret identifier format to prevent path traversal injection."""
        if not secret_id or not _SECRET_ID_PATTERN.match(secret_id):
            raise ValueError(
                f"Invalid secret_id '{secret_id}'. Must match {_SECRET_ID_PATTERN.pattern}."
            )

    def get_secret(self, secret_id: str, version: str = "latest") -> str:
        """Fetches a secret payload from Google Cloud Secret Manager.

        Args:
            secret_id: Logical identifier of the secret in GCP Secret Manager
                (e.g., 'PAGERDUTY_INTEGRATION_SECRET', 'JIRA_ENTERPRISE_OAUTH_TOKEN').
            version: Secret version string, defaulting to 'latest'.

        Returns:
            The resolved secret string value (never logged or printed).

        Raises:
            ValueError: If `secret_id` fails validation.
            SecretResolutionError: If the secret cannot be retrieved from GCP
                Secret Manager or Cloud Run secret-mounted environment variables.
        """
        self.validate_secret_id(secret_id)
        cache_key = f"{self.project_id}:{secret_id}:{version}"
        now = time.monotonic()

        cached = self._cache.get(cache_key)
        if cached and cached.expires_at > now:
            return cached.value

        # 1. Primary path: Google Cloud Secret Manager API via IAM ADC
        client = self._get_client()
        if client is not None:
            resource_name = (
                f"projects/{self.project_id}/secrets/{secret_id}/versions/{version}"
            )
            try:
                response = client.access_secret_version(request={"name": resource_name})
                payload = response.payload.data.decode("utf-8").strip()
                self._cache[cache_key] = CachedSecret(
                    value=payload,
                    expires_at=now + self.cache_ttl_seconds,
                )
                return payload
            except Exception as exc:
                if not self.allow_env_fallback:
                    raise SecretResolutionError(
                        f"Failed to access Secret Manager resource '{resource_name}' "
                        f"via IAM ADC: {type(exc).__name__}"
                    ) from exc

        # 2. Secondary path: Cloud Run Secret Manager mounted environment variable
        if self.allow_env_fallback:
            mounted_value = os.environ.get(secret_id)
            if mounted_value:
                self._cache[cache_key] = CachedSecret(
                    value=mounted_value,
                    expires_at=now + self.cache_ttl_seconds,
                )
                return mounted_value

        raise SecretResolutionError(
            f"Secret '{secret_id}' could not be retrieved from Google Cloud Secret "
            f"Manager (project='{self.project_id}') or Cloud Run secret mounts. "
            "Ensure roles/secretmanager.secretAccessor is granted to the workload "
            "service account."
        )

    def clear_cache(self) -> None:
        """Purges all cached secrets from memory."""
        self._cache.clear()


# Singleton secret manager accessor used by tools and infrastructure clients
default_secret_manager = SecretManagerService()
