from __future__ import annotations

import logging
import re
import secrets
from urllib.parse import quote_plus, urlparse, urlunparse

import httpx

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env, retry

logger = logging.getLogger(__name__)

SERVICE = "mongodb"
ATLAS_API_BASE = "https://cloud.mongodb.com/api/atlas/v2"


class MongoDBRotator:
    REQUIRED_ENV_VARS = [
        "MONGODB_ATLAS_PUBLIC_KEY",
        "MONGODB_ATLAS_PRIVATE_KEY",
        "MONGODB_ATLAS_GROUP_ID",
        "MONGODB_ATLAS_USERNAME",
        "MONGODB_URI",
    ]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._public_key = env["MONGODB_ATLAS_PUBLIC_KEY"]
        self._private_key = env["MONGODB_ATLAS_PRIVATE_KEY"]
        self._group_id = env["MONGODB_ATLAS_GROUP_ID"]
        self._username = env["MONGODB_ATLAS_USERNAME"]
        self._old_uri = env["MONGODB_URI"]
        self._new_password: str | None = None
        self._new_uri: str | None = None

    def rotate(self, session: RotationSession) -> dict[str, str]:
        session.register_service(SERVICE)  # no cleanup hook — Atlas password can't be un-rotated atomically
        print(f"[{SERVICE}] Generating new password...")
        self._generate_new_credential()
        print(f"[{SERVICE}] Validating new URI...")
        self._validate_new_credential(session)
        payload = self._doppler_payload()
        doppler.push_secrets(payload)
        print(f"[{SERVICE}] Pushed new URI to Doppler.")
        self._watch_rollout()
        self._finalize()
        print(f"[{SERVICE}] Rotation complete.")
        return payload

    @retry(retryable_exceptions=(httpx.HTTPError, httpx.ConnectError), max_retries=5, base_delay=1.0, cap=60.0)
    def _generate_new_credential(self) -> None:
        new_password = secrets.token_urlsafe(32)
        url = f"{ATLAS_API_BASE}/groups/{self._group_id}/databaseUsers/admin/{self._username}"
        with httpx.Client(timeout=30) as client:
            resp = client.patch(
                url,
                auth=(self._public_key, self._private_key),
                headers={"Accept": "application/vnd.atlas.2023-01-01+json", "Content-Type": "application/json"},
                json={"password": new_password},
            )
        if resp.status_code >= 400:
            raise RotationError(SERVICE, f"Atlas API error {resp.status_code}: {resp.text[:300]}")
        self._new_password = new_password
        self._new_uri = _replace_password_in_uri(self._old_uri, new_password)

    def _validate_new_credential(self, session: RotationSession) -> None:
        result = validator.validate_mongodb(self._new_uri)  # type: ignore[arg-type]
        if not result:
            session.mark_failed()
            raise RotationError(SERVICE, f"Validation failed: {result.error}")

    def _doppler_payload(self) -> dict[str, str]:
        return {"MONGODB_URI": self._new_uri}  # type: ignore[dict-item]

    def _watch_rollout(self) -> None:
        pass

    def _finalize(self) -> None:
        pass  # Atlas updates password in place; old password is gone


def _replace_password_in_uri(uri: str, new_password: str) -> str:
    """Replace the password component in a MongoDB URI with new_password."""
    parsed = urlparse(uri)
    # netloc is user:password@host:port — rebuild with new password
    user = parsed.username or ""
    host = parsed.hostname or ""
    port = parsed.port
    hostpart = f"{host}:{port}" if port else host
    new_netloc = f"{quote_plus(user)}:{quote_plus(new_password)}@{hostpart}"
    new_parsed = parsed._replace(netloc=new_netloc)
    return urlunparse(new_parsed)
