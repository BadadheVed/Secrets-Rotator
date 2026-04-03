from __future__ import annotations

import base64
import logging

import httpx

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env

logger = logging.getLogger(__name__)

SERVICE = "elasticsearch"


class ElasticsearchRotator:
    """
    Rotates an Elasticsearch API key using the Security API.

    Flow:
      1. Create a new API key (POST /_security/api_key) authenticated with the current key.
      2. Validate the new key via GET /_cluster/health.
      3. Push ELASTICSEARCH_API_KEY + ELASTICSEARCH_API_KEY_ID to Doppler.
      4. Invalidate the old key (DELETE /_security/api_key).

    Cleanup hook: invalidates the freshly-created key on rollback.

    Env vars:
      ELASTICSEARCH_HOST        e.g. https://my-cluster.es.io:9243
      ELASTICSEARCH_API_KEY     base64-encoded "id:api_key" value (the 'encoded' field from create response)
      ELASTICSEARCH_API_KEY_ID  the ID portion of the current key (used for invalidation)
      ELASTICSEARCH_KEY_NAME    optional display name for created keys (default: secrets-rot-rotated)
    """

    REQUIRED_ENV_VARS = [
        "ELASTICSEARCH_HOST",
        "ELASTICSEARCH_API_KEY",
        "ELASTICSEARCH_API_KEY_ID",
    ]

    def __init__(self) -> None:
        import os

        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._host = env["ELASTICSEARCH_HOST"].rstrip("/")
        self._old_encoded_key = env["ELASTICSEARCH_API_KEY"]
        self._old_key_id = env["ELASTICSEARCH_API_KEY_ID"]
        self._key_name = os.environ.get("ELASTICSEARCH_KEY_NAME", "secrets-rot-rotated")

        self._new_encoded_key: str | None = None
        self._new_key_id: str | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auth_header(self, encoded_key: str | None = None) -> dict[str, str]:
        return {"Authorization": f"ApiKey {encoded_key or self._old_encoded_key}"}

    def _url(self, path: str) -> str:
        return f"{self._host}/{path.lstrip('/')}"

    # ------------------------------------------------------------------
    # Public rotate() entry point
    # ------------------------------------------------------------------

    def rotate(self, session: RotationSession) -> dict[str, str]:
        session.register_service(SERVICE, cleanup_fn=self._cleanup)
        print(f"[{SERVICE}] Creating new API key...")
        self._generate_new_credential()
        print(f"[{SERVICE}] Validating new API key...")
        self._validate_new_credential(session)
        payload = self._doppler_payload()
        doppler.push_secrets(payload)
        print(f"[{SERVICE}] Pushed new API key to Doppler.")
        self._watch_rollout()
        self._finalize()
        print(f"[{SERVICE}] Rotation complete.")
        return payload

    # ------------------------------------------------------------------
    # Rotator protocol methods (called by rotate_all in main.py)
    # ------------------------------------------------------------------

    def _generate_new_credential(self) -> None:
        """Create a new Elasticsearch API key via POST /_security/api_key."""
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.post(
                    self._url("/_security/api_key"),
                    headers=self._auth_header(),
                    json={"name": self._key_name},
                )
            if resp.status_code == 401:
                raise RotationError(SERVICE, "Current API key is invalid (401). Check ELASTICSEARCH_API_KEY.")
            if resp.status_code >= 400:
                raise RotationError(
                    SERVICE,
                    f"Failed to create API key: HTTP {resp.status_code} — {resp.text[:300]}",
                )
            data = resp.json()
            new_id: str = data["id"]
            new_raw_key: str = data["api_key"]

            # Elasticsearch's 'encoded' field = base64(id:api_key) — build it ourselves
            # so we don't depend on the server returning it (older versions may not).
            encoded = base64.b64encode(f"{new_id}:{new_raw_key}".encode()).decode()

            self._new_key_id = new_id
            self._new_encoded_key = data.get("encoded", encoded)

        except RotationError:
            raise
        except Exception as exc:
            raise RotationError(SERVICE, f"Unexpected error creating API key: {exc}", cause=exc)

    def _validate_new_credential(self, session: RotationSession) -> None:
        result = validator.validate_elasticsearch(self._host, self._new_encoded_key)  # type: ignore[arg-type]
        if not result:
            session.mark_failed()
            raise RotationError(SERVICE, f"Validation failed: {result.error}")

    def _doppler_payload(self) -> dict[str, str]:
        return {
            "ELASTICSEARCH_API_KEY": self._new_encoded_key,   # type: ignore[dict-item]
            "ELASTICSEARCH_API_KEY_ID": self._new_key_id,     # type: ignore[dict-item]
        }

    def _watch_rollout(self) -> None:
        pass  # API keys are effective immediately

    def _finalize(self) -> None:
        """Invalidate the old API key."""
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.delete(
                    self._url("/_security/api_key"),
                    headers=self._auth_header(self._new_encoded_key),
                    json={"id": self._old_key_id},
                )
            if resp.status_code not in (200, 204):
                logger.warning(
                    "[%s] Could not invalidate old key %s: HTTP %d — %s",
                    SERVICE, self._old_key_id, resp.status_code, resp.text[:200],
                )
            else:
                print(f"[{SERVICE}] Old API key {self._old_key_id} invalidated.")
        except Exception as exc:
            logger.error("[%s] Finalize failed (old key not invalidated): %s", SERVICE, exc)

    def _cleanup(self) -> None:
        """Invalidate the new API key on rollback."""
        if not self._new_key_id:
            return
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.delete(
                    self._url("/_security/api_key"),
                    headers=self._auth_header(),  # old key still valid (Doppler was rolled back)
                    json={"id": self._new_key_id},
                )
            if resp.status_code not in (200, 204):
                raise RotationError(
                    SERVICE,
                    f"Could not invalidate new key {self._new_key_id}: HTTP {resp.status_code}",
                )
            logger.info("[%s] Rolled back: new API key %s invalidated.", SERVICE, self._new_key_id)
        except RotationError:
            raise
        except Exception as exc:
            logger.error("[%s] Cleanup failed: %s", SERVICE, exc)
            raise
