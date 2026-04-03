from __future__ import annotations

import json
import logging

import httpx

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env

logger = logging.getLogger(__name__)

SERVICE = "cloudflare"
CF_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareRotator:
    REQUIRED_ENV_VARS = [
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_API_TOKEN_ID",
        "CLOUDFLARE_ACCOUNT_ID",
    ]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._old_token = env["CLOUDFLARE_API_TOKEN"]
        self._old_token_id = env["CLOUDFLARE_API_TOKEN_ID"]
        self._account_id = env["CLOUDFLARE_ACCOUNT_ID"]
        self._new_token: str | None = None
        self._new_token_id: str | None = None

    def _headers(self, token: str | None = None) -> dict[str, str]:
        return {"Authorization": f"Bearer {token or self._old_token}"}

    def _get_old_token_policies(self) -> list:
        """Retrieve policies from the existing token to clone them."""
        with httpx.Client(timeout=20) as client:
            resp = client.get(
                f"{CF_BASE}/user/tokens/{self._old_token_id}",
                headers=self._headers(),
            )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("result", {}).get("policies", [])

        # Fallback: load from env var if old token lacks list permission
        import os
        policy_json = os.environ.get("CLOUDFLARE_TOKEN_POLICY_JSON")
        if policy_json:
            logger.warning("[%s] Cannot list token policies (HTTP %d), using CLOUDFLARE_TOKEN_POLICY_JSON.", SERVICE, resp.status_code)
            return json.loads(policy_json)

        raise RotationError(
            SERVICE,
            f"Cannot retrieve token policies (HTTP {resp.status_code}) and CLOUDFLARE_TOKEN_POLICY_JSON is not set.",
        )

    def rotate(self, session: RotationSession) -> dict[str, str]:
        session.register_service(SERVICE, cleanup_fn=self._cleanup)
        print(f"[{SERVICE}] Reading existing token policies...")
        policies = self._get_old_token_policies()
        print(f"[{SERVICE}] Creating new token with same policies...")
        self._generate_new_credential(policies)
        print(f"[{SERVICE}] Validating new token...")
        self._validate_new_credential(session)
        payload = self._doppler_payload()
        doppler.push_secrets(payload)
        print(f"[{SERVICE}] Pushed new token to Doppler.")
        self._watch_rollout()
        self._finalize()
        print(f"[{SERVICE}] Rotation complete.")
        return payload

    def _generate_new_credential(self, policies: list) -> None:
        body = {
            "name": "rotated-token",
            "policies": policies,
        }
        with httpx.Client(timeout=20) as client:
            resp = client.post(f"{CF_BASE}/user/tokens", headers=self._headers(), json=body)
        if resp.status_code not in (200, 201):
            raise RotationError(SERVICE, f"Failed to create new token: HTTP {resp.status_code} {resp.text[:300]}")
        result = resp.json().get("result", {})
        self._new_token = result.get("value")
        self._new_token_id = result.get("id")
        if not self._new_token or not self._new_token_id:
            raise RotationError(SERVICE, "New token creation response missing value/id.")

    def _validate_new_credential(self, session: RotationSession) -> None:
        result = validator.validate_cloudflare(self._new_token)  # type: ignore[arg-type]
        if not result:
            session.mark_failed()
            raise RotationError(SERVICE, f"Validation failed: {result.error}")

    def _doppler_payload(self) -> dict[str, str]:
        return {
            "CLOUDFLARE_API_TOKEN": self._new_token,  # type: ignore[dict-item]
            "CLOUDFLARE_API_TOKEN_ID": self._new_token_id,  # type: ignore[dict-item]
        }

    def _watch_rollout(self) -> None:
        pass

    def _finalize(self) -> None:
        """Revoke the old token."""
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.delete(
                    f"{CF_BASE}/user/tokens/{self._old_token_id}",
                    headers=self._headers(self._new_token),
                )
            if resp.status_code not in (200, 204):
                logger.warning("[%s] Could not revoke old token: HTTP %d", SERVICE, resp.status_code)
            else:
                print(f"[{SERVICE}] Old token {self._old_token_id} revoked.")
        except Exception as exc:
            logger.error("[%s] Failed to revoke old token: %s", SERVICE, exc)

    def _cleanup(self) -> None:
        """Revoke the new token on rollback."""
        if not self._new_token_id:
            return
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.delete(
                    f"{CF_BASE}/user/tokens/{self._new_token_id}",
                    headers=self._headers(),
                )
            if resp.status_code not in (200, 204):
                raise RotationError(SERVICE, f"Could not revoke new token: HTTP {resp.status_code}")
            logger.info("[%s] Rolled back: new token %s revoked.", SERVICE, self._new_token_id)
        except RotationError:
            raise
        except Exception as exc:
            logger.error("[%s] Cleanup failed: %s", SERVICE, exc)
            raise
