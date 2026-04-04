from __future__ import annotations

import json
import logging

import httpx

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env

import os

logger = logging.getLogger(__name__)

SERVICE = "cloudflare"
CF_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareRotator:
    """
    Two-token rotation pattern:

    CLOUDFLARE_MASTER_TOKEN  — account-level master token, never rotated.
                                 Needs: Account > API Tokens > Edit
                                 Used by this rotator to create/delete app tokens.

    CLOUDFLARE_API_TOKEN       — account-level app token, gets rotated each run.
                                 Needs: Zone Read (or whatever your app needs).
                                 NO token-management permissions (Cloudflare forbids it).
    """

    REQUIRED_ENV_VARS = [
        "CF_MASTER_TOKEN",
        "CF_ACCOUNT_ID",
    ]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._rotation_token = env["CF_MASTER_TOKEN"]       # master — stays forever
        self._old_token: str | None = os.environ.get("CF_API_TOKEN")  # None = bootstrap
        self._account_id = env["CF_ACCOUNT_ID"]
        self._old_token_id: str | None = None
        self._new_token: str | None = None
        self._new_token_id: str | None = None

        if self._old_token:
            self._fetch_current_token_id()
        else:
            print(f"[{SERVICE}] No existing app token found — will create first token (bootstrap mode).")

    def _mgmt_headers(self) -> dict[str, str]:
        """Headers using the master rotation token — for create/delete/list calls."""
        return {"Authorization": f"Bearer {self._rotation_token}"}

    def _app_headers(self, token: str | None = None) -> dict[str, str]:
        """Headers using the app token (or override) — for verify calls."""
        return {"Authorization": f"Bearer {token or self._old_token}"}

    def _fetch_current_token_id(self) -> None:
        """Get the app token's ID by calling GET /accounts/{id}/tokens/verify with the app token."""
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.get(
                    f"{CF_BASE}/accounts/{self._account_id}/tokens/verify",
                    headers=self._app_headers(),
                )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    self._old_token_id = data.get("result", {}).get("id")
                    if self._old_token_id:
                        logger.info("[%s] App token ID: %s", SERVICE, self._old_token_id)
                        return

            logger.error("[%s] App token verify failed. Status: %d, Body: %s", SERVICE, resp.status_code, resp.text[:500])
            raise RotationError(SERVICE, f"Failed to verify app token: HTTP {resp.status_code}")
        except RotationError:
            raise
        except Exception as exc:
            raise RotationError(SERVICE, f"Failed to verify app token: {exc}", cause=exc)

    def _get_old_token_policies(self) -> list:
        """Retrieve policies from the app token using the master rotation token.
        In bootstrap mode (no old token), falls back to CLOUDFLARE_TOKEN_POLICY_JSON."""
        # Bootstrap mode: no existing app token to read policies from
        if not self._old_token_id:
            policy_json = os.environ.get("CF_TOKEN_POLICY_JSON")
            if policy_json:
                logger.info("[%s] Bootstrap mode: using CF_TOKEN_POLICY_JSON.", SERVICE)
                return json.loads(policy_json)
            raise RotationError(
                SERVICE,
                "Bootstrap mode requires CF_TOKEN_POLICY_JSON to be set (no existing app token to clone policies from).",
            )

        with httpx.Client(timeout=20) as client:
            resp = client.get(
                f"{CF_BASE}/accounts/{self._account_id}/tokens/{self._old_token_id}",
                headers=self._mgmt_headers(),
            )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("result", {}).get("policies", [])

        # Fallback: load from env var
        policy_json = os.environ.get("CF_TOKEN_POLICY_JSON")
        if policy_json:
            logger.warning("[%s] Cannot list token policies (HTTP %d), using CF_TOKEN_POLICY_JSON.", SERVICE, resp.status_code)
            return json.loads(policy_json)

        raise RotationError(
            SERVICE,
            f"Cannot retrieve token policies (HTTP {resp.status_code}) and CF_TOKEN_POLICY_JSON is not set.",
        )

    def rotate(self, session: RotationSession) -> dict[str, str]:
        session.register_service(SERVICE, cleanup_fn=self._cleanup)
        print(f"[{SERVICE}] Reading existing token policies...")
        policies = self._get_old_token_policies()
        print(f"[{SERVICE}] Creating new app token with same policies...")
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
        # Strip policy 'id' fields — Cloudflare rejects reusing them in POST
        clean_policies = [
            {
                "effect": p["effect"],
                "resources": p["resources"],
                "permission_groups": [
                    {"id": pg["id"]} for pg in p.get("permission_groups", [])
                ],
            }
            for p in policies
        ]
        prefix = os.environ.get("KEY_PREFIX", "secrets-rot")
        body = {"name": f"{prefix}-cloudflare", "policies": clean_policies}
        with httpx.Client(timeout=20) as client:
            resp = client.post(f"{CF_BASE}/accounts/{self._account_id}/tokens", headers=self._mgmt_headers(), json=body)
        if resp.status_code not in (200, 201):
            raise RotationError(SERVICE, f"Failed to create new token: HTTP {resp.status_code} {resp.text[:300]}")
        result = resp.json().get("result", {})
        self._new_token = result.get("value")
        self._new_token_id = result.get("id")
        if not self._new_token or not self._new_token_id:
            raise RotationError(SERVICE, "New token creation response missing value/id.")

    def _validate_new_credential(self, session: RotationSession) -> None:
        result = validator.validate_cloudflare(self._new_token, self._account_id)  # type: ignore[arg-type]
        if not result:
            session.mark_failed()
            raise RotationError(SERVICE, f"Validation failed: {result.error}")

    def _doppler_payload(self) -> dict[str, str]:
        payload: dict[str, str] = {
            "CF_API_KEY": self._new_token,        # type: ignore[dict-item]
            "CF_API_TOKEN_ID": self._new_token_id, # type: ignore[dict-item]
            "CF_ACCOUNT_ID": self._account_id,
        }
        # Push static vars to Doppler if set in env
        for key in ("CF_KV_NAMESPACE_ID", "CF_EMAIL"):
            val = os.environ.get(key)
            if val:
                payload[key] = val
        return payload

    def _watch_rollout(self) -> None:
        pass

    def _finalize(self) -> None:
        """Revoke the old app token using the master rotation token. Skip in bootstrap mode."""
        if not self._old_token_id:
            print(f"[{SERVICE}] Bootstrap mode — no old token to revoke.")
            return
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.delete(
                    f"{CF_BASE}/accounts/{self._account_id}/tokens/{self._old_token_id}",
                    headers=self._mgmt_headers(),
                )
            if resp.status_code not in (200, 204):
                logger.warning("[%s] Could not revoke old token: HTTP %d", SERVICE, resp.status_code)
            else:
                print(f"[{SERVICE}] Old app token {self._old_token_id} revoked.")
        except Exception as exc:
            logger.error("[%s] Failed to revoke old token: %s", SERVICE, exc)

    def _cleanup(self) -> None:
        """Revoke the new app token on rollback using the master rotation token."""
        if not self._new_token_id:
            return
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.delete(
                    f"{CF_BASE}/accounts/{self._account_id}/tokens/{self._new_token_id}",
                    headers=self._mgmt_headers(),
                )
            if resp.status_code not in (200, 204):
                raise RotationError(SERVICE, f"Could not revoke new token: HTTP {resp.status_code}")
            logger.info("[%s] Rolled back: new token %s revoked.", SERVICE, self._new_token_id)
        except RotationError:
            raise
        except Exception as exc:
            logger.error("[%s] Cleanup failed: %s", SERVICE, exc)
            raise
