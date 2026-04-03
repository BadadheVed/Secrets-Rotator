from __future__ import annotations

import logging

import httpx

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env

logger = logging.getLogger(__name__)

SERVICE = "azure_ad"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class AzureADRotator:
    REQUIRED_ENV_VARS = [
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_APP_OBJECT_ID",
    ]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._tenant_id = env["AZURE_TENANT_ID"]
        self._client_id = env["AZURE_CLIENT_ID"]
        self._old_secret = env["AZURE_CLIENT_SECRET"]
        self._app_object_id = env["AZURE_APP_OBJECT_ID"]
        self._new_secret: str | None = None
        self._new_secret_key_id: str | None = None

    def _get_access_token(self, client_secret: str | None = None) -> str:
        import msal
        app = msal.ConfidentialClientApplication(
            self._client_id,
            authority=f"https://login.microsoftonline.com/{self._tenant_id}",
            client_credential=client_secret or self._old_secret,
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            raise RotationError(SERVICE, f"Token acquisition failed: {result.get('error_description', result)}")
        return result["access_token"]

    def rotate(self, session: RotationSession) -> dict[str, str]:
        session.register_service(SERVICE, cleanup_fn=self._cleanup)
        print(f"[{SERVICE}] Adding new client secret via Graph API...")
        self._generate_new_credential()
        print(f"[{SERVICE}] Validating new secret...")
        self._validate_new_credential(session)
        payload = self._doppler_payload()
        doppler.push_secrets(payload)
        print(f"[{SERVICE}] Pushed new secret to Doppler.")
        self._watch_rollout()
        self._finalize()
        print(f"[{SERVICE}] Rotation complete.")
        return payload

    def _generate_new_credential(self) -> None:
        try:
            token = self._get_access_token()
            url = f"{GRAPH_BASE}/applications/{self._app_object_id}/addPassword"
            body = {"passwordCredential": {"displayName": "secrets-rot-rotated"}}
            with httpx.Client(timeout=30) as client:
                resp = client.post(url, headers={"Authorization": f"Bearer {token}"}, json=body)
            if resp.status_code not in (200, 201):
                raise RotationError(SERVICE, f"addPassword failed: HTTP {resp.status_code} {resp.text[:300]}")
            result = resp.json()
            self._new_secret = result["secretText"]
            self._new_secret_key_id = result["keyId"]
        except RotationError:
            raise
        except Exception as exc:
            raise RotationError(SERVICE, f"Failed to add password: {exc}", cause=exc)

    def _validate_new_credential(self, session: RotationSession) -> None:
        result = validator.validate_azure_ad(self._tenant_id, self._client_id, self._new_secret)  # type: ignore[arg-type]
        if not result:
            session.mark_failed()
            raise RotationError(SERVICE, f"Validation failed: {result.error}")

    def _doppler_payload(self) -> dict[str, str]:
        return {"AZURE_CLIENT_SECRET": self._new_secret}  # type: ignore[dict-item]

    def _watch_rollout(self) -> None:
        pass

    def _finalize(self) -> None:
        """Remove the old client secret password credential."""
        try:
            token = self._get_access_token(self._new_secret)
            # Find the old keyId by listing credentials
            url = f"{GRAPH_BASE}/applications/{self._app_object_id}"
            with httpx.Client(timeout=30) as client:
                resp = client.get(url, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code != 200:
                logger.warning("[%s] Could not list credentials to finalize: HTTP %d", SERVICE, resp.status_code)
                return
            creds = resp.json().get("passwordCredentials", [])
            old_key_ids = [
                c["keyId"] for c in creds
                if c["keyId"] != self._new_secret_key_id
                and c.get("displayName", "") != "secrets-rot-rotated"
            ]
            for key_id in old_key_ids:
                remove_url = f"{GRAPH_BASE}/applications/{self._app_object_id}/removePassword"
                with httpx.Client(timeout=30) as client:
                    client.post(
                        remove_url,
                        headers={"Authorization": f"Bearer {token}"},
                        json={"keyId": key_id},
                    )
                print(f"[{SERVICE}] Removed old secret keyId={key_id}.")
        except Exception as exc:
            logger.error("[%s] Finalize failed: %s", SERVICE, exc)

    def _cleanup(self) -> None:
        """Remove the new secret on rollback."""
        if not self._new_secret_key_id:
            return
        try:
            token = self._get_access_token()  # old secret still in env
            url = f"{GRAPH_BASE}/applications/{self._app_object_id}/removePassword"
            with httpx.Client(timeout=30) as client:
                resp = client.post(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    json={"keyId": self._new_secret_key_id},
                )
            if resp.status_code not in (200, 204):
                raise RotationError(SERVICE, f"removePassword failed: HTTP {resp.status_code}")
            logger.info("[%s] Rolled back: removed new secret keyId=%s.", SERVICE, self._new_secret_key_id)
        except RotationError:
            raise
        except Exception as exc:
            logger.error("[%s] Cleanup failed: %s", SERVICE, exc)
            raise
