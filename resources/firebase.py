from __future__ import annotations

import base64
import json
import logging

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env

logger = logging.getLogger(__name__)

SERVICE = "firebase"


class FirebaseRotator:
    REQUIRED_ENV_VARS = [
        "FIRE_CREDS_ROTATER_JSON",  # firebase-rotation-admin key (creates/deletes keys)
        "FIRE_CREDS_JSON",          # ved-710 app key (the one being rotated)
    ]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)

        # Rotation admin key — used to authenticate to GCP IAM API
        rotater_b64 = env["FIRE_CREDS_ROTATER_JSON"]
        self._admin_key_json = base64.b64decode(rotater_b64).decode("utf-8")

        # App key (ved-710) — extract project_id and client_email to know which SA to rotate
        app_b64 = env["FIRE_CREDS_JSON"]
        app_key_json = base64.b64decode(app_b64).decode("utf-8")
        app_creds = json.loads(app_key_json)
        self._project_id = app_creds["project_id"]
        self._sa_email = app_creds["client_email"]

        # Store old key id for deletion during finalize
        self._old_key_id: str | None = app_creds.get("private_key_id")

        self._new_key_id: str | None = None
        self._new_key_json: str | None = None

    def rotate(self, session: RotationSession) -> dict[str, str]:
        session.register_service(SERVICE, cleanup_fn=self._cleanup)
        print(f"[{SERVICE}] Creating new SA key...")
        self._generate_new_credential()
        print(f"[{SERVICE}] Validating new SA key against Firebase...")
        self._validate_new_credential(session)
        payload = self._doppler_payload()
        doppler.push_secrets(payload)
        print(f"[{SERVICE}] Pushed new SA key to Doppler.")
        self._watch_rollout()
        self._finalize()
        print(f"[{SERVICE}] Rotation complete.")
        return payload

    def _iam_service(self):
        import google.oauth2.service_account as sa_module
        from googleapiclient.discovery import build

        creds = sa_module.Credentials.from_service_account_info(
            json.loads(self._admin_key_json),
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        return build("iam", "v1", credentials=creds, cache_discovery=False)

    def _generate_new_credential(self) -> None:
        try:
            svc = self._iam_service()
            resource = f"projects/{self._project_id}/serviceAccounts/{self._sa_email}"
            resp = svc.projects().serviceAccounts().keys().create(
                name=resource, body={"privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE"}
            ).execute()
            raw = base64.b64decode(resp["privateKeyData"]).decode("utf-8")
            key_info = json.loads(raw)
            self._new_key_id = key_info["private_key_id"]
            self._new_key_json = raw
            logger.info("[%s] New key created: %s", SERVICE, self._new_key_id)
            logger.debug("[%s] New key JSON first 100 chars: %s", SERVICE, raw[:100])
        except Exception as exc:
            raise RotationError(SERVICE, f"Failed to create new SA key: {exc}", cause=exc)

    def _validate_new_credential(self, session: RotationSession) -> None:
        import time
        # Retry validation — GCP sometimes takes a moment to activate new keys
        max_retries = 3
        for attempt in range(max_retries):
            result = validator.validate_firebase(self._project_id, self._new_key_json)  # type: ignore[arg-type]
            if result:
                return
            # If permission error, wait and retry
            if "INSUFFICIENT_PERMISSION" in str(result.error) and attempt < max_retries - 1:
                print(f"[{SERVICE}] Waiting for key activation... (attempt {attempt + 1}/{max_retries})")
                time.sleep(2)
            else:
                break

        session.mark_failed()
        raise RotationError(SERVICE, f"Validation failed: {result.error}")

    def _doppler_payload(self) -> dict[str, str]:
        # Encode the new key as base64 before pushing to Doppler
        encoded = base64.b64encode(self._new_key_json.encode()).decode()  # type: ignore[union-attr]
        return {"FIRE_CREDS_JSON": encoded}

    def _watch_rollout(self) -> None:
        pass

    def _finalize(self) -> None:
        """Delete the old SA key."""
        try:
            if not self._old_key_id:
                return
            svc = self._iam_service()
            resource = (
                f"projects/{self._project_id}/serviceAccounts/{self._sa_email}/keys/{self._old_key_id}"
            )
            svc.projects().serviceAccounts().keys().delete(name=resource).execute()
            print(f"[{SERVICE}] Old SA key {self._old_key_id} deleted.")
        except Exception as exc:
            logger.error("[%s] Failed to delete old SA key: %s", SERVICE, exc)

    def _cleanup(self) -> None:
        """Delete the new SA key on rollback."""
        if not self._new_key_id:
            return
        try:
            svc = self._iam_service()
            resource = (
                f"projects/{self._project_id}/serviceAccounts/{self._sa_email}/keys/{self._new_key_id}"
            )
            svc.projects().serviceAccounts().keys().delete(name=resource).execute()
            logger.info("[%s] Rolled back: deleted new SA key %s.", SERVICE, self._new_key_id)
        except Exception as exc:
            logger.error("[%s] Cleanup failed: %s", SERVICE, exc)
            raise
