from __future__ import annotations

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
        "FIREBASE_PROJECT_ID",
        "FIREBASE_SA_KEY_JSON",
        "FIREBASE_SA_EMAIL",
    ]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._project_id = env["FIREBASE_PROJECT_ID"]
        self._admin_key_json = env["FIREBASE_SA_KEY_JSON"]
        self._sa_email = env["FIREBASE_SA_EMAIL"]
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
            import base64
            raw = base64.b64decode(resp["privateKeyData"]).decode("utf-8")
            key_info = json.loads(raw)
            self._new_key_id = key_info["private_key_id"]
            self._new_key_json = raw
        except Exception as exc:
            raise RotationError(SERVICE, f"Failed to create new SA key: {exc}", cause=exc)

    def _validate_new_credential(self, session: RotationSession) -> None:
        result = validator.validate_firebase(self._project_id, self._new_key_json)  # type: ignore[arg-type]
        if not result:
            session.mark_failed()
            raise RotationError(SERVICE, f"Validation failed: {result.error}")

    def _doppler_payload(self) -> dict[str, str]:
        return {"FIREBASE_SA_KEY_JSON": self._new_key_json}  # type: ignore[dict-item]

    def _watch_rollout(self) -> None:
        pass

    def _finalize(self) -> None:
        """Delete the old SA key."""
        try:
            old_info = json.loads(self._admin_key_json)
            old_key_id = old_info.get("private_key_id")
            if not old_key_id:
                return
            svc = self._iam_service()
            resource = (
                f"projects/{self._project_id}/serviceAccounts/{self._sa_email}/keys/{old_key_id}"
            )
            svc.projects().serviceAccounts().keys().delete(name=resource).execute()
            print(f"[{SERVICE}] Old SA key {old_key_id} deleted.")
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
