from __future__ import annotations

import logging

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env

logger = logging.getLogger(__name__)

SERVICE = "azure_openai"


class AzureOpenAIRotator:
    REQUIRED_ENV_VARS = [
        "AZURE_OPENAI_RESOURCE_NAME",
        "AZURE_OPENAI_KEY",
        "AZURE_SUBSCRIPTION_ID",
        "AZURE_RESOURCE_GROUP",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
    ]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._resource_name = env["AZURE_OPENAI_RESOURCE_NAME"]
        self._subscription_id = env["AZURE_SUBSCRIPTION_ID"]
        self._resource_group = env["AZURE_RESOURCE_GROUP"]
        self._tenant_id = env["AZURE_TENANT_ID"]
        self._client_id = env["AZURE_CLIENT_ID"]
        self._client_secret = env["AZURE_CLIENT_SECRET"]
        self._endpoint = f"https://{self._resource_name}.openai.azure.com"
        self._new_key: str | None = None

    def _mgmt_client(self):
        from azure.identity import ClientSecretCredential
        from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient

        cred = ClientSecretCredential(
            tenant_id=self._tenant_id,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )
        return CognitiveServicesManagementClient(cred, self._subscription_id)

    def rotate(self, session: RotationSession) -> dict[str, str]:
        # No cleanup hook: Azure OpenAI has two keys; both remain valid during rotation
        session.register_service(SERVICE)
        print(f"[{SERVICE}] Regenerating Key2...")
        self._regenerate_key("Key2")
        key2 = self._get_key("Key2")
        print(f"[{SERVICE}] Validating Key2...")
        self._validate_key(key2, session, step="Key2")
        print(f"[{SERVICE}] Regenerating Key1...")
        self._regenerate_key("Key1")
        key1 = self._get_key("Key1")
        print(f"[{SERVICE}] Validating Key1...")
        self._validate_key(key1, session, step="Key1")
        self._new_key = key1
        payload = self._doppler_payload()
        doppler.push_secrets(payload)
        print(f"[{SERVICE}] Pushed Key1 to Doppler.")
        self._watch_rollout()
        self._finalize()
        print(f"[{SERVICE}] Rotation complete.")
        return payload

    def _regenerate_key(self, key_name: str) -> None:
        try:
            client = self._mgmt_client()
            client.accounts.regenerate_key(
                self._resource_group,
                self._resource_name,
                {"keyName": key_name},
            )
        except Exception as exc:
            raise RotationError(SERVICE, f"Failed to regenerate {key_name}: {exc}", cause=exc)

    def _get_key(self, key_name: str) -> str:
        try:
            client = self._mgmt_client()
            keys = client.accounts.list_keys(self._resource_group, self._resource_name)
            return keys.key1 if key_name == "Key1" else keys.key2
        except Exception as exc:
            raise RotationError(SERVICE, f"Failed to retrieve {key_name}: {exc}", cause=exc)

    def _validate_key(self, key: str, session: RotationSession, step: str = "") -> None:
        result = validator.validate_azure_openai(self._endpoint, key)
        if not result:
            session.mark_failed()
            raise RotationError(SERVICE, f"Validation failed for {step}: {result.error}")

    def _doppler_payload(self) -> dict[str, str]:
        return {"AZURE_OPENAI_KEY": self._new_key}  # type: ignore[dict-item]

    def _watch_rollout(self) -> None:
        pass  # Key is effective immediately

    def _finalize(self) -> None:
        pass  # Both keys have been rotated; nothing more to clean up
