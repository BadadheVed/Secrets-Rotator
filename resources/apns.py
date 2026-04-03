from __future__ import annotations

import logging

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env

logger = logging.getLogger(__name__)

SERVICE = "apns"


class APNSRotator:
    """
    Semi-automated APNS key rotation.

    Apple provides no public API to create or revoke .p8 keys programmatically.
    This rotator prompts the user to:
      1. Create a new key in the Apple Developer portal and paste the p8 content + key ID.
      2. After validation succeeds, confirm manual revocation of the old key in the portal.
    """

    REQUIRED_ENV_VARS = [
        "APNS_TEAM_ID",
        "APNS_KEY_ID",
        "APNS_AUTH_KEY",
        "APNS_BUNDLE_ID",
    ]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._team_id = env["APNS_TEAM_ID"]
        self._old_key_id = env["APNS_KEY_ID"]
        self._old_auth_key = env["APNS_AUTH_KEY"]
        self._bundle_id = env["APNS_BUNDLE_ID"]
        self._new_key_id: str | None = None
        self._new_auth_key: str | None = None

    def rotate(self, session: RotationSession) -> dict[str, str]:
        # No cleanup hook: old .p8 remains valid until manually revoked
        session.register_service(SERVICE)
        self._generate_new_credential()
        print(f"[{SERVICE}] Validating new APNs key...")
        self._validate_new_credential(session)
        payload = self._doppler_payload()
        doppler.push_secrets(payload)
        print(f"[{SERVICE}] Pushed new key to Doppler.")
        self._watch_rollout()
        self._finalize()
        print(f"[{SERVICE}] Rotation complete.")
        return payload

    def _generate_new_credential(self) -> None:
        import getpass
        print(f"\n[{SERVICE}] Can't be done programmatically.")
        print("  1. Go to https://developer.apple.com/account/resources/authkeys/list")
        print("  2. Create a new APNs Auth Key and download the .p8 file.")
        print()
        new_key_id = getpass.getpass("  Enter new Key ID (e.g. ABCDEFGHIJ) [hidden]: ").strip()
        print("  Paste the full .p8 file content below (input will be hidden, paste and press Enter):")
        new_auth_key = getpass.getpass("  .p8 content: ").strip()

        if not new_key_id or not new_auth_key:
            raise RotationError(SERVICE, "New key ID or .p8 content was empty — rotation aborted.")

        self._new_key_id = new_key_id
        self._new_auth_key = new_auth_key

    def _validate_new_credential(self, session: RotationSession) -> None:
        result = validator.validate_apns(
            self._team_id,
            self._new_key_id,  # type: ignore[arg-type]
            self._new_auth_key,  # type: ignore[arg-type]
            self._bundle_id,
        )
        if not result:
            session.mark_failed()
            raise RotationError(SERVICE, f"Validation failed: {result.error}")

    def _doppler_payload(self) -> dict[str, str]:
        return {
            "APNS_KEY_ID": self._new_key_id,  # type: ignore[dict-item]
            "APNS_AUTH_KEY": self._new_auth_key,  # type: ignore[dict-item]
        }

    def _watch_rollout(self) -> None:
        pass  # Key validated via sandbox connection already

    def _finalize(self) -> None:
        print(f"\n[{SERVICE}] MANUAL STEP REQUIRED — Revoke old key")
        print(f"  Old Key ID: {self._old_key_id}")
        print("  1. Go to https://developer.apple.com/account/resources/authkeys/list")
        print("  2. Revoke the old key listed above.")
        input("  Press Enter when done (or skip — old key will remain active until revoked): ")
