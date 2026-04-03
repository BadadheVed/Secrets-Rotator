from __future__ import annotations

import logging

import httpx

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

class _AnthropicRotator:
    SERVICE = "anthropic"
    REQUIRED_ENV_VARS = ["ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY_ID"]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._old_key = env["ANTHROPIC_API_KEY"]
        self._old_key_id = env["ANTHROPIC_API_KEY_ID"]
        self._new_key: str | None = None
        self._new_key_id: str | None = None

    def generate(self) -> None:
        with httpx.Client(timeout=20) as client:
            resp = client.post(
                "https://api.anthropic.com/v1/api_keys",
                headers={
                    "x-api-key": self._old_key,
                    "anthropic-version": "2023-06-01",
                },
                json={"name": "secrets-rot-rotated"},
            )
        if resp.status_code not in (200, 201):
            raise RotationError(self.SERVICE, f"Create key failed: HTTP {resp.status_code} {resp.text[:200]}")
        data = resp.json()
        self._new_key = data["secret_key"]
        self._new_key_id = data["id"]

    def validate(self) -> validator.ValidationResult:
        return validator.validate_simple_key("anthropic", self._new_key)  # type: ignore[arg-type]

    def doppler_payload(self) -> dict[str, str]:
        return {
            "ANTHROPIC_API_KEY": self._new_key,  # type: ignore[dict-item]
            "ANTHROPIC_API_KEY_ID": self._new_key_id,  # type: ignore[dict-item]
        }

    def finalize(self) -> None:
        """Delete old key."""
        if not self._old_key_id:
            return
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.delete(
                    f"https://api.anthropic.com/v1/api_keys/{self._old_key_id}",
                    headers={
                        "x-api-key": self._new_key,
                        "anthropic-version": "2023-06-01",
                    },
                )
            if resp.status_code not in (200, 204):
                logger.warning("[%s] Could not delete old key: HTTP %d", self.SERVICE, resp.status_code)
            else:
                print(f"[{self.SERVICE}] Old key {self._old_key_id} deleted.")
        except Exception as exc:
            logger.error("[%s] Finalize failed: %s", self.SERVICE, exc)


# ---------------------------------------------------------------------------
# OpenAI  (manual — no rotation API)
# ---------------------------------------------------------------------------

class _OpenAIRotator:
    SERVICE = "openai"
    REQUIRED_ENV_VARS = ["OPENAI_API_KEY"]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._old_key = env["OPENAI_API_KEY"]
        self._new_key: str | None = None

    def generate(self) -> None:
        import getpass
        print(f"\n[{self.SERVICE}] Can't be done programmatically.")
        print("  1. Go to https://platform.openai.com/api-keys")
        print("  2. Create a new secret key, then paste it below (input will be hidden).")
        self._new_key = getpass.getpass("  New OpenAI API key: ").strip()
        if not self._new_key:
            raise RotationError(self.SERVICE, "No key entered — rotation aborted.")

    def validate(self) -> validator.ValidationResult:
        return validator.validate_simple_key("openai", self._new_key)  # type: ignore[arg-type]

    def doppler_payload(self) -> dict[str, str]:
        return {"OPENAI_API_KEY": self._new_key}  # type: ignore[dict-item]

    def finalize(self) -> None:
        print(f"\n[{self.SERVICE}] Remember to revoke the old key at https://platform.openai.com/api-keys")


# ---------------------------------------------------------------------------
# Gemini  (manual)
# ---------------------------------------------------------------------------

class _GeminiRotator:
    SERVICE = "gemini"
    REQUIRED_ENV_VARS = ["GEMINI_API_KEY"]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._old_key = env["GEMINI_API_KEY"]
        self._new_key: str | None = None

    def generate(self) -> None:
        import getpass
        print(f"\n[{self.SERVICE}] Can't be done programmatically.")
        print("  1. Go to https://aistudio.google.com/app/apikey")
        print("  2. Create a new key, then paste it below (input will be hidden).")
        self._new_key = getpass.getpass("  New Gemini API key: ").strip()
        if not self._new_key:
            raise RotationError(self.SERVICE, "No key entered — rotation aborted.")

    def validate(self) -> validator.ValidationResult:
        return validator.validate_simple_key("gemini", self._new_key)  # type: ignore[arg-type]

    def doppler_payload(self) -> dict[str, str]:
        return {"GEMINI_API_KEY": self._new_key}  # type: ignore[dict-item]

    def finalize(self) -> None:
        print(f"\n[{self.SERVICE}] Remember to delete the old key at https://aistudio.google.com/app/apikey")


# ---------------------------------------------------------------------------
# Deepgram  (programmatic)
# ---------------------------------------------------------------------------

class _DeepgramRotator:
    SERVICE = "deepgram"
    REQUIRED_ENV_VARS = ["DEEPGRAM_API_KEY", "DEEPGRAM_PROJECT_ID", "DEEPGRAM_API_KEY_ID"]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._old_key = env["DEEPGRAM_API_KEY"]
        self._old_key_id = env["DEEPGRAM_API_KEY_ID"]
        self._project_id = env["DEEPGRAM_PROJECT_ID"]
        self._new_key: str | None = None
        self._new_key_id: str | None = None

    def generate(self) -> None:
        with httpx.Client(timeout=20) as client:
            resp = client.post(
                f"https://api.deepgram.com/v1/projects/{self._project_id}/keys",
                headers={"Authorization": f"Token {self._old_key}"},
                json={"comment": "secrets-rot-rotated", "scopes": ["member"]},
            )
        if resp.status_code not in (200, 201):
            raise RotationError(self.SERVICE, f"Create key failed: HTTP {resp.status_code} {resp.text[:200]}")
        data = resp.json()
        self._new_key = data.get("key")
        self._new_key_id = data.get("api_key_id")
        if not self._new_key or not self._new_key_id:
            raise RotationError(self.SERVICE, "Missing key/api_key_id in create response.")

    def validate(self) -> validator.ValidationResult:
        return validator.validate_simple_key("deepgram", self._new_key)  # type: ignore[arg-type]

    def doppler_payload(self) -> dict[str, str]:
        return {
            "DEEPGRAM_API_KEY": self._new_key,  # type: ignore[dict-item]
            "DEEPGRAM_API_KEY_ID": self._new_key_id,  # type: ignore[dict-item]
        }

    def finalize(self) -> None:
        if not self._old_key_id:
            return
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.delete(
                    f"https://api.deepgram.com/v1/projects/{self._project_id}/keys/{self._old_key_id}",
                    headers={"Authorization": f"Token {self._new_key}"},
                )
            if resp.status_code not in (200, 204):
                logger.warning("[%s] Could not delete old key: HTTP %d", self.SERVICE, resp.status_code)
            else:
                print(f"[{self.SERVICE}] Old key {self._old_key_id} deleted.")
        except Exception as exc:
            logger.error("[%s] Finalize failed: %s", self.SERVICE, exc)


# ---------------------------------------------------------------------------
# Public-facing rotator used in main.py
# ---------------------------------------------------------------------------

_ROTATORS = {
    "anthropic": _AnthropicRotator,
    "openai": _OpenAIRotator,
    "gemini": _GeminiRotator,
    "deepgram": _DeepgramRotator,
}


class SimpleRotator:
    """Wraps one simple-key rotator by name."""

    def __init__(self, service: str) -> None:
        if service not in _ROTATORS:
            raise ValueError(f"Unknown simple service: {service!r}. Choose from {list(_ROTATORS)}")
        self._rotator = _ROTATORS[service]()
        self._service = service

    def rotate(self, session: RotationSession) -> dict[str, str]:
        session.register_service(self._service)  # no cleanup hook: old key still valid
        print(f"[{self._service}] Generating new key...")
        self._rotator.generate()
        print(f"[{self._service}] Validating new key...")
        result = self._rotator.validate()
        if not result:
            raise RotationError(self._service, f"Validation failed: {result.error}")
        payload = self._rotator.doppler_payload()
        doppler.push_secrets(payload)
        print(f"[{self._service}] Pushed new key to Doppler.")
        self._rotator.finalize()
        print(f"[{self._service}] Rotation complete.")
        return payload


def rotate_all_simple(session: RotationSession) -> list[dict[str, str]]:
    """Rotate all four simple services sequentially."""
    results = []
    for svc in _ROTATORS:
        rotator = SimpleRotator(svc)
        results.append(rotator.rotate(session))
    return results
