from __future__ import annotations

import logging
import secrets

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env, retry

logger = logging.getLogger(__name__)

SERVICE = "postgres"


class PostgresRotator:
    REQUIRED_ENV_VARS = [
        "POSTGRES_HOST",
        "POSTGRES_PORT",
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
    ]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._host = env["POSTGRES_HOST"]
        self._port = int(env["POSTGRES_PORT"])
        self._db = env["POSTGRES_DB"]
        self._user = env["POSTGRES_USER"]
        self._old_password = env["POSTGRES_PASSWORD"]
        self._new_password: str | None = None

    def rotate(self, session: RotationSession) -> dict[str, str]:
        session.register_service(SERVICE, cleanup_fn=self._cleanup)
        print(f"[{SERVICE}] Generating new password...")
        self._generate_new_credential()
        print(f"[{SERVICE}] Validating new password...")
        self._validate_new_credential(session)
        payload = self._doppler_payload()
        doppler.push_secrets(payload)
        print(f"[{SERVICE}] Pushed new password to Doppler.")
        self._watch_rollout()
        self._finalize()
        print(f"[{SERVICE}] Rotation complete.")
        return payload

    def _generate_new_credential(self) -> None:
        new_password = secrets.token_urlsafe(32)

        @retry(retryable_exceptions=(Exception,), max_retries=5, base_delay=1.0, cap=60.0)
        def _alter() -> None:
            import psycopg2
            conn = psycopg2.connect(
                host=self._host,
                port=self._port,
                dbname=self._db,
                user=self._user,
                password=self._old_password,
                connect_timeout=10,
            )
            try:
                conn.autocommit = True
                cur = conn.cursor()
                cur.execute("ALTER USER %s PASSWORD %s", (self._user, new_password))
                cur.close()
            finally:
                conn.close()

        try:
            _alter()
        except Exception as exc:
            raise RotationError(SERVICE, f"Failed to set new password: {exc}", cause=exc)

        self._new_password = new_password

    def _validate_new_credential(self, session: RotationSession) -> None:
        result = validator.validate_postgres(
            self._host, self._port, self._db, self._user, self._new_password  # type: ignore[arg-type]
        )
        if not result:
            session.mark_failed()
            raise RotationError(SERVICE, f"Validation failed: {result.error}")

    def _doppler_payload(self) -> dict[str, str]:
        return {"POSTGRES_PASSWORD": self._new_password}  # type: ignore[dict-item]

    def _watch_rollout(self) -> None:
        pass  # Postgres has no async rollout concept

    def _finalize(self) -> None:
        pass  # Old password is already invalidated by ALTER USER

    def _cleanup(self) -> None:
        """Revert to old password on rollback."""
        if self._new_password is None:
            return
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=self._host,
                port=self._port,
                dbname=self._db,
                user=self._user,
                password=self._new_password,
                connect_timeout=10,
            )
            try:
                conn.autocommit = True
                cur = conn.cursor()
                cur.execute("ALTER USER %s PASSWORD %s", (self._user, self._old_password))
                cur.close()
            finally:
                conn.close()
            logger.info("[%s] Reverted to old password.", SERVICE)
        except Exception as exc:
            logger.error("[%s] Cleanup failed: %s", SERVICE, exc)
            raise
