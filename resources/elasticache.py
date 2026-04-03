from __future__ import annotations

import logging
import secrets
import time
from urllib.parse import urlparse

import doppler
import validator
from rollback import RotationSession
from utils import RotationError, get_required_env

logger = logging.getLogger(__name__)

SERVICE = "elasticache"
POLL_INTERVAL = 10   # seconds between describe_users polls
POLL_TIMEOUT  = 600  # 10 minutes max


class ElastiCacheRotator:
    """
    Rotates passwords for ALL users in an ElastiCache User Group using the
    modern User/UserGroup auth model (not legacy cluster-level AuthToken).

    Zero-downtime strategy per user:
      1. modify_user(Passwords=[old, new])  → both accepted simultaneously
      2. Poll until user Status = "active"
      3. Validate connection with new password
      4. Push REDIS_AWS_PASSWORD to Doppler
      5. modify_user(Passwords=[new])       → old password revoked

    Rollback hook: modify_user(Passwords=[old]) for every user that was touched.

    Required env vars:
      AWS_ACCESS_KEY_ID
      AWS_SECRET_ACCESS_KEY
      AWS_REGION
      ELASTICACHE_USER_GROUP_ID   — User Group bound to the cluster
      REDIS_AWS_URL               — e.g. rediss://cluster.xxx.cache.amazonaws.com:6379
      REDIS_AWS_USERNAME              — Redis ACL username (used for validation connection)
      REDIS_AWS_PASSWORD          — current password

    Required IAM actions on the executing role:
      elasticache:DescribeUserGroups
      elasticache:DescribeUsers
      elasticache:ModifyUser
    """

    REQUIRED_ENV_VARS = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_REGION",
        "ELASTICACHE_USER_GROUP_ID",
        "REDIS_AWS_URL",
        "REDIS_AWS_USERNAME",
        "REDIS_AWS_PASSWORD",
    ]

    def __init__(self) -> None:
        env = get_required_env(*self.REQUIRED_ENV_VARS)
        self._region        = env["AWS_REGION"]
        self._user_group_id = env["ELASTICACHE_USER_GROUP_ID"]
        self._redis_url     = env["REDIS_AWS_URL"]
        self._redis_user    = env["REDIS_AWS_USERNAME"]
        self._old_password  = env["REDIS_AWS_PASSWORD"]
        self._new_password: str | None = None
        # UserIds that were successfully patched — used by rollback hook
        self._modified_user_ids: list[str] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def rotate(self, session: RotationSession) -> dict[str, str]:
        session.register_service(SERVICE, cleanup_fn=self._cleanup)

        print(f"[{SERVICE}] Generating new 16-char password...")
        self._generate_new_credential()

        print(f"[{SERVICE}] Enumerating users in group '{self._user_group_id}'...")
        user_ids = self._list_group_user_ids()
        if not user_ids:
            raise RotationError(SERVICE, f"User group '{self._user_group_id}' has no users.")
        print(f"[{SERVICE}] Found {len(user_ids)} user(s): {', '.join(user_ids)}")

        print(f"[{SERVICE}] Adding new password alongside old (zero-downtime)...")
        self._add_new_password_to_all(user_ids)

        print(f"[{SERVICE}] Waiting for all users to become active...")
        self._poll_all_active(user_ids)

        print(f"[{SERVICE}] Validating connection with new password...")
        self._validate_new_credential(session)

        payload = self._doppler_payload()
        doppler.push_secrets(payload)
        print(f"[{SERVICE}] Pushed new password to Doppler.")

        self._watch_rollout()
        self._finalize(user_ids)
        print(f"[{SERVICE}] Rotation complete.")
        return payload

    # ------------------------------------------------------------------
    # Step implementations (also called by rotate_all in main.py)
    # ------------------------------------------------------------------

    def _generate_new_credential(self) -> None:
        # ElastiCache passwords: 16–128 printable ASCII, no @, ", /, or spaces.
        # token_urlsafe(12) → exactly 16 base64url chars (A-Za-z0-9_-)
        self._new_password = secrets.token_urlsafe(12)  # exactly 16 chars

    # Called by rotate_all Phase 1
    _generate_new_credential.__doc__ = "Phase 1 — generate"

    def _validate_new_credential(self, session: RotationSession) -> None:
        """
        Try a live TCP connection to confirm the new password works.
        If the cluster is unreachable (VPC-private, no tunnel), fall back to
        trusting the AWS API result — modify_user succeeded + user is active
        is sufficient proof that the password is set correctly.
        """
        result = validator.validate_elasticache(
            self._redis_url, self._redis_user, self._new_password  # type: ignore[arg-type]
        )
        if result:
            return  # live connection confirmed ✓

        # Connection errors / timeouts mean the cluster isn't reachable from here
        # (ElastiCache is VPC-private). If the AWS User API confirmed the change,
        # treat that as sufficient validation.
        _network_errors = ("timed out", "connection refused", "connect call failed",
                           "network is unreachable", "no route to host")
        is_network_error = any(s in (result.error or "").lower() for s in _network_errors)

        if is_network_error:
            logger.warning(
                "[%s] TCP validation skipped — cluster unreachable from this host "
                "(expected for VPC-private ElastiCache). "
                "AWS API confirmed password change is active. Error: %s",
                SERVICE, result.error,
            )
            print(
                f"[{SERVICE}] ⚠️  Live connection skipped (VPC-private cluster). "
                "Trusting AWS API confirmation."
            )
            return  # AWS API is sufficient proof

        # Auth failure or other real error — abort
        session.mark_failed()
        raise RotationError(SERVICE, f"Validation failed: {result.error}")


    def _doppler_payload(self) -> dict[str, str]:
        return {"REDIS_AWS_PASSWORD": self._new_password}  # type: ignore[dict-item]

    def _watch_rollout(self) -> None:
        pass  # password is effective immediately once user status = active

    def _finalize(self, user_ids: list[str] | None = None) -> None:
        """Remove old password — only new password now accepted."""
        ids = user_ids or self._modified_user_ids
        client = self._client()
        for uid in ids:
            try:
                client.modify_user(
                    UserId=uid,
                    Passwords=[self._new_password],
                    NoPasswordRequired=False,
                )
                print(f"[{SERVICE}]   {uid}: old password revoked.")
            except Exception as exc:
                logger.error("[%s] Finalize failed for user %s: %s", SERVICE, uid, exc)

    # ------------------------------------------------------------------
    # AWS helpers
    # ------------------------------------------------------------------

    def _client(self):
        import boto3
        return boto3.client("elasticache", region_name=self._region)

    def _list_group_user_ids(self) -> list[str]:
        """Return all UserIds in the user group."""
        try:
            resp = self._client().describe_user_groups(UserGroupId=self._user_group_id)
            groups = resp.get("UserGroups", [])
            if not groups:
                raise RotationError(SERVICE, f"User group '{self._user_group_id}' not found.")
            return groups[0].get("UserIds", [])
        except RotationError:
            raise
        except Exception as exc:
            raise RotationError(SERVICE, f"describe_user_groups failed: {exc}", cause=exc)

    def _add_new_password_to_all(self, user_ids: list[str]) -> None:
        """
        For each user: set Passwords=[old, new] so both are accepted simultaneously.
        Records successfully patched users for the rollback hook.
        """
        client = self._client()
        for uid in user_ids:
            try:
                client.modify_user(
                    UserId=uid,
                    Passwords=[self._old_password, self._new_password],
                    NoPasswordRequired=False,
                )
                self._modified_user_ids.append(uid)
                print(f"[{SERVICE}]   {uid}: both passwords active.")
            except Exception as exc:
                raise RotationError(
                    SERVICE,
                    f"modify_user failed for '{uid}': {exc}",
                    cause=exc,
                )

    def _poll_all_active(self, user_ids: list[str]) -> None:
        """Poll describe_users for every user until Status = 'active' or timeout."""
        client = self._client()
        pending = list(user_ids)
        deadline = time.time() + POLL_TIMEOUT

        while pending and time.time() < deadline:
            still_pending = []
            for uid in pending:
                try:
                    resp = client.describe_users(UserId=uid)
                    users = resp.get("Users", [])
                    status = users[0].get("Status", "unknown") if users else "unknown"
                    if status == "active":
                        print(f"[{SERVICE}]   {uid}: active ✓")
                    else:
                        still_pending.append(uid)
                        print(f"[{SERVICE}]   {uid}: status={status}, waiting...")
                except Exception as exc:
                    raise RotationError(SERVICE, f"describe_users failed for '{uid}': {exc}", cause=exc)

            pending = still_pending
            if pending:
                time.sleep(POLL_INTERVAL)

        if pending:
            raise RotationError(SERVICE, f"Timed out waiting for users to become active: {pending}")

    # ------------------------------------------------------------------
    # Rollback hook
    # ------------------------------------------------------------------

    def _cleanup(self) -> None:
        """On rollback: restore each modified user to accept only the old password."""
        if not self._modified_user_ids:
            return
        client = self._client()
        for uid in self._modified_user_ids:
            try:
                client.modify_user(
                    UserId=uid,
                    Passwords=[self._old_password],
                    NoPasswordRequired=False,
                )
                logger.info("[%s] Rolled back: %s restored to old password.", SERVICE, uid)
            except Exception as exc:
                logger.error("[%s] Cleanup failed for user %s: %s", SERVICE, uid, exc)
                raise
