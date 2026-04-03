from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

import doppler
from doppler import DopplerError

logger = logging.getLogger(__name__)


@dataclass
class RotationSession:
    """
    Tracks all services touched during a rotation run.
    Created once at the start of a run via create_session().
    Passed into every rotator's rotate() call.
    """

    pre_rotation_log_id: str
    touched_services: list[str] = field(default_factory=list)
    cleanup_hooks: dict[str, Optional[Callable[[], None]]] = field(default_factory=dict)
    failed: bool = False

    def register_service(
        self, service_name: str, cleanup_fn: Optional[Callable[[], None]] = None
    ) -> None:
        """Call before mutating any state for service_name."""
        if service_name not in self.touched_services:
            self.touched_services.append(service_name)
        self.cleanup_hooks[service_name] = cleanup_fn

    def mark_failed(self) -> None:
        self.failed = True


def create_session() -> RotationSession:
    """
    Capture the current Doppler config log ID and return a new RotationSession.
    Must be called BEFORE any rotator mutates state.
    """
    log = doppler.get_current_config_log()
    log_id = log["id"]
    logger.info("Rotation session started. Doppler snapshot log: %s", log_id)
    return RotationSession(pre_rotation_log_id=log_id)


def rollback_session(session: RotationSession) -> None:
    """
    1. Revert Doppler config to the pre-rotation log.
    2. Run per-service cleanup hooks in reverse insertion order.
    Errors in individual hooks are caught and logged — they do NOT abort the rest.
    """
    session.mark_failed()

    print("\n[ROLLBACK] Starting rollback...")

    # Step 1: Doppler rollback
    try:
        doppler.rollback_to_config_log(session.pre_rotation_log_id)
        print(f"[ROLLBACK] Doppler config reverted to log {session.pre_rotation_log_id}.")
    except DopplerError as exc:
        logger.error("Failed to rollback Doppler: %s", exc)
        print(f"[ROLLBACK] WARNING: Doppler rollback failed: {exc}")

    # Step 2: Per-service cleanup in reverse order
    for service in reversed(session.touched_services):
        hook = session.cleanup_hooks.get(service)
        if hook is None:
            print(f"[ROLLBACK] {service}: no service-side cleanup needed.")
            continue
        try:
            print(f"[ROLLBACK] {service}: running cleanup...")
            hook()
            print(f"[ROLLBACK] {service}: cleanup completed.")
        except Exception as exc:
            logger.error("Cleanup hook for %s raised: %s", service, exc)
            print(f"[ROLLBACK] {service}: cleanup FAILED ({exc}). Manual cleanup may be required.")

    print("[ROLLBACK] Rollback complete.\n")
