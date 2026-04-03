from __future__ import annotations

# Load .env into the process environment before any other module reads os.environ.
# This means `uv run main.py` works out of the box without manually exporting vars.
from dotenv import load_dotenv
load_dotenv(override=False)  # override=False: real env vars take priority over .env

import datetime
import logging
import pathlib
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import doppler
import rollback
from rollback import RotationSession
from resources import (
    APNSRotator,
    AzureADRotator,
    AzureOpenAIRotator,
    CloudflareRotator,
    ElastiCacheRotator,
    ElasticsearchRotator,
    FirebaseRotator,
    KafkaGCPRotator,
    MongoDBRotator,
    rotate_all_simple,
)
from utils import RotationError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

_ENVS_DIR = pathlib.Path(__file__).parent / "envs"


def write_last_env(payload: dict[str, str]) -> None:
    """
    After a successful rotation:
      1. Print every new credential clearly to the console.
      2. Write them to envs/.env.last so they can be retrieved later.
    """
    if not payload:
        return

    _ENVS_DIR.mkdir(exist_ok=True)
    last_env_path = _ENVS_DIR / ".env.last"
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")

    file_lines = [
        f"# Last rotation: {timestamp}",
        "# ⚠️  These are live credentials. Delete this file once noted.",
        "",
    ]
    for key in sorted(payload):
        file_lines.append(f"{key}={payload[key]}")
    last_env_path.write_text("\n".join(file_lines) + "\n")

    width = 56
    print()
    print("┌" + "─" * width + "┐")
    print("│" + " New credentials — also saved to envs/.env.last ".center(width) + "│")
    print("├" + "─" * width + "┤")
    for key in sorted(payload):
        line = f"  {key} = {payload[key]}"
        print("│" + line.ljust(width) + "│")
    print("└" + "─" * width + "┘")


MENU = """\
┌──────────────────────────────────────────────────────────────┐
│              Secret Rotation Orchestrator                    │
└──────────────────────────────────────────────────────────────┘
  1. AWS ElastiCache (Redis)
  2. GCP Kafka
  3. Firebase
  4. Cloudflare
  5. MongoDB Atlas
  6. Azure AD
  7. Azure OpenAI
  8. Apple APNS                   (can't be done programmatically)
  9. Simple API Keys
       Anthropic, Deepgram        (programmatic)
       OpenAI, Gemini             (can't be done programmatically)
 10. Elasticsearch
  0. Rotate ALL

  q. Quit
"""


def _build_rotator(choice: int):
    """Instantiate the rotator for a menu choice (1–10). Returns None for simple-keys."""
    if choice == 1:
        return ElastiCacheRotator()
    if choice == 2:
        return KafkaGCPRotator()
    if choice == 3:
        return FirebaseRotator()
    if choice == 4:
        return CloudflareRotator()
    if choice == 5:
        return MongoDBRotator()
    if choice == 6:
        return AzureADRotator()
    if choice == 7:
        return AzureOpenAIRotator()
    if choice == 8:
        return APNSRotator()
    if choice == 10:
        return ElasticsearchRotator()
    return None  # choice == 9 handled separately


def rotate_single(choice: int) -> None:
    """Rotate a single service (options 1–10)."""
    session = rollback.create_session()
    try:
        if choice == 9:
            # Simple keys — each sub-rotator registers itself
            payloads = rotate_all_simple(session)
            payload: dict[str, str] = {}
            for p in payloads:
                payload.update(p)
        else:
            rotator = _build_rotator(choice)
            payload = rotator.rotate(session)
        print("\n✅  Rotation finished successfully.")
        write_last_env(payload)
    except RotationError as exc:
        print(f"\n❌  Rotation failed: {exc}")
        logger.exception("RotationError during single rotation")
        rollback.rollback_session(session)
    except KeyboardInterrupt:
        print("\n⚠️  Rotation interrupted by user.")
        rollback.rollback_session(session)
    except Exception as exc:
        print(f"\n❌  Unexpected error: {exc}")
        logger.exception("Unexpected error during single rotation")
        rollback.rollback_session(session)


def rotate_all() -> None:
    """
    Rotate ALL services in the coordinated multi-phase flow described in the plan:
      1. Generate (sequential)
      2. Validate all (no Doppler writes yet)
      3. Single atomic Doppler push
      4. Watch rollouts (parallel, max_workers=5)
      5. Finalize / revoke old credentials
    """
    session = rollback.create_session()

    # --- Phase 1: Generate ---
    print("\n━━━ Phase 1: Generate new credentials ━━━")
    ALL_ROTATORS = [
        ElastiCacheRotator(),
        ElasticsearchRotator(),
        KafkaGCPRotator(),
        FirebaseRotator(),
        CloudflareRotator(),
        MongoDBRotator(),
        AzureADRotator(),
        AzureOpenAIRotator(),
        APNSRotator(),
    ]

    for rotator in ALL_ROTATORS:
        svc = rotator.__class__.__name__
        try:
            session.register_service(svc)
            print(f"  [{svc}] Generating...")
            rotator._generate_new_credential()  # type: ignore[attr-defined]
        except RotationError as exc:
            print(f"\n❌  Generate failed for {svc}: {exc}")
            rollback.rollback_session(session)
            return
        except Exception as exc:
            print(f"\n❌  Unexpected error for {svc}: {exc}")
            rollback.rollback_session(session)
            return

    # --- Phase 2: Validate ---
    print("\n━━━ Phase 2: Validate all credentials ━━━")
    all_payloads: dict[str, str] = {}
    for rotator in ALL_ROTATORS:
        svc = rotator.__class__.__name__
        try:
            print(f"  [{svc}] Validating...")
            rotator._validate_new_credential(session)  # type: ignore[attr-defined]
            all_payloads.update(rotator._doppler_payload())  # type: ignore[attr-defined]
        except RotationError as exc:
            print(f"\n❌  Validation failed for {svc}: {exc}")
            rollback.rollback_session(session)
            return

    # Simple keys are handled per-sub-service; run generates + validates inline
    from resources.simple_rotators import _ROTATORS as _SIMPLE
    simple_instances: dict[str, object] = {}
    for svc_name, cls in _SIMPLE.items():
        try:
            instance = cls()
            session.register_service(svc_name)
            print(f"  [{svc_name}] Generating...")
            instance.generate()
            print(f"  [{svc_name}] Validating...")
            result = instance.validate()
            if not result:
                raise RotationError(svc_name, f"Validation failed: {result.error}")
            all_payloads.update(instance.doppler_payload())
            simple_instances[svc_name] = instance
        except RotationError as exc:
            print(f"\n❌  Failed for {svc_name}: {exc}")
            rollback.rollback_session(session)
            return

    # --- Phase 3: Atomic Doppler push ---
    print("\n━━━ Phase 3: Pushing all secrets to Doppler ━━━")
    try:
        doppler.push_secrets(all_payloads)
        print(f"  Pushed {len(all_payloads)} secret(s).")
    except Exception as exc:
        print(f"\n❌  Doppler push failed: {exc}")
        rollback.rollback_session(session)
        return

    # --- Phase 4: Watch rollouts (parallel) ---
    print("\n━━━ Phase 4: Watching rollouts ━━━")
    watch_errors: list[str] = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(rotator._watch_rollout): rotator.__class__.__name__  # type: ignore[attr-defined]
            for rotator in ALL_ROTATORS
        }
        for future in as_completed(futures):
            svc = futures[future]
            try:
                future.result()
                print(f"  [{svc}] Rollout OK.")
            except Exception as exc:
                watch_errors.append(f"{svc}: {exc}")
                print(f"  [{svc}] Rollout error: {exc}")

    if watch_errors:
        print("\n❌  Rollout failures detected — rolling back.")
        rollback.rollback_session(session)
        return

    # --- Phase 5: Finalize ---
    print("\n━━━ Phase 5: Revoking old credentials ━━━")
    for rotator in ALL_ROTATORS:
        svc = rotator.__class__.__name__
        try:
            rotator._finalize()  # type: ignore[attr-defined]
        except Exception as exc:
            # Log but do NOT roll back — new creds are already live
            logger.error("[%s] Finalize failed (non-fatal): %s", svc, exc)
            print(f"  [{svc}] Finalize warning (manual cleanup may be needed): {exc}")

    for svc_name, instance in simple_instances.items():
        try:
            instance.finalize()  # type: ignore[attr-defined]
        except Exception as exc:
            logger.error("[%s] Finalize failed (non-fatal): %s", svc_name, exc)
            print(f"  [{svc_name}] Finalize warning: {exc}")

    print("\n✅  All services rotated successfully.")
    write_last_env(all_payloads)


def main() -> None:
    while True:
        print(MENU)
        raw = input("Choice: ").strip().lower()

        if raw in ("q", "quit", "exit"):
            print("Goodbye.")
            sys.exit(0)

        try:
            choice = int(raw)
        except ValueError:
            print("Invalid input — please enter a number or 'q'.")
            continue

        if choice not in range(0, 11):
            print("Please choose a number between 0 and 10.")
            continue

        if choice == 0:
            rotate_all()
        else:
            rotate_single(choice)

        print()
        cont = input("Return to menu? [Y/n]: ").strip().lower()
        if cont in ("n", "no"):
            print("Goodbye.")
            sys.exit(0)


if __name__ == "__main__":
    main()
