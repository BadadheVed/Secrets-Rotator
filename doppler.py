from __future__ import annotations

import logging
import os

import httpx

from utils import retry

logger = logging.getLogger(__name__)

DOPPLER_API_BASE = "https://api.doppler.com/v3"


class DopplerError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"Doppler API error {status_code}: {message}")


def _get_headers() -> dict[str, str]:
    token = os.environ.get("DOPPLER_TOKEN")
    if not token:
        raise EnvironmentError("Missing required environment variable: DOPPLER_TOKEN")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _get_project_config() -> tuple[str, str]:
    project = os.environ.get("DOPPLER_PROJECT")
    config = os.environ.get("DOPPLER_CONFIG")
    missing = [n for n, v in [("DOPPLER_PROJECT", project), ("DOPPLER_CONFIG", config)] if not v]
    if missing:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing)}")
    return project, config  # type: ignore[return-value]


def _raise_for_status(response: httpx.Response) -> None:
    if response.status_code >= 400:
        try:
            body = response.json()
            msg = body.get("messages", [str(body)])[0]
        except Exception:
            msg = response.text
        raise DopplerError(response.status_code, msg)


@retry(retryable_exceptions=(httpx.HTTPStatusError, httpx.ConnectError, DopplerError), max_retries=5, base_delay=1.0, cap=60.0)
def get_current_config_log() -> dict:
    """Return the most recent Doppler config log entry."""
    project, config = _get_project_config()
    params = {"project": project, "config": config, "page": 1, "per_page": 1}
    with httpx.Client(timeout=30) as client:
        resp = client.get(f"{DOPPLER_API_BASE}/configs/config/logs", headers=_get_headers(), params=params)
    _raise_for_status(resp)
    logs = resp.json().get("logs", [])
    if not logs:
        raise DopplerError(404, "No config logs found — has this config been used before?")
    return logs[0]


@retry(retryable_exceptions=(httpx.HTTPStatusError, httpx.ConnectError, DopplerError), max_retries=5, base_delay=1.0, cap=60.0)
def push_secrets(secrets_dict: dict[str, str]) -> dict:
    """Merge-push secrets into Doppler config. Unrelated secrets are unaffected."""
    project, config = _get_project_config()
    payload = {"project": project, "config": config, "secrets": secrets_dict}
    with httpx.Client(timeout=30) as client:
        resp = client.post(f"{DOPPLER_API_BASE}/configs/config/secrets", headers=_get_headers(), json=payload)
    _raise_for_status(resp)
    logger.info("Pushed %d secret(s) to Doppler (%s/%s).", len(secrets_dict), project, config)
    return resp.json()


@retry(retryable_exceptions=(httpx.HTTPStatusError, httpx.ConnectError, DopplerError), max_retries=5, base_delay=1.0, cap=60.0)
def rollback_to_config_log(log_id: str) -> dict:
    """Revert Doppler config to the state captured in log_id."""
    project, config = _get_project_config()
    # Correct endpoint: POST /v3/configs/config/logs/log/rollback
    # log_id is a query param (?log=...), NOT a path segment.
    params = {"project": project, "config": config, "log": log_id}
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            f"{DOPPLER_API_BASE}/configs/config/logs/log/rollback",
            headers=_get_headers(),
            params=params,
        )
    _raise_for_status(resp)
    logger.info("Rolled back Doppler config to log %s.", log_id)
    return resp.json()
