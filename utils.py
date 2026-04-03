from __future__ import annotations

import functools
import logging
import os
import random
import time
from typing import Any, Callable, Type, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class RotationError(Exception):
    def __init__(self, service: str, message: str, cause: Exception | None = None) -> None:
        self.service = service
        self.cause = cause
        super().__init__(f"[{service}] {message}")


def get_required_env(*names: str) -> dict[str, str]:
    """Read env vars, raise EnvironmentError listing all missing ones."""
    values: dict[str, str] = {}
    missing: list[str] = []
    for name in names:
        val = os.environ.get(name)
        if val is None:
            missing.append(name)
        else:
            values[name] = val
    if missing:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing)}")
    return values


def with_retry(
    fn: Callable[..., T],
    *,
    retryable_exceptions: tuple[Type[Exception], ...] = (Exception,),
    max_retries: int = 5,
    base_delay: float = 1.0,
    cap: float = 60.0,
    jitter: bool = True,
) -> T:
    """
    Call fn(). On retryable exception, sleep with full-jitter exponential backoff:
      delay = random(0, min(cap, base_delay * 2^attempt))
    Raises the final exception after max_retries exhausted.
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except retryable_exceptions as exc:
            last_exc = exc
            if attempt == max_retries:
                break
            ceiling = min(cap, base_delay * (2 ** attempt))
            delay = random.uniform(0, ceiling) if jitter else ceiling
            logger.warning(
                "Attempt %d/%d failed (%s). Retrying in %.1fs...",
                attempt + 1,
                max_retries,
                exc,
                delay,
            )
            time.sleep(delay)
    raise last_exc  # type: ignore[misc]


def retry(
    retryable_exceptions: tuple[Type[Exception], ...] = (Exception,),
    max_retries: int = 5,
    base_delay: float = 1.0,
    cap: float = 60.0,
    jitter: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator form of with_retry."""
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return with_retry(
                lambda: fn(*args, **kwargs),
                retryable_exceptions=retryable_exceptions,
                max_retries=max_retries,
                base_delay=base_delay,
                cap=cap,
                jitter=jitter,
            )
        return wrapper
    return decorator
