"""Secret scrubbing.

Every string that leaves this process -- console output, audit records,
exception messages -- passes through :func:`redact` first.  Secrets are
registered the moment they are collected from the user and stay registered for
the lifetime of the process.

The registry holds the plaintext in memory (it has to, in order to match it),
but nothing here ever writes a secret anywhere.  :func:`clear` wipes it on
disconnect.
"""

from __future__ import annotations

import threading
from typing import Any

MASK = "***REDACTED***"

# Secrets shorter than this are not registered: masking a 3-character string
# would corrupt unrelated output far more than it would protect anything.
MIN_SECRET_LENGTH = 4

_lock = threading.RLock()
_secrets: set[str] = set()


def register(secret: str | None) -> None:
    """Register a secret to be scrubbed from all future output."""
    if not secret or len(secret) < MIN_SECRET_LENGTH:
        return
    with _lock:
        _secrets.add(secret)
        # A password typed on Windows may reach a remote shell with backslashes
        # escaped, or be embedded in a URL.  Register those forms too so a
        # transformed copy cannot leak.
        escaped = secret.replace("\\", "\\\\")
        if escaped != secret:
            _secrets.add(escaped)


def unregister(secret: str | None) -> None:
    """Forget a single secret (used when a hop's credential is discarded)."""
    if not secret:
        return
    with _lock:
        _secrets.discard(secret)
        _secrets.discard(secret.replace("\\", "\\\\"))


def clear() -> None:
    """Wipe the whole registry.  Called when a session disconnects."""
    with _lock:
        _secrets.clear()


def count() -> int:
    """How many secrets are currently registered (for diagnostics only)."""
    with _lock:
        return len(_secrets)


def redact(text: Any) -> Any:
    """Replace every registered secret in ``text`` with :data:`MASK`.

    Non-string input is returned unchanged, so this is safe to apply blindly.
    """
    if not isinstance(text, str) or not text:
        return text
    with _lock:
        current = tuple(_secrets)
    if not current:
        return text
    # Longest first: if one secret contains another, mask the larger match.
    for secret in sorted(current, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, MASK)
    return text


def redact_obj(obj: Any) -> Any:
    """Recursively redact strings inside dicts, lists, tuples and sets."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {redact_obj(k): redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(v) for v in obj)
    if isinstance(obj, set):
        return {redact_obj(v) for v in obj}
    return obj


class RedactingError(Exception):
    """Base for errors whose message is scrubbed before it is ever displayed."""

    def __init__(self, message: str) -> None:
        super().__init__(redact(message))
