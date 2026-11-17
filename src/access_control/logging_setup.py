"""Keep third-party logging out of the operator's terminal.

Paramiko logs protocol oddities through the standard ``logging`` module.  When
nothing has configured a handler, Python falls back to ``logging.lastResort``,
which prints WARNING and above to stderr -- so a benign
``Oops, unhandled type 3 ('unimplemented')`` from the SSH transport lands in the
middle of a password prompt and reads like a failure.  It is not: type 3 is
``SSH_MSG_UNIMPLEMENTED``, a server telling us it ignored a message.

Rather than silence it (the detail matters when a hop misbehaves), give those
loggers a file of their own.  Records pass through :func:`~.redact.redact`
first, because this file is written to disk and a library could in principle log
a string a credential was interpolated into.
"""

from __future__ import annotations

import logging
import os
import traceback
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .paths import ensure_dir, log_dir
from .redact import redact

#: Libraries that talk on the wire and log while doing it.
NOISY_LOGGERS = (
    "paramiko",
    "pypsrp",
    "spnego",
    "requests",
    "urllib3",
    "asyncio",
)

#: Size at which ``transport.log`` and ``errors.log`` roll over, and how many
#: rolled ``transport.log`` files are kept. Neither file is covered by the audit
#: trail's ``retention_days`` pruning, so this is what bounds them.
MAX_LOG_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 3

_installed: Path | None = None


class _RotatingHandler(RotatingFileHandler):
    """Size-bounded, and quiet when the rename cannot happen.

    On Windows a second ``ac`` process holding the file open makes the rollover
    rename fail. Logging's default answer is a traceback on stderr, in the
    middle of the operator's prompt; the record is written to the current file
    instead and the rollover is retried on a later record.
    """

    def doRollover(self) -> None:
        try:
            super().doRollover()
        except OSError:
            pass


class _RedactingFilter(logging.Filter):
    """Scrub registered secrets from a record before it reaches the file."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        return True


def transport_log_path() -> Path:
    return log_dir() / "transport.log"


def install_quiet_logging(level: int = logging.WARNING) -> Path | None:
    """Route library logging to a file instead of the operator's terminal.

    Idempotent, and safe to call before the log directory exists.  Returns the
    file the records go to, or ``None`` if it could not be opened -- in which
    case the loggers are silenced rather than left printing to stderr.
    """
    global _installed
    if _installed is not None:
        return _installed

    handler: logging.Handler
    path: Path | None
    try:
        path = transport_log_path()
        ensure_dir(path.parent)
        # delay=True: no file is created unless a library actually logs.
        handler = _RotatingHandler(
            path, maxBytes=MAX_LOG_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8", delay=True
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
    except OSError:
        handler, path = logging.NullHandler(), None

    handler.addFilter(_RedactingFilter())
    for name in NOISY_LOGGERS:
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.setLevel(level)
        # Without this a root handler configured later would re-print these to
        # the terminal, which is the whole problem.
        logger.propagate = False

    _installed = path or transport_log_path()
    return path


def set_library_log_level(level: str) -> None:
    """Apply the inventory's ``logging.level`` to the library log.

    It governs ``transport.log`` only. The audit trail is evidence and records
    every action whatever this is set to.
    """
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(getattr(logging, level))


def record_unexpected(exc: BaseException, *, context: str = "") -> Path | None:
    """Write an unexpected exception's traceback where it can be looked up.

    Unexpected means "not an :class:`~.errors.AccessControlError`" -- a bug, or
    a library failing in a way this tool has no message for.  The operator gets
    one clean line; the traceback goes here so it is not lost.
    """
    try:
        path = log_dir() / "errors.log"
        ensure_dir(path.parent)
        if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
            os.replace(path, path.with_name(path.name + ".1"))
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"\n===== {stamp} {context} =====\n{redact(body)}")
        return path
    except OSError:
        return None
