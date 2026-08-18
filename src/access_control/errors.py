"""Exception hierarchy.

Every message is scrubbed of registered secrets before it can be printed, so a
password embedded in a connection string can never leak through a traceback.
"""

from __future__ import annotations

from .redact import RedactingError


class AccessControlError(RedactingError):
    """Base class for all errors raised by this package."""


class ConfigError(AccessControlError):
    """The inventory or operations file is invalid."""


class RouteError(AccessControlError):
    """A host's hop path cannot be turned into an executable route."""


class CredentialError(AccessControlError):
    """A credential could not be obtained (no prompter, cancelled, refused)."""


class ConnectionFailed(AccessControlError):
    """A hop or target could not be reached or authenticated."""


class ChannelUnavailable(AccessControlError):
    """The requested execution channel is not usable on this host."""


class SessionError(AccessControlError):
    """The session is missing, expired, or in the wrong state."""


class PermissionRequired(AccessControlError):
    """A gated operation was attempted without explicit confirmation."""


class CommandBlocked(AccessControlError):
    """A command matched the catastrophic-command deny-list."""


class StepFailed(AccessControlError):
    """A step ran but did not meet its expectation."""


class TemplateError(AccessControlError):
    """A step template referenced a variable that was not supplied."""
