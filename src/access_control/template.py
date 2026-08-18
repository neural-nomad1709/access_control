"""Strict ``{{name}}`` templating for operation steps.

Deliberately strict: an unresolved placeholder raises instead of rendering an
empty string.  ``Remove-Item {{path}}`` silently becoming ``Remove-Item`` is the
kind of mistake that deletes the wrong thing on a production server.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .errors import TemplateError

_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\}\}")


def placeholders(template: str) -> list[str]:
    """Every distinct variable name referenced by ``template``, in order."""
    seen: list[str] = []
    for match in _PLACEHOLDER.finditer(template):
        name = match.group(1)
        if name not in seen:
            seen.append(name)
    return seen


def render(template: str, variables: Mapping[str, Any], *, where: str = "template") -> str:
    """Substitute ``{{name}}`` placeholders from ``variables``.

    Raises :class:`TemplateError` naming every missing variable at once, so a
    misconfigured operation reports all its problems in one pass.
    """
    missing = [
        name
        for name in placeholders(template)
        if name not in variables or variables[name] is None
    ]
    if missing:
        available = ", ".join(sorted(variables)) or "(none)"
        raise TemplateError(
            f"{where}: unresolved variable(s) {', '.join(missing)}. Available: {available}"
        )

    def _sub(match: re.Match[str]) -> str:
        return str(variables[match.group(1)])

    return _PLACEHOLDER.sub(_sub, template)
