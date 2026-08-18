"""Execution channels.

Each module here knows how to reach one kind of machine and run one command on
it, and nothing about operations, sessions, or policy.

``base``    result type and the channel protocol every transport implements
``ssh``     Paramiko, chained hop to hop with ``direct-tcpip``
``tunnel``  local port forward anchored at the last SSH hop
``winrm``   PowerShell Remoting over that tunnel (pypsrp)
``nested``  Windows-to-Windows leg via ``Invoke-Command`` with explicit credentials
``rdp``     interactive ``mstsc`` handoff for a human (never used for automation)
"""

from __future__ import annotations

from .base import ExecResult, clamp_output

__all__ = ["ExecResult", "clamp_output"]
