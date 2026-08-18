"""Interactive handoff to a human.

RDP is never used for automation here -- it cannot return an exit code.  What it
*is* good for is putting a real desktop in front of an operator, over the same
authenticated hop chain the automation uses.  Two situations need that:

* Something genuinely requires a GUI (a legacy installer with no silent switch).
* WinRM is disabled on a host, so there is no automation channel yet.  RDP in
  once, run ``Enable-PSRemoting -Force``, and the host is automatable from then
  on.  This is the bootstrap the whole design falls back to.

Credential handling defaults to *not* staging a password: ``mstsc`` prompts for
it, which is exactly the manual-entry model PLAN.md asks for.  Staging via
``cmdkey`` is opt-in, and the stored credential is always removed afterwards --
including if the process is interrupted.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import ChannelUnavailable

RDP_READY_GRACE_S = 1.0


def _windows_only(tool: str) -> None:
    if sys.platform != "win32":
        raise ChannelUnavailable(
            f"{tool} is only available on Windows; this client is running on {sys.platform}."
        )


@dataclass
class RdpSession:
    """A launched ``mstsc`` session and everything that must be cleaned up."""

    endpoint: str
    target_label: str
    username: str | None
    process: subprocess.Popen[bytes] | None = None
    staged_credential: str | None = None
    rdp_file: Path | None = None
    launched_at: float = field(default_factory=time.time)

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def wait(self, timeout: float | None = None) -> int | None:
        if self.process is None:
            return None
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def cleanup(self) -> list[str]:
        """Remove the staged credential and the generated .rdp file.

        Returns a list of what was cleaned, for the audit trail.  Never raises --
        cleanup runs from ``finally`` blocks and must not mask a real error.
        """
        cleaned: list[str] = []
        if self.staged_credential:
            try:
                subprocess.run(
                    ["cmdkey", f"/delete:{self.staged_credential}"],
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
                cleaned.append(f"credential {self.staged_credential}")
            except (OSError, subprocess.SubprocessError):
                pass
            self.staged_credential = None
        if self.rdp_file is not None:
            try:
                self.rdp_file.unlink(missing_ok=True)
                cleaned.append(str(self.rdp_file))
            except OSError:
                pass
            self.rdp_file = None
        return cleaned


def stage_credential(endpoint: str, username: str, password: str) -> str:
    """Store a Terminal Services credential for ``endpoint`` via ``cmdkey``.

    The password is on ``cmdkey``'s command line for the lifetime of that
    process, which is visible to other processes on this machine for a few
    milliseconds.  That is why staging is opt-in: the default lets ``mstsc``
    prompt instead, and nothing is written anywhere.
    """
    _windows_only("cmdkey")
    target = f"TERMSRV/{endpoint}"
    result = subprocess.run(
        ["cmdkey", f"/generic:{target}", f"/user:{username}", f"/pass:{password}"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        raise ChannelUnavailable(
            f"cmdkey could not stage a credential for {target}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return target


def write_rdp_file(endpoint: str, username: str | None, extra: dict[str, str] | None = None) -> Path:
    """Write a minimal ``.rdp`` file so the username is pre-filled.

    No password is ever written -- only the address, the username, and settings
    that make the session usable.  The file lands outside the repository.
    """
    settings = {
        "full address:s": endpoint,
        "prompt for credentials:i": "0" if username else "1",
        "administrative session:i": "0",
        "screen mode id:i": "2",
        "authentication level:i": "0",
        "negotiate security layer:i": "1",
        "redirectclipboard:i": "1",
        "redirectprinters:i": "0",
        "audiomode:i": "2",
    }
    if username:
        settings["username:s"] = username
    settings.update(extra or {})

    # Keys already carry their .rdp type suffix, so a line reads
    # "full address:s" + ":" + "127.0.0.1:53001".
    handle, name = tempfile.mkstemp(prefix="ac-rdp-", suffix=".rdp")
    path = Path(name)
    with os.fdopen(handle, "w", encoding="utf-8") as fh:
        for key, value in settings.items():
            fh.write(f"{key}:{value}\n")
    return path


def launch_rdp(
    endpoint: str,
    *,
    target_label: str,
    username: str | None = None,
    password: str | None = None,
    stage_credentials: bool = False,
    full_screen: bool = False,
) -> RdpSession:
    """Launch ``mstsc`` against ``endpoint`` (the local end of a tunnel)."""
    _windows_only("mstsc")
    if shutil.which("mstsc") is None:
        raise ChannelUnavailable("mstsc.exe was not found on this machine")

    session = RdpSession(endpoint=endpoint, target_label=target_label, username=username)
    try:
        if stage_credentials:
            if not (username and password):
                raise ChannelUnavailable(
                    "staging credentials needs both a username and a password"
                )
            session.staged_credential = stage_credential(endpoint, username, password)

        session.rdp_file = write_rdp_file(endpoint, username if stage_credentials else None)

        argv = ["mstsc", str(session.rdp_file)]
        if full_screen:
            argv.append("/f")
        session.process = subprocess.Popen(argv)  # noqa: S603 - fixed argv, no shell
        # Give mstsc time to read the file and the credential before either is
        # torn down by a fast caller.
        time.sleep(RDP_READY_GRACE_S)
        return session
    except Exception:
        session.cleanup()
        raise


def launch_ssh_shell(
    endpoint_host: str,
    endpoint_port: int,
    *,
    username: str | None = None,
    target_label: str = "",
) -> int:
    """Hand an interactive SSH shell to the operator through the tunnel.

    The system ``ssh`` client is used rather than a Paramiko shell loop: it
    already handles terminal raw mode, window resizing, and Ctrl-C correctly on
    Windows, and reimplementing that badly would be worse than shelling out.

    Host-key checking is disabled *for the loopback endpoint only*.  The forward
    itself already terminates on a bastion whose key was verified, and the
    ephemeral local port would otherwise produce a new "unknown host" every time.
    """
    ssh_exe = shutil.which("ssh")
    if ssh_exe is None:
        raise ChannelUnavailable(
            "the ssh client was not found. On Windows install it with:\n"
            "    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
        )

    destination = f"{username}@{endpoint_host}" if username else endpoint_host
    argv = [
        ssh_exe,
        "-p",
        str(endpoint_port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        f"UserKnownHostsFile={os.devnull}",
        "-o",
        "LogLevel=ERROR",
        destination,
    ]
    if target_label:
        print(f"Opening an interactive shell on {target_label} ...", file=sys.stderr)
    return subprocess.call(argv)  # noqa: S603 - fixed argv, no shell
