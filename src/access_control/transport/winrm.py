"""PowerShell Remoting over the SSH tunnel.

This is the automation channel for Windows.  RDP carries pixels; PSRP carries
output, error, warning and verbose streams plus a resolved exit code -- which is
what makes "read the logs after each action and fix what broke" possible at all.

Transport notes
---------------
The endpoint is always ``127.0.0.1:<tunnel port>``, so **NTLM** is the right
authentication choice: unlike Kerberos it needs no SPN, and the loopback address
is only ever the local end of the forward.  ``encryption='auto'`` keeps pypsrp's
message-level encryption on even over plain HTTP, so the payload is encrypted
inside the SSH tunnel rather than relying on it.

A single :class:`RunspacePool` is held open for the whole session.  That avoids
re-authenticating per command, and lets a multi-step operation share state (a
variable set in one step is visible in the next).
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Mapping

from pypsrp.client import Client
from pypsrp.powershell import PowerShell, RunspacePool

from ..errors import ChannelUnavailable, ConnectionFailed
from .base import ExecResult
from .pshell import parse_exit, quote_single, wrap_script

#: WinRM's own operation timeout.  Long installs are fine -- PSRP keeps polling
#: with fresh Receive calls -- but the read timeout must exceed it.
DEFAULT_OPERATION_TIMEOUT = 60
DEFAULT_READ_TIMEOUT = 90
DEFAULT_CONNECT_TIMEOUT = 30

#: Substrings that mark a *transport* wedge -- the request was rejected at the
#: HTTP/auth layer, so the command never reached the shell and re-running it is
#: safe. The classic case is a desynced NTLM message-seal, which makes every
#: subsequent sealed request return an empty "Bad HTTP response ... Code: 400".
#: A reset mid-send (10054) is the same category. These are matched against the
#: exception text to decide whether to rebuild the transport and retry once.
_WEDGE_MARKERS = (
    "bad http response",
    "code: 400",
    "10054",
    "an existing connection was forcibly closed",
    "connection aborted",
    "connection reset",
)


def _looks_wedged(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in _WEDGE_MARKERS)

#: Opt-in escape hatch. On a workstation where Group Policy sets "Restrict NTLM:
#: Outgoing NTLM traffic = Deny" and this host is not on the allow-list, Windows
#: SSPI refuses to emit the NTLM token and pypsrp fails locally with
#: SEC_E_LOGON_DENIED (0x8009030C) -- *before* the server ever sees the
#: credential, so it looks like a wrong password when it is not. Setting this
#: switches pypsrp to spnego's pure-Python NTLM provider, which computes the
#: response itself and does not consult the LSA allow-list. It deliberately
#: steps around a corporate control, so it is off unless explicitly enabled.
PYTHON_NTLM_ENV = "AC_WINRM_PYTHON_NTLM"

_python_ntlm_installed = False


def _python_ntlm_requested() -> bool:
    return os.environ.get(PYTHON_NTLM_ENV, "").strip().lower() in ("1", "true", "yes")


def _install_python_ntlm() -> None:
    """Force pypsrp/spnego to use the pure-Python NTLM provider, once per process.

    pypsrp calls ``spnego.client(..., options=...)`` and offers no hook to pick
    the provider, so we wrap that call to OR in ``NegotiateOptions.use_ntlm``.
    ``wrapping_winrm`` (message encryption) is preserved because pypsrp adds it to
    the same options value, so the payload is still sealed over plain HTTP.
    """
    global _python_ntlm_installed
    if _python_ntlm_installed:
        return
    import spnego

    original = spnego.client

    def _client(*args: Any, **kwargs: Any):
        opts = kwargs.get("options", 0) or 0
        kwargs["options"] = opts | spnego.NegotiateOptions.use_ntlm
        return original(*args, **kwargs)

    spnego.client = _client
    try:
        import pypsrp.negotiate as _neg  # the module that actually calls spnego.client

        _neg.spnego.client = _client
    except Exception:  # noqa: BLE001 - if the import layout changes, the global patch still applies
        pass
    _python_ntlm_installed = True


class WinRMChannel:
    """A PowerShell Remoting session against one Windows machine."""

    kind = "winrm"

    def __init__(
        self,
        node_id: str,
        endpoint_host: str,
        endpoint_port: int,
        *,
        username: str,
        password: str,
        auth: str = "ntlm",
        ntlm_provider: str = "sspi",
        ssl: bool = False,
        display_target: str | None = None,
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    ) -> None:
        self.node_id = node_id
        self.endpoint = f"{endpoint_host}:{endpoint_port}"
        #: The machine's real address, for error messages -- the endpoint is a
        #: loopback port and would be meaningless to an operator.
        self.display_target = display_target or self.endpoint
        self.username = username
        self._password = password
        self._auth = auth
        # On a host whose outgoing NTLM is blocked by local Group Policy, switch
        # pypsrp to the pure-Python NTLM provider before the client is built (it
        # wraps spnego.client, which pypsrp calls lazily on first use). Driven by
        # the host's `auth.ntlm_provider: python` in inventory.yaml; the env var
        # remains as an operator override so behaviour can be forced without a
        # config edit.
        if auth == "ntlm" and (ntlm_provider == "python" or _python_ntlm_requested()):
            _install_python_ntlm()
        #: Everything needed to rebuild the pypsrp client from scratch, so a
        #: wedged transport (a desynced NTLM message-seal) can be discarded and a
        #: fresh handshake negotiated without re-prompting for the credential.
        self._client_kwargs = dict(
            server=endpoint_host,
            port=endpoint_port,
            username=username,
            password=password,
            ssl=ssl,
            auth=auth,
            cert_validation=False,
            encryption="auto",
            connection_timeout=connect_timeout,
            operation_timeout=DEFAULT_OPERATION_TIMEOUT,
            read_timeout=DEFAULT_READ_TIMEOUT,
        )
        self._client = self._build_client()
        self._pool: RunspacePool | None = None
        self._lock = threading.RLock()
        #: How many times the transport was transparently rebuilt after a wedge.
        self.reopens = 0

    def _build_client(self) -> Client:
        kwargs = dict(self._client_kwargs)
        server = kwargs.pop("server")
        return Client(server, **kwargs)

    # -- lifecycle --------------------------------------------------------

    def connect(self) -> "WinRMChannel":
        """Open the runspace pool and confirm the far end really answers."""
        if self._pool is not None:
            return self

        pool = RunspacePool(self._client.wsman)
        try:
            pool.open()
        except Exception as exc:  # noqa: BLE001 - pypsrp raises a wide family here
            raise self._connect_error(exc) from exc
        self._pool = pool
        return self

    def _connect_error(self, exc: Exception) -> ConnectionFailed:
        text = str(exc)
        hint = ""
        lowered = text.lower()
        reset = any(
            marker in lowered
            for marker in ("10054", "forcibly closed", "connection aborted", "connection reset")
        )
        if "401" in text or "unauthorized" in lowered or "authentication" in lowered:
            hint = (
                "\nThe credentials were rejected. Check the username form -- WinRM usually "
                "wants DOMAIN\\user or user@domain. Nothing was stored; you will be prompted "
                "again on retry."
            )
        elif reset:
            # A reset is NOT "nothing is listening" -- that gives a refusal or a
            # timeout. Something accepted the connection and then closed it, and
            # across an SSH forward the usual culprit is the far end of the
            # forward, not the WinRM service.
            hint = (
                f"\nThe connection was ACCEPTED and then closed, which is different from "
                f"nothing listening.\n"
                f"Across an SSH forward this most often means the BASTION could not reach "
                f"{self.display_target} -- sshd opens the local port, discovers the far side "
                f"is unreachable, and closes the channel. Confirm from the bastion itself:\n"
                f"    uv run ac shell bastion1\n"
                f"    nc -vz {self.display_target.replace(':', ' ')}\n"
                f"Other causes, in order: WinRM is listening on HTTPS 5986 only (set the "
                f"port and protocol to winrm-ssl); a host firewall on the target dropping "
                f"the session; or an HTTP listener that rejects unencrypted traffic for "
                f"this auth type."
            )
        elif "connection" in lowered or "refused" in lowered or "timed out" in lowered:
            hint = (
                f"\nThe tunnel is up but nothing answered WinRM on {self.display_target}. "
                f"Run 'ac probe' to confirm 5985 is open, and if it is closed use "
                f"'ac rdp' once to run: Enable-PSRemoting -Force"
            )
        return ConnectionFailed(
            f"{self.node_id}: PowerShell Remoting to {self.display_target} failed "
            f"(via {self.endpoint}): {text}{hint}"
        )

    def close(self) -> None:
        with self._lock:
            pool, self._pool = self._pool, None
        if pool is not None:
            try:
                pool.close()
            except Exception:  # noqa: BLE001 - teardown must never raise
                pass

    def _reopen(self) -> None:
        """Discard the wedged transport and open a fresh one.

        The NTLM message-seal counters live in the auth context held by the
        pypsrp client's WSMan transport, so a desync survives merely reopening
        the pool -- the whole client has to be rebuilt to force a new handshake.
        The stored credential is reused, so this is invisible to the operator.
        """
        with self._lock:
            old, self._pool = self._pool, None
            if old is not None:
                try:
                    old.close()
                except Exception:  # noqa: BLE001 - the old transport is wedged anyway
                    pass
            self._client = self._build_client()
            pool = RunspacePool(self._client.wsman)
            pool.open()
            self._pool = pool
            self.reopens += 1

    @property
    def active(self) -> bool:
        return self._pool is not None

    # -- execution --------------------------------------------------------

    def exec(
        self,
        command: str,
        *,
        shell: str = "powershell",
        timeout_s: int = 600,
        parameters: Mapping[str, Any] | None = None,
    ) -> ExecResult:
        """Run one script and return its streams and exit code."""
        if shell in ("cmd", "bash", "sh"):
            # Route everything through PowerShell so there is one code path and
            # one exit-code convention.
            script = f"& cmd.exe /c {quote_single(command)}"
        else:
            script = command

        wrapped = wrap_script(script, out_string=True)
        started = time.monotonic()
        output, streams, had_errors, timed_out = self._invoke(wrapped, parameters, timeout_s)
        duration = time.monotonic() - started

        stdout, exit_code = parse_exit(output)
        errors = [str(e) for e in getattr(streams, "error", []) or []]
        if exit_code is None:
            # The sentinel never printed: the pipeline was stopped or died.
            exit_code = None if timed_out else (1 if had_errors else 0)

        return ExecResult(
            node_id=self.node_id,
            channel="winrm",
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr="\n".join(errors),
            duration_s=duration,
            ps_errors=errors,
            ps_warnings=[str(w) for w in getattr(streams, "warning", []) or []],
            ps_verbose=[str(v) for v in getattr(streams, "verbose", []) or []],
            ps_information=[str(i) for i in getattr(streams, "information", []) or []],
            timed_out=timed_out,
        )

    def _invoke(
        self,
        script: str,
        parameters: Mapping[str, Any] | None,
        timeout_s: int,
        attempt: int = 0,
    ) -> tuple[str, Any, bool, bool]:
        """Run ``script`` in the pool, enforcing a wall-clock timeout.

        pypsrp has no per-pipeline timeout, so the pipeline runs on a worker
        thread and is explicitly stopped if it overruns -- otherwise a hung
        installer would block the session for ever.

        A single transparent retry recovers from a transport wedge: if the call
        fails with a wedge signature (see :data:`_WEDGE_MARKERS`), the transport
        is rebuilt and the same script re-run once. It is safe because a wedge
        rejects the request before the shell executes it.
        """
        if self._pool is None:
            raise ChannelUnavailable(
                f"{self.node_id}: no PowerShell Remoting session is open (call connect first)"
            )

        with self._lock:
            ps = PowerShell(self._pool)
            ps.add_script(script)
            for name, value in (parameters or {}).items():
                ps.add_parameter(name, value)

            result: dict[str, Any] = {}

            def _run() -> None:
                try:
                    result["output"] = ps.invoke()
                except Exception as exc:  # noqa: BLE001 - reported, not raised, from a thread
                    result["error"] = exc

            worker = threading.Thread(target=_run, name=f"ac-psrp-{self.node_id}", daemon=True)
            worker.start()
            worker.join(timeout=timeout_s)

            timed_out = worker.is_alive()
            if timed_out:
                try:
                    ps.stop()
                except Exception:  # noqa: BLE001
                    pass
                worker.join(timeout=15)

            if "error" in result and not timed_out:
                exc = result["error"]
                if attempt == 0 and _looks_wedged(exc):
                    # The transport is wedged (typically a desynced NTLM
                    # message-seal): every sealed request now 400s. The request
                    # was rejected before the shell ran it, so rebuild the
                    # transport and re-run the same script exactly once.
                    self._reopen()
                    return self._invoke(script, parameters, timeout_s, attempt=1)
                raise ConnectionFailed(
                    f"{self.node_id}: PowerShell Remoting call failed: {exc}"
                )

            output_objects = result.get("output") or []
            text = "\n".join(str(o) for o in output_objects)
            return text, ps.streams, bool(ps.had_errors), timed_out

    # -- file transfer ----------------------------------------------------

    def upload(self, local_path: str, remote_path: str) -> str:
        """Copy a local file to the Windows host over WinRM.

        Slow for large files -- WinRM base64-encodes the payload.  Prefer a
        package share already present on the server, which is what the shipped
        install operation assumes.
        """
        return self._client.copy(str(local_path), str(remote_path))

    def fetch(self, remote_path: str, local_path: str) -> None:
        self._client.fetch(str(remote_path), str(local_path))


def nested_invoke_script() -> str:
    """The script used for a Windows-to-Windows leg.

    The password arrives as a *bound parameter*, never inside the script text.
    That matters: PowerShell script-block logging (event 4104) records the script
    a jump server executes, so an interpolated password would be written to that
    server's event log in clear text.  A parameter value is not part of the
    logged script body.
    """
    return """
param(
    [Parameter(Mandatory=$true)][string]$AcComputerName,
    [Parameter(Mandatory=$true)][string]$AcUser,
    [Parameter(Mandatory=$true)][string]$AcPassword,
    [Parameter(Mandatory=$true)][string]$AcScript,
    [int]$AcPort = 5985
)
$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString -String $AcPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($AcUser, $secure)
$block = [ScriptBlock]::Create($AcScript)
try {
    Invoke-Command -ComputerName $AcComputerName -Port $AcPort -Credential $credential `
        -Authentication Negotiate -ScriptBlock $block
} finally {
    Remove-Variable -Name AcPassword, secure, credential -ErrorAction SilentlyContinue
}
""".strip()


class NestedWinRMChannel:
    """A Windows target reached *through* a Windows jump server.

    The jump server is already driven over PSRP; this runs ``Invoke-Command`` on
    it, pointed at the next machine, with credentials supplied as parameters.
    That is the "Jump Server → Target Server" leg from PLAN.md, with a channel
    that returns real output instead of a screenshot.
    """

    kind = "nested-winrm"

    def __init__(
        self,
        node_id: str,
        via: WinRMChannel,
        *,
        target_host: str,
        target_port: int,
        username: str,
        password: str,
    ) -> None:
        self.node_id = node_id
        self.via = via
        self.target_host = target_host
        self.target_port = target_port
        self.username = username
        self._password = password

    @property
    def active(self) -> bool:
        return self.via.active

    def connect(self) -> "NestedWinRMChannel":
        """Verify the far end answers before any real work is attempted."""
        probe = self.exec("$env:COMPUTERNAME", timeout_s=90)
        if not probe.ok:
            raise ConnectionFailed(
                f"{self.node_id}: cannot reach {self.target_host}:{self.target_port} from "
                f"{self.via.node_id}.\n"
                f"{probe.stderr or probe.stdout}\n"
                f"Check that WinRM is enabled on the target and that "
                f"{self.via.node_id} is allowed to reach it on {self.target_port}. From an "
                f"RDP session on {self.via.node_id} you can confirm with:\n"
                f"    Test-NetConnection {self.target_host} -Port {self.target_port}"
            )
        return self

    def exec(self, command: str, *, shell: str = "powershell", timeout_s: int = 600) -> ExecResult:
        if shell in ("cmd", "bash", "sh"):
            command = f"& cmd.exe /c {quote_single(command)}"

        result = self.via.exec(
            nested_invoke_script(),
            shell="powershell",
            timeout_s=timeout_s,
            parameters={
                "AcComputerName": self.target_host,
                "AcUser": self.username,
                "AcPassword": self._password,
                "AcScript": wrap_script(command, out_string=True),
                "AcPort": self.target_port,
            },
        )

        # The inner script emits its own sentinel, which travelled back through
        # the jump server's output; re-parse so the target's exit code wins.
        stdout, inner_exit = parse_exit(result.stdout)
        return ExecResult(
            node_id=self.node_id,
            channel="nested-winrm",
            command=command,
            exit_code=inner_exit if inner_exit is not None else result.exit_code,
            stdout=stdout,
            stderr=result.stderr,
            duration_s=result.duration_s,
            ps_errors=result.ps_errors,
            ps_warnings=result.ps_warnings,
            ps_verbose=result.ps_verbose,
            ps_information=result.ps_information,
            timed_out=result.timed_out,
        )

    def upload(self, local_path: str, remote_path: str) -> str:
        raise ChannelUnavailable(
            f"{self.node_id}: direct upload through a Windows jump server is not supported.\n"
            f"Copy to {self.via.node_id} first, then move it on with an operation step, or "
            f"use the server-local package share."
        )

    def fetch(self, remote_path: str, local_path: str) -> None:
        raise ChannelUnavailable(
            f"{self.node_id}: direct fetch through a Windows jump server is not supported.\n"
            f"Use a step that copies the file to {self.via.node_id} first."
        )

    def close(self) -> None:
        # The underlying jump-server channel is owned by the session.
        return None
