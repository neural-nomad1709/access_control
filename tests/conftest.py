"""Shared fixtures.

Every test here runs fully offline: no bastion, no target, no network.  The
transports are exercised against fakes so the parts that carry credentials and
decide policy can be tested exhaustively without a production server.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any, Callable

import pytest

from access_control.audit import AuditLog
from access_control.config import Catalog, Host, Inventory, load_inventory, load_operations
from access_control.route import plan_route
from access_control.transport.base import ExecResult

# NOTE: a raw string, so a backslash here is the backslash YAML sees. YAML
# single-quoted scalars do not process escapes, so 'D:\packages' is literal.
INVENTORY_YAML = r"""
hops:
  bastion1:
    kind: ssh
    host: bastion.example.net
    port: 2222
    user: opuser
    description: Test bastion
    auth:
      method: key+password
      key_file: ~/.ssh/id_test
  jump1:
    kind: windows
    host: 10.0.0.10
    user: 'CORP\opuser'
    description: Windows jump server
    automation: winrm
    interactive: rdp

hosts:
  lin01:
    kind: linux
    host: 10.0.0.20
    path: [bastion1]
    user: opuser
    tags: [linux]
    auth:
      method: password
  win01:
    kind: windows
    host: 10.0.0.30
    path: [bastion1, jump1]
    user: 'CORP\opuser'
    automation: winrm
    interactive: rdp
    tags: [windows, prod]
    vars:
      patch_share: 'D:\packages\patches'
  win02:
    kind: windows
    host: 10.0.0.31
    path: [bastion1]
    user: 'CORP\opuser'
    automation: winrm
    tags: [windows]
"""

OPERATIONS_YAML = r"""
operations:
  - id: echo-op
    description: Two harmless steps
    host_ids: ['*']
    requires_permission: false
    params:
      - name: message
        required: true
    steps:
      - id: first
        desc: Say the message
        run: |
          Write-Output '{{message}}'
        expect:
          stdout_contains: '{{message}}'
      - id: second
        desc: Report the host
        run: |
          Write-Output '{{host_id}}'

  - id: needs-approval
    description: Gated operation
    host_ids: [win01]
    requires_permission: true
    steps:
      - id: only
        desc: Restart a service
        run: |
          Restart-Service W3SVC

  - id: failing-op
    description: Fails, then collects diagnostics
    host_ids: ['*']
    requires_permission: false
    steps:
      - id: boom
        desc: Always fails
        run: |
          Write-Output 'about to fail'
          exit 1603
        on_failure:
          collect:
            - files: ['C:\Windows\Temp\*.log']
          hints:
            "1603": Generic MSI failure -- read the collected log
            "*": Something else went wrong
      - id: never-reached
        desc: Should not run
        run: |
          Write-Output 'unreachable'

  - id: windows-only
    description: Bound by tag
    tags: [windows]
    requires_permission: false
    steps:
      - id: only
        desc: Trivial
        run: |
          Write-Output 'ok'
"""


@pytest.fixture
def config_files(tmp_path: Path) -> Path:
    directory = tmp_path / "config"
    directory.mkdir()
    (directory / "inventory.yaml").write_text(textwrap.dedent(INVENTORY_YAML), encoding="utf-8")
    (directory / "operations.yaml").write_text(textwrap.dedent(OPERATIONS_YAML), encoding="utf-8")
    return directory


@pytest.fixture
def inventory(config_files: Path) -> Inventory:
    return load_inventory(config_files / "inventory.yaml")


@pytest.fixture
def catalog(config_files: Path) -> Catalog:
    return load_operations(config_files / "operations.yaml")


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(
        session_id="20260101T000000Z-testtest",
        agent_id="pytest",
        host_id="win01",
        directory=tmp_path / "logs",
    )


class FakeSession:
    """A Session-shaped object whose ``exec`` is scripted by the test.

    The engine only needs a small surface from a session, so faking it here lets
    the policy, templating, expectation and collection logic be tested without a
    single socket.
    """

    def __init__(
        self,
        inventory: Inventory,
        catalog: Catalog,
        host_id: str,
        *,
        responder: Callable[[str], ExecResult] | None = None,
        audit: AuditLog | None = None,
        allowed_operations: tuple[str, ...] = (),
    ) -> None:
        self.inventory = inventory
        self.catalog = catalog
        self.host_id = host_id
        self.host: Host = inventory.get(host_id)
        self.route = plan_route(inventory, host_id)
        self.session_id = "20260101T000000Z-testtest"
        self.agent_id = "pytest"
        self.audit = audit
        self.allowed_operations = allowed_operations
        self.commands: list[str] = []
        self._responder = responder or self._default_responder
        # Enough of the real Session's surface for preflight to inspect.
        self.ssh_hops: list[Any] = []
        self.idle_timeout_s = 1800
        self.idle_s = 0.0
        self.closed = False

    @property
    def default_shell(self) -> str:
        return "powershell" if self.host.is_windows else "bash"

    def _default_responder(self, command: str) -> ExecResult:
        return ExecResult(
            node_id=self.host_id,
            channel="fake",
            command=command,
            exit_code=0,
            stdout="ok",
        )

    def exec(self, command: str, *, shell: str | None = None, timeout_s: int = 600) -> ExecResult:
        self.commands.append(command)
        return self._responder(command)

    def permits(self, operation_id: str) -> bool:
        return not self.allowed_operations or operation_id in self.allowed_operations

    def touch(self) -> None:
        return None

    def require_active(self) -> None:
        return None


@pytest.fixture
def make_session(inventory: Inventory, catalog: Catalog) -> Callable[..., FakeSession]:
    def factory(host_id: str = "win01", **kwargs: Any) -> FakeSession:
        return FakeSession(inventory, catalog, host_id, **kwargs)

    return factory
