"""Command line interface.

``ac connect`` is the one command that must run in the operator's own terminal --
it is where every hop's password is typed.  Everything else is a thin client that
attaches to that session, so an agent can drive the work without ever handling a
credential.
"""

from __future__ import annotations

import json
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .audit import list_sessions, load_session
from .brief import load_brief, validate_brief
from .campaign import load_campaign, plan_campaign, run_campaign
from .config import load_all, load_inventory, load_operations
from .credentials import TerminalPrompter, WindowsCredUIPrompter, select_prompter
from .daemon import (
    EphemeralSession,
    SessionClient,
    SessionServer,
    attach,
    build_session,
    list_descriptors,
)
from .errors import AccessControlError
from .logging_setup import install_quiet_logging, record_unexpected
from .operator_shell import run_operator_shell
from .paths import config_dir, log_dir, session_dir
from .probe import probe_route, summarise
from .route import plan_hop_route, plan_route
from .transport.interactive import launch_rdp, launch_ssh_shell

app = typer.Typer(
    name="ac",
    help="Run audited operations on servers reached through a chain of bastion hosts.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err = Console(stderr=True)


def _fail(message: str, code: int = 1) -> None:
    err.print(f"[bold red]error:[/bold red] {message}")
    raise typer.Exit(code)


def _client_or_fail(host_id: str) -> SessionClient:
    client = attach(host_id)
    if client is None:
        _fail(
            f"no live session for '{host_id}'.\n\n"
            f"Passwords are never stored, so a session has to be opened by you, in your own "
            f"terminal:\n\n"
            f"    uv run ac connect {host_id}\n\n"
            f"Leave that window open; it holds the authenticated path until the task is done."
        )
    assert client is not None
    return client


def _emit(data: Any, as_json: bool) -> None:
    if as_json:
        console.print_json(json.dumps(data, default=str))


# --------------------------------------------------------------------------
# Inspection
# --------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Show the version."""
    console.print(f"access-control {__version__}")


@app.command()
def doctor() -> None:
    """Check this machine is ready: config, dependencies, keys, prompting."""
    table = Table(title="access-control preflight", show_header=True, header_style="bold")
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Detail", overflow="fold")

    problems = 0

    def row(name: str, ok: bool | None, detail: str) -> None:
        nonlocal problems
        if ok is False:
            problems += 1
        mark = "[green]ok[/green]" if ok else ("[yellow]warn[/yellow]" if ok is None else "[red]FAIL[/red]")
        table.add_row(name, mark, detail)

    row("python", True, sys.version.split()[0])

    for module in ("paramiko", "pypsrp", "yaml", "typer"):
        try:
            __import__(module)
            row(f"import {module}", True, "installed")
        except ImportError as exc:
            row(f"import {module}", False, f"{exc}. Run: uv sync")

    inventory_file = config_dir() / "inventory.yaml"
    if inventory_file.exists():
        row("inventory.yaml", True, str(inventory_file))
    else:
        row(
            "inventory.yaml",
            None,
            f"not found -- falling back to inventory.example.yaml. Create it with:\n"
            f"  copy config\\inventory.example.yaml config\\inventory.yaml",
        )

    try:
        inventory, catalog, warnings = load_all()
        row("config parse", True, f"{len(inventory.hosts)} hosts, {len(catalog.operations)} operations")
        for warning in warnings:
            row("config warning", None, warning)
    except AccessControlError as exc:
        row("config parse", False, str(exc))
        inventory = None  # type: ignore[assignment]

    if inventory is not None:
        for hop_id, hop in inventory.hops.items():
            key_file = hop.auth.key_file
            if key_file is None:
                continue
            if key_file.exists():
                from .transport.ssh import looks_like_putty_key

                if looks_like_putty_key(key_file):
                    row(f"key {hop_id}", False, f"{key_file} is a PuTTY .ppk -- see docs/runbook.md")
                else:
                    row(f"key {hop_id}", True, str(key_file))
            else:
                row(f"key {hop_id}", False, f"missing: {key_file}")

        for host_id in inventory.hosts:
            try:
                route = plan_route(inventory, host_id)
                row(f"route {host_id}", True, route.describe())
            except AccessControlError as exc:
                row(f"route {host_id}", False, str(exc))

    prompter = select_prompter()
    if prompter.name == "terminal":
        row("credential prompt", True, "interactive terminal (preferred)")
    elif prompter.name == "windows-dialog":
        row("credential prompt", True, "Windows credential dialog")
    else:
        row(
            "credential prompt",
            False,
            "no way to prompt. Run 'ac connect <host>' from a real terminal.",
        )

    row("mstsc (RDP)", shutil.which("mstsc") is not None, shutil.which("mstsc") or "not found")
    row("ssh client", shutil.which("ssh") is not None, shutil.which("ssh") or "not found")
    row("audit log dir", True, str(log_dir()))
    row("session dir", True, str(session_dir()))

    live = list_descriptors()
    row("live sessions", True, ", ".join(d.host_id for d in live) if live else "none")

    console.print(table)
    if problems:
        _fail(f"{problems} check(s) failed")
    console.print("[green]Ready.[/green]")


@app.command()
def hosts(json_out: bool = typer.Option(False, "--json", help="Emit JSON")) -> None:
    """List configured hosts and how each is reached."""
    inventory = load_inventory()
    rows = []
    for host_id, host in sorted(inventory.hosts.items()):
        try:
            route = plan_route(inventory, host_id).describe()
        except AccessControlError as exc:
            route = f"INVALID: {exc}"
        rows.append(
            {
                "host_id": host_id,
                "kind": host.kind,
                "address": host.host,
                "automation": host.automation,
                "route": route,
                "tags": list(host.tags),
                "description": host.description,
            }
        )

    if json_out:
        _emit(rows, True)
        return

    table = Table(show_header=True, header_style="bold")
    for column in ("host", "kind", "address", "channel", "route"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            row["host_id"], row["kind"], row["address"], row["automation"], row["route"]
        )
    console.print(table)


@app.command()
def ops(
    host: Optional[str] = typer.Option(None, "--host", "-h", help="Only operations for this host"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """List the configurable operation catalog."""
    inventory, catalog, _ = load_all()
    if host:
        target = inventory.get(host)
        operations = catalog.for_host(target)
    else:
        operations = list(catalog.operations.values())

    rows = [
        {
            "id": op.id,
            "description": op.description.strip(),
            "hosts": list(op.host_ids) or list(op.tags),
            "params": [p.name + ("" if p.required else "?") for p in op.params],
            "steps": [s.id for s in op.steps],
            "gated": op.is_gated,
            "destructive": op.destructive,
        }
        for op in operations
    ]

    if json_out:
        _emit(rows, True)
        return

    table = Table(show_header=True, header_style="bold")
    for column in ("operation", "applies to", "params", "steps", "gate"):
        table.add_column(column, overflow="fold")
    for row in rows:
        gate = "destructive" if row["destructive"] else ("approval" if row["gated"] else "-")
        table.add_row(
            row["id"],
            ", ".join(row["hosts"]),
            ", ".join(row["params"]) or "-",
            ", ".join(row["steps"]),
            gate,
        )
    console.print(table)
    if not json_out:
        console.print("\nEdit [bold]config/operations.yaml[/bold] to add or change operations.")


@app.command()
def routes(
    host: Optional[str] = typer.Argument(None, help="Resolve the route to this host"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Show declared connectivity, or resolve the route to one host.

    Routes are never discovered. Everything shown here was declared in
    inventory.yaml, and anything not shown here cannot be reached.
    """
    inventory = load_inventory()

    if host is None:
        rows = [edge.to_dict() for edge in inventory.graph.edges]
        if json_out:
            _emit(
                {
                    "declared_via": "routes" if inventory.routes_declared else "path shorthand",
                    "entry_points": inventory.graph.entry_points(),
                    "edges": rows,
                },
                True,
            )
            return
        source = "explicit routes:" if inventory.routes_declared else "compiled from path:"
        console.print(f"[dim]connectivity {source}[/dim]\n")
        table = Table(show_header=True, header_style="bold")
        for column in ("source", "target", "automation", "interactive", "domain"):
            table.add_column(column, overflow="fold")
        for edge in inventory.graph.edges:
            table.add_row(
                edge.source,
                edge.target,
                str(edge.automation) if edge.automation else "-",
                str(edge.interactive) if edge.interactive else "-",
                edge.domain or "-",
            )
        console.print(table)
        console.print(
            f"\nentry points (reachable from your machine): "
            f"{', '.join(inventory.graph.entry_points()) or 'none'}"
        )
        return

    try:
        resolved = plan_route(inventory, host)
    except AccessControlError as exc:
        _fail(str(exc))
        return

    if json_out:
        _emit({"channel": resolved.channel, **resolved.resolved.to_dict()}, True)
        return
    console.print(_raw_panel(resolved.describe_verbose(), f"route to {host}"))
    console.print(f"execution shape: [bold]{resolved.channel}[/bold]")


@app.command()
def probe(
    host: str = typer.Argument(..., help="Host id from inventory.yaml"),
    deep: bool = typer.Option(
        False, "--deep", help="Also ask the Windows jump server whether it can reach the target"
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Find out which channels actually work along a host's route.

    This is the command that decides the real path forward: it prompts for the
    bastion credentials, then reports what each machine on the way answers on.
    """
    inventory = load_inventory()
    session = build_session(host, inventory=inventory)
    try:
        report = probe_route(inventory, host, session.creds, audit=session.audit, deep=deep)
    except AccessControlError as exc:
        _fail(str(exc))
        return
    finally:
        session.creds.clear()

    if json_out:
        _emit(report, True)
        return
    console.print(_raw_panel(summarise(report), f"probe {host}"))


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


@app.command()
def connect(
    host: str = typer.Argument(..., help="Host id from inventory.yaml"),
    operations: Optional[str] = typer.Option(
        None,
        "--ops",
        help="Comma-separated operations to authorise for this session. "
        "Omit to allow every operation the catalog permits for this host.",
    ),
    idle_timeout: int = typer.Option(
        1800, "--idle-timeout", help="Seconds of inactivity before the session closes (0 = never)"
    ),
    no_shell: bool = typer.Option(
        False,
        "--no-shell",
        help="Hold the session open without a prompt. Use when the window is not "
        "yours to type in -- a service wrapper, or a log you want kept clean.",
    ),
    no_fallback: bool = typer.Option(
        False,
        "--no-fallback",
        help="Fail outright if the target leg fails, instead of holding the session "
        "at the last hop that authenticated.",
    ),
) -> None:
    """Open an authenticated session. Run this in your own terminal.

    You will be prompted for a password at every hop -- bastion, jump server, and
    target. Nothing is stored: the credentials live in this process only and are
    wiped when it exits.

    Leave this window open: it becomes a prompt on the host, and the prompt
    always names the machine the next command reaches. Other commands (yours, or
    an agent's) attach to this session by host id and never see a credential.

    If the last leg fails but a bastion did authenticate, the session is held
    there rather than thrown away -- so you can diagnose from the machine that
    was supposed to reach the target, and :retry without retyping anything.
    """
    install_quiet_logging()
    if attach(host) is not None:
        _fail(
            f"a session for '{host}' is already open.\n"
            f"Use it, or close it first with:  uv run ac disconnect {host}"
        )

    if not TerminalPrompter.available():
        err.print(
            "[yellow]warning:[/yellow] this is not an interactive terminal, so prompts will "
            + (
                "appear in a Windows credential dialog on your desktop."
                if WindowsCredUIPrompter.available()
                else "fail. Run this from a real terminal window."
            )
        )

    allowed = tuple(o.strip() for o in operations.split(",") if o.strip()) if operations else ()
    try:
        session = build_session(
            host,
            allowed_operations=allowed,
            idle_timeout_s=idle_timeout,
            fallback_to_hop=not no_fallback,
        )
    except AccessControlError as exc:
        _fail(str(exc))
        return

    console.print(
        Panel(
            f"[bold]{session.route.describe()}[/bold]\n\n"
            f"You will be asked for a password at each hop.\n"
            f"Nothing is stored -- these credentials exist only while this window is open.",
            title=f"connecting to {host}",
            expand=False,
        )
    )

    try:
        session.connect()
    except AccessControlError as exc:
        _fail(str(exc))
        return
    except KeyboardInterrupt:
        err.print("\n[yellow]cancelled.[/yellow] Nothing was stored.")
        raise typer.Exit(130) from None
    except Exception as exc:  # noqa: BLE001 - the operator gets one clean line
        # Anything that reaches here is a bug or a library failing in a way this
        # tool has no message for. Print the one line, keep the traceback.
        path = record_unexpected(exc, context=f"connect {host}")
        _fail(
            f"unexpected failure while connecting to '{host}': "
            f"{type(exc).__name__}: {exc}\n"
            + (f"Full traceback: {path}" if path else "")
        )
        return

    if session.degraded:
        console.print(
            Panel(
                f"[bold]{session.route.describe()}[/bold]\n\n"
                f"The leg to [bold]{host}[/bold] failed:\n"
                f"    {session.degraded_reason}\n\n"
                f"The chain up to [bold]{session.current_node.id}[/bold] "
                f"([bold]{session.prompt_label}[/bold]) did authenticate, so the session "
                f"is being held there rather than thrown away.\n"
                f"Diagnose from that machine -- it is the one that was supposed to reach "
                f"the target -- then run [bold]:retry[/bold] at the prompt. The hops stay "
                f"authenticated, so a retry costs no password.\n\n"
                f"[yellow]Operations and `ac exec` are refused while this session is a "
                f"fallback:[/yellow] they are written against {host}, and this is not it.",
                title=f"[yellow]fallback -- held at {session.current_node.id}[/yellow]",
                expand=False,
            )
        )

    started = threading.Event()

    def ready(descriptor: Any) -> None:
        where = (
            f"[yellow]{session.current_node.id} (fallback)[/yellow]"
            if session.degraded
            else f"[green]{host}[/green]"
        )
        console.print(
            Panel(
                f"session    [bold]{descriptor.session_id}[/bold]\n"
                f"route      {session.route.describe()}\n"
                f"on         {where}  ({session.prompt_label})\n"
                f"audit      {session.audit.path if session.audit else '-'}\n"
                f"operations {'none (fallback)' if session.degraded else (', '.join(allowed) or 'all permitted for this host')}\n\n"
                + (
                    "[green]Connected.[/green] Type commands at the prompt below; "
                    ":help lists the prompt's own commands.\n"
                    f"Close with :exit, or from another terminal:  uv run ac disconnect {host}"
                    if not no_shell
                    else "[green]Connected.[/green] Leave this window open.\n"
                    f"Close with Ctrl-C, or from another terminal:  "
                    f"uv run ac disconnect {host}"
                ),
                title="session open",
                expand=False,
            )
        )
        started.set()

    server = SessionServer(session, on_ready=ready)

    if no_shell:
        report = server.serve_forever()
        console.print(_status_panel(report, title=f"session closed ({report.get('status')})"))
        return

    # The socket server runs behind the prompt so agents can attach to the very
    # same session the operator is typing into -- one authenticated path, two
    # users of it.
    outcome: dict[str, Any] = {}

    def serve() -> None:
        try:
            outcome.update(server.serve_forever())
        except Exception as exc:  # noqa: BLE001 - a dead server must not be silent
            record_unexpected(exc, context=f"session server {host}")
            outcome["server_error"] = f"{type(exc).__name__}: {exc}"
            started.set()

    thread = threading.Thread(target=serve, name="ac-session-server", daemon=True)
    thread.start()
    started.wait(timeout=10)

    if outcome.get("server_error"):
        _fail(f"the session server did not start: {outcome['server_error']}")
        return

    try:
        status_name = run_operator_shell(session, console, err)
    except KeyboardInterrupt:
        status_name = "interrupted"
    except Exception as exc:  # noqa: BLE001 - never leave the chain up on a bug
        path = record_unexpected(exc, context=f"prompt {host}")
        err.print(
            f"[bold red]error:[/bold red] the prompt failed: {type(exc).__name__}: {exc}\n"
            + (f"Full traceback: {path}\n" if path else "")
            + "Closing the session."
        )
        status_name = "error"

    report = server.shutdown(status_name)
    thread.join(timeout=5)
    console.print(_status_panel(report, title=f"session closed ({report.get('status')})"))


@app.command()
def status(
    host: Optional[str] = typer.Argument(None, help="Host id; omit to list every live session"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Show live sessions, or one session's full status."""
    if host is None:
        descriptors = list_descriptors()
        if json_out:
            _emit(
                [
                    {"host_id": d.host_id, "session_id": d.session_id, "pid": d.pid, "agent_id": d.agent_id}
                    for d in descriptors
                ],
                True,
            )
            return
        if not descriptors:
            console.print("No live sessions. Open one with:  uv run ac connect <host>")
            return
        table = Table(show_header=True, header_style="bold")
        for column in ("host", "session", "pid", "agent"):
            table.add_column(column, overflow="fold")
        for d in descriptors:
            table.add_row(d.host_id, d.session_id, str(d.pid), d.agent_id)
        console.print(table)
        return

    client = _client_or_fail(host)
    report = client.call("status")
    if json_out:
        _emit(report, True)
        return
    console.print(_status_panel(report, title=f"session {host}"))


def _status_panel(report: dict[str, Any], title: str) -> Panel:
    lines = [
        f"host        {report.get('host_id')}",
        f"session     {report.get('session_id')}",
        f"agent       {report.get('agent_id')}",
        f"route       {report.get('route')}",
        f"connected   {report.get('connected')}",
        f"steps       {report.get('steps_ok', 0)} ok / {report.get('steps_failed', 0)} failed",
        f"elapsed     {report.get('elapsed_s')}s",
    ]
    if report.get("expires_in_s") is not None:
        lines.append(f"expires in  {report['expires_in_s']}s of inactivity")
    if report.get("log_file"):
        lines.append(f"audit       {report['log_file']}")
    if report.get("summary_file"):
        lines.append(f"summary     {report['summary_file']}")
    return Panel("\n".join(lines), title=title, expand=False)


@app.command()
def reload(
    host: str = typer.Argument(..., help="Host id"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Re-read operations.yaml into a live session, without reconnecting.

    Use this while iterating on an operation. Reconnecting would cost you a
    password at every hop; this does not. Refused if the host's route changed,
    because the live connection would no longer match the config.
    """
    client = _client_or_fail(host)
    try:
        result = client.call("reload")
    except AccessControlError as exc:
        _fail(str(exc))
        return

    if json_out:
        _emit(result, True)
        return
    console.print(f"[green]reloaded[/green] {len(result['operations'])} operations for {host}")
    if result.get("added"):
        console.print(f"  added:   {', '.join(result['added'])}")
    if result.get("removed"):
        console.print(f"  removed: {', '.join(result['removed'])}")
    for warning in result.get("warnings") or []:
        console.print(f"  [yellow]warning:[/yellow] {warning}")


@app.command()
def disconnect(
    host: str = typer.Argument(..., help="Host id"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Close a session, after printing its final status."""
    client = _client_or_fail(host)
    report = client.call("close")
    if json_out:
        _emit(report, True)
        return
    console.print(_status_panel(report, title=f"closing {host}"))
    console.print("[green]Session closing.[/green] Credentials wiped.")


# --------------------------------------------------------------------------
# Work
# --------------------------------------------------------------------------


def _parse_params(pairs: list[str] | None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for pair in pairs or []:
        if "=" not in pair:
            _fail(f"--param expects name=value, got '{pair}'")
        name, _, value = pair.partition("=")
        params[name.strip()] = value
    return params


@app.command()
def verify(
    host: str = typer.Argument(..., help="Host id with a live session"),
    expect_hostname: Optional[str] = typer.Option(
        None, "--expect-hostname", help="Fail unless the target reports this name"
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Check a live session: still connected, and on the machine you think.

    Run this before any real work, and again after anything that might have
    disturbed the path. The identity check is the important one -- every hop past
    the first arrives over a local port forward, and a port number carries no
    identity.
    """
    client = _client_or_fail(host)
    spec = {"expect_hostname": expect_hostname} if expect_hostname else {}
    result = client.call("preflight", spec=spec)

    if json_out:
        _emit(result, True)
    else:
        for check in result["checks"]:
            colour = "green" if check["passed"] else ("red" if check["severity"] == "fatal" else "yellow")
            mark = "ok" if check["passed"] else ("FAIL" if check["severity"] == "fatal" else "warn")
            console.print(f"[{colour}]{mark:>4}[/{colour}]  {check['name']}", end="  ")
            _raw(check["detail"], "dim")
            if not check["passed"] and check.get("remedy"):
                _raw(f"        -> {check['remedy']}", "yellow")
        console.print(
            "\n[green]All checks passed.[/green]"
            if result["ok"]
            else "\n[bold red]Checks failed -- do not start work.[/bold red]"
        )
    if not result["ok"]:
        raise typer.Exit(2)


brief_app = typer.Typer(
    help="Task briefs: the instruction document telling the agent what to do.",
    no_args_is_help=True,
)
app.add_typer(brief_app, name="brief")


@brief_app.command("show")
def brief_show(
    path: Path = typer.Argument(..., help="Path to the task brief YAML"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Render a brief for a human to read and approve."""
    try:
        brief = load_brief(path)
    except AccessControlError as exc:
        _fail(str(exc))
        return
    if json_out:
        _emit(brief.to_dict(), True)
        return
    console.print(_raw_panel(brief.render(), str(path)))


@brief_app.command("validate")
def brief_validate(
    path: Path = typer.Argument(..., help="Path to the task brief YAML"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Check a brief against the inventory and catalogue. Connects to nothing.

    Every operation must exist and be permitted on the host, every parameter must
    be declared, and the host must resolve to a route. Run this before the change
    window, not during it.
    """
    inventory, catalog, _ = load_all()
    try:
        brief = load_brief(path)
        warnings = validate_brief(brief, inventory, catalog)
    except AccessControlError as exc:
        if json_out:
            _emit({"ok": False, "error": str(exc)}, True)
            raise typer.Exit(2)
        _fail(str(exc))
        return

    if json_out:
        _emit({"ok": True, "warnings": warnings, "brief": brief.to_dict()}, True)
        return

    console.print(_raw_panel(brief.render(), f"{path} — valid"))
    for warning in warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    console.print(
        f"\n[green]Brief is executable.[/green] Run it with:\n"
        f"    uv run ac connect {brief.host}      # in your own terminal\n"
        f"    uv run ac brief run {path}"
    )


@brief_app.command("run")
def brief_run(
    path: Path = typer.Argument(..., help="Path to the task brief YAML"),
    confirm: bool = typer.Option(
        False, "--confirm", help="Approve the gated operations this brief contains"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Render everything, run nothing"),
    skip_preflight: bool = typer.Option(
        False, "--skip-preflight", help="Not recommended; preflight is the safety net"
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Execute a brief: preflight, then each operation in order, then report."""
    inventory, catalog, _ = load_all()
    try:
        brief = load_brief(path)
        warnings = validate_brief(brief, inventory, catalog)
    except AccessControlError as exc:
        _fail(str(exc))
        return

    for warning in warnings:
        err.print(f"[yellow]warning:[/yellow] {warning}")

    if dry_run:
        console.print(_raw_panel(brief.render(), f"{path} — dry run"))
        for step in brief.operations:
            console.print(f"\n[bold]would run:[/bold] {step.operation}")
            try:
                with _offline_engine(brief.host) as engine:
                    result = engine.run_operation(
                        step.operation, dict(step.params), dry_run=True,
                        start_at=step.start_at,
                        only_steps=list(step.only_steps) or None,
                    ).to_dict()
                _print_operation(result)
            except AccessControlError as exc:
                _fail(str(exc))
        return

    client = _client_or_fail(brief.host)

    # -- preflight ---------------------------------------------------------
    if not skip_preflight:
        report = client.call("preflight", spec=dict(brief.preflight))
        if not report["ok"]:
            for check in report["checks"]:
                if not check["passed"]:
                    _raw(f"  {check['name']}: {check['detail']}", "red")
                    if check.get("remedy"):
                        _raw(f"    -> {check['remedy']}", "yellow")
            _fail(
                f"preflight failed for brief '{brief.id}'. Nothing was run.\n"
                f"Fix the blockers above, or run `uv run ac verify {brief.host}` to re-check."
            )
            return
        console.print(f"[green]preflight passed[/green] ({len(report['checks'])} checks)")

    # -- operations --------------------------------------------------------
    results: list[dict[str, Any]] = []
    failed = False
    for index, step in enumerate(brief.operations, 1):
        console.print(f"\n[bold cyan]({index}/{len(brief.operations)}) {step.operation}[/bold cyan]")
        try:
            result = client.call(
                "run_operation",
                operation_id=step.operation,
                params=dict(step.params),
                confirmed=confirm,
                start_at=step.start_at,
                only_steps=list(step.only_steps) or None,
            )
        except AccessControlError as exc:
            _raw(str(exc), "red")
            failed = True
            break

        results.append(result)
        if not json_out:
            _print_operation(result)

        if not result.get("ok"):
            failed = True
            if step.on_failure == "continue":
                console.print("[yellow]continuing: on_failure is 'continue'[/yellow]")
                continue
            if step.on_failure == "rollback" and brief.rollback:
                console.print("[yellow]running rollback[/yellow]")
                for rb in brief.rollback:
                    results.append(
                        client.call(
                            "run_operation", operation_id=rb.operation,
                            params=dict(rb.params), confirmed=confirm,
                        )
                    )
            break
        if brief.rules.stop_on_first_failure and failed:
            break

    payload = {
        "brief_id": brief.id,
        "host": brief.host,
        "ok": not failed,
        "operations": results,
        "success_criteria": list(brief.success_criteria),
    }
    if json_out:
        _emit(payload, True)
    else:
        console.print(
            f"\n[bold]{brief.id}[/bold]: "
            + ("[green]completed[/green]" if not failed else "[red]stopped on failure[/red]")
        )
        if brief.success_criteria:
            console.print("\n[bold]Confirm before signing off:[/bold]")
            for criterion in brief.success_criteria:
                console.print(f"  [ ] {criterion}")
    if failed:
        raise typer.Exit(2)


# --------------------------------------------------------------------------
# Campaigns: run one brief across many hosts
# --------------------------------------------------------------------------


campaign_app = typer.Typer(
    help="Campaigns: fan one brief out across many hosts' live sessions.",
    no_args_is_help=True,
)
app.add_typer(campaign_app, name="campaign")


def _campaign_plan_or_fail(path: Path):
    """Load a campaign and validate every target's brief offline."""
    inventory, catalog, _ = load_all()
    try:
        campaign = load_campaign(path)
        plan, warnings = plan_campaign(campaign, inventory, catalog)
    except AccessControlError as exc:
        _fail(str(exc))
        raise  # unreachable; _fail raises
    return campaign, plan, warnings


def _session_hosts() -> set[str]:
    return {d.host_id for d in list_descriptors()}


@campaign_app.command("show")
def campaign_show(
    path: Path = typer.Argument(..., help="Path to the campaign YAML"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Render a campaign: its targets and the brief each runs."""
    try:
        campaign = load_campaign(path)
    except AccessControlError as exc:
        _fail(str(exc))
        return
    if json_out:
        _emit(
            {
                "id": campaign.id,
                "title": campaign.title,
                "targets": [
                    {"host": t.host, "brief": t.brief, "note": t.note} for t in campaign.targets
                ],
            },
            True,
        )
        return
    console.print(_raw_panel(campaign.render(), str(path)))


@campaign_app.command("validate")
def campaign_validate(
    path: Path = typer.Argument(..., help="Path to the campaign YAML"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Check every target's brief against the inventory and catalogue.

    Connects to nothing. Also reports, per host, whether a live session exists --
    a campaign only drives hosts that already have one.
    """
    campaign, plan, warnings = _campaign_plan_or_fail(path)
    live = _session_hosts()

    if json_out:
        _emit(
            {
                "ok": True,
                "campaign": campaign.id,
                "targets": [
                    {"host": pt.host, "brief_id": pt.brief.id, "session_live": pt.host in live}
                    for pt in plan
                ],
                "warnings": warnings,
            },
            True,
        )
        return

    console.print(_raw_panel(campaign.render(), f"{path} — valid"))
    table = Table(show_header=True, header_style="bold")
    for column in ("host", "brief", "session"):
        table.add_column(column, overflow="fold")
    for pt in plan:
        session = "[green]live[/green]" if pt.host in live else "[yellow]none — connect first[/yellow]"
        table.add_row(pt.host, pt.brief.id, session)
    console.print(table)
    for warning in warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    missing = [pt.host for pt in plan if pt.host not in live]
    if missing:
        console.print(
            f"\n[dim]{len(missing)} host(s) have no live session. Open each with "
            f"'uv run ac connect <host>' before running, or they will be skipped.[/dim]"
        )


@campaign_app.command("run")
def campaign_run(
    path: Path = typer.Argument(..., help="Path to the campaign YAML"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Render the plan, run nothing"),
    confirm: bool = typer.Option(False, "--confirm", help="Approve gated operations fleet-wide"),
    parallel: Optional[int] = typer.Option(
        None, "--parallel", help="Override the campaign's max_parallel"
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Run a campaign: dispatch each target's brief to that host's live session.

    Credentials are never handled here. Each host must already have a session
    (``uv run ac connect <host>``); hosts without one are skipped, not connected.
    """
    campaign, plan, warnings = _campaign_plan_or_fail(path)

    if dry_run:
        console.print(_raw_panel(campaign.render(), f"{path} — dry run"))
        for warning in warnings:
            console.print(f"[yellow]warning:[/yellow] {warning}")
        console.print("\n[dim]dry run: nothing was dispatched.[/dim]")
        return

    for warning in warnings:
        err.print(f"[yellow]warning:[/yellow] {warning}")

    def progress(kind: str, host: str, detail: str) -> None:
        if kind == "start":
            console.print(f"[cyan]▶ {host}[/cyan] running {detail}")
        elif kind == "skipped":
            console.print(f"[yellow]• {host} skipped[/yellow] ({detail})")
        elif kind == "done":
            colour = "green" if detail == "ok" else "red"
            console.print(f"[{colour}]✓ {host}[/{colour}] {detail}")

    report = run_campaign(
        campaign, plan, confirm=confirm, max_parallel=parallel, on_event=progress
    )

    if json_out:
        _emit(report.to_dict(), True)
    else:
        console.print(f"\n[bold]campaign {campaign.id}[/bold]")
        table = Table(show_header=True, header_style="bold")
        for column in ("host", "brief", "result", "detail"):
            table.add_column(column, overflow="fold")
        for r in report.results:
            colour = {"ok": "green", "skipped": "yellow"}.get(r.status, "red")
            table.add_row(r.host, r.brief_id, f"[{colour}]{r.status}[/{colour}]", r.detail)
        console.print(table)
        counts = ", ".join(f"{k}: {v}" for k, v in sorted(report.counts().items()))
        console.print(f"\n{counts}")

    if not report.ok:
        raise typer.Exit(2)


@app.command("run")
def run_operation(
    host: str = typer.Argument(..., help="Host id"),
    operation: str = typer.Argument(..., help="Operation id from operations.yaml"),
    param: Optional[list[str]] = typer.Option(None, "--param", "-p", help="name=value"),
    confirm: bool = typer.Option(False, "--confirm", help="Approve a gated operation"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Render the commands, run nothing"),
    only: Optional[str] = typer.Option(None, "--only", help="Comma-separated step ids to run"),
    start_at: Optional[str] = typer.Option(None, "--start-at", help="Resume from this step"),
    summary: bool = typer.Option(
        False, "--summary", help="Print the full end-to-end report instead of the step log"
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Run an operation on a host."""
    params = _parse_params(param)
    only_steps = [s.strip() for s in only.split(",")] if only else None

    client = attach(host)
    try:
        if client is not None:
            result = client.call(
                "run_operation",
                operation_id=operation,
                params=params,
                confirmed=confirm,
                dry_run=dry_run,
                only_steps=only_steps,
                start_at=start_at,
            )
        elif dry_run:
            # A dry run touches no server, so it needs no session at all.
            with _offline_engine(host) as engine:
                result = engine.run_operation(
                    operation, params, dry_run=True, only_steps=only_steps, start_at=start_at
                ).to_dict()
        else:
            _fail(
                f"no live session for '{host}'. Open one in your own terminal:\n"
                f"    uv run ac connect {host}"
            )
            return
    except AccessControlError as exc:
        _fail(str(exc))
        return

    if json_out:
        _emit(result, True)
    elif summary:
        _raw(result.get("summary", "(no summary produced)"))
    else:
        _print_operation(result)
    # Non-zero exit so a failed operation is visible to a shell, a CI job, or a
    # caller checking the return code rather than parsing the output.
    if not result.get("ok"):
        raise typer.Exit(2)


@app.command("preview")
def preview_operation(
    host: str = typer.Argument(..., help="Host id"),
    operation: str = typer.Argument(..., help="Operation id"),
    param: Optional[list[str]] = typer.Option(None, "--param", "-p", help="name=value"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Show exactly what an operation would run, without connecting."""
    params = _parse_params(param)
    try:
        with _offline_engine(host) as engine:
            result = engine.preview(operation, params)
    except AccessControlError as exc:
        _fail(str(exc))
        return

    if json_out:
        _emit(result, True)
        return

    console.print(f"[bold]{result['operation_id']}[/bold] on {result['host_id']}")
    console.print(f"route: {result['route']}")
    if result["requires_permission"]:
        console.print("[yellow]requires the operator's approval before it runs[/yellow]")
    for step in result["steps"]:
        # markup=False throughout: command text is full of square brackets
        # ([math]::Round, [IO.Path]) that Rich would otherwise eat as style
        # tags. The operator approves based on this text, so it must be exact.
        console.print(f"\n[{step['step_id']}] {step['desc']}", style="bold cyan", markup=False)
        if step["policy"] != "allowed":
            console.print(
                f"  ({step['policy']}: {step['policy_reason']})", style="yellow", markup=False
            )
        console.print(step["command"], style="dim", markup=False)


class _offline_engine:
    """Engine over an unconnected session, for previews and dry runs."""

    def __init__(self, host_id: str) -> None:
        self.host_id = host_id

    def __enter__(self):
        from .engine import Engine

        self.session = build_session(self.host_id)
        return Engine(self.session)

    def __exit__(self, *_exc: object) -> None:
        return None


@app.command("exec")
def exec_command(
    host: str = typer.Argument(..., help="Host id"),
    command: list[str] = typer.Argument(..., help="Command to run (use -- before it)"),
    shell: Optional[str] = typer.Option(None, "--shell", help="powershell | cmd | bash"),
    confirm: bool = typer.Option(False, "--confirm", help="Approve a gated command"),
    timeout: int = typer.Option(300, "--timeout", help="Seconds"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Run one ad-hoc command on a host."""
    client = _client_or_fail(host)
    try:
        result = client.call(
            "run_command",
            command=" ".join(command),
            shell=shell,
            confirmed=confirm,
            timeout_s=timeout,
        )
    except AccessControlError as exc:
        _fail(str(exc))
        return

    if json_out:
        _emit(result, True)
        return
    _print_result(result)


@app.command("logs")
def fetch_logs(
    host: str = typer.Argument(..., help="Host id"),
    path: str = typer.Option(..., "--path", help="File path or glob on the remote host"),
    tail: int = typer.Option(200, "--tail", help="Lines from the end"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Read the tail of a log file on a host."""
    client = _client_or_fail(host)
    result = client.call("fetch_log", path=path, tail=tail)
    if json_out:
        _emit(result, True)
        return
    _raw(result.get("stdout") or result.get("stderr") or "(empty)")


@app.command("upload")
def upload_file(
    host: str = typer.Argument(..., help="Host id"),
    local: Path = typer.Argument(..., help="Local file"),
    remote: str = typer.Argument(..., help="Destination path on the host"),
) -> None:
    """Copy a local file to a host."""
    if not local.exists():
        _fail(f"local file not found: {local}")
    client = _client_or_fail(host)
    result = client.call("upload", local_path=str(local.resolve()), remote_path=remote)
    console.print(f"[green]uploaded[/green] -> {result.get('uploaded')}")


@app.command("download")
def download_file(
    host: str = typer.Argument(..., help="Host id"),
    remote: str = typer.Argument(..., help="Path on the host"),
    local: Path = typer.Argument(..., help="Local destination"),
) -> None:
    """Copy a file from a host to this machine."""
    client = _client_or_fail(host)
    result = client.call("download", remote_path=remote, local_path=str(local.resolve()))
    console.print(f"[green]downloaded[/green] -> {result.get('downloaded')}")


# --------------------------------------------------------------------------
# Interactive handoff
# --------------------------------------------------------------------------


@app.command()
def rdp(
    node: str = typer.Argument(..., help="Host or hop id"),
    stage_credentials: bool = typer.Option(
        False,
        "--stage-credentials",
        help="Pre-fill the password via cmdkey instead of letting mstsc prompt. "
        "Off by default: letting Windows prompt keeps the password out of any process list.",
    ),
    full_screen: bool = typer.Option(False, "--full-screen"),
) -> None:
    """Open an interactive RDP session through the bastion chain.

    Use this when something genuinely needs a GUI, or to bootstrap a host where
    WinRM is off: log in once and run  Enable-PSRemoting -Force.
    """
    inventory = load_inventory()
    try:
        target = inventory.node(node)
        route = plan_hop_route(inventory, node)
    except AccessControlError as exc:
        _fail(str(exc))
        return

    if target.interactive != "rdp":
        _fail(
            f"'{node}' is not configured for RDP (interactive: {target.interactive}).\n"
            f"For a shell use:  uv run ac shell {node}"
        )

    client = attach(node)
    if client is not None:
        tunnel = client.call(
            "open_tunnel", dest_host=target.host, dest_port=target.rdp_port, purpose=f"rdp:{node}"
        )
        username = (client.call("credentials_for", node_id=node) or {}).get("username")
        _run_rdp(
            f"127.0.0.1:{tunnel['local_port']}",
            node,
            username or target.user,
            stage_credentials,
            full_screen,
        )
        client.call("close_tunnel", tunnel_id=tunnel["tunnel_id"])
        return

    # No session: build a temporary one just to carry the tunnel.
    console.print(f"No live session for '{node}'; opening a temporary one for the tunnel.")
    console.print(f"route: {route.describe()}")
    with EphemeralSession(node, inventory=inventory) as session:
        tunnel = session.open_tunnel(target.host, target.rdp_port, purpose=f"rdp:{node}")
        _run_rdp(tunnel.endpoint, node, target.user, stage_credentials, full_screen)


def _run_rdp(
    endpoint: str, node: str, username: str | None, stage: bool, full_screen: bool
) -> None:
    password = None
    if stage:
        password = select_prompter().ask_secret(
            f"RDP {node}", "password to stage for mstsc", username
        )
    console.print(f"Launching mstsc against {endpoint} (tunnelled to {node}) ...")
    session = launch_rdp(
        endpoint,
        target_label=node,
        username=username,
        password=password,
        stage_credentials=stage,
        full_screen=full_screen,
    )
    try:
        console.print("[dim]Waiting for the RDP window to close ...[/dim]")
        session.wait()
    except KeyboardInterrupt:
        pass
    finally:
        cleaned = session.cleanup()
        if cleaned:
            console.print(f"[dim]cleaned up: {', '.join(cleaned)}[/dim]")


@app.command()
def tunnel(
    node: str = typer.Argument(..., help="Host or hop id to forward to"),
    port: int = typer.Option(
        0, "--port", help="Local port to bind (0 = pick a free one)"
    ),
    remote_port: Optional[int] = typer.Option(
        None, "--remote-port", help="Port on the target (default: its declared one)"
    ),
) -> None:
    """Hold open a port forward to a node, for any client to use.

    The forward runs through the same authenticated bastion chain everything else
    uses. Point mRemoteNG, mstsc, a database client or a browser at the local
    port it prints. Ctrl-C closes it.

    Use this when you want the tunnel without the rest of the tooling -- it is
    the same mechanism `ac connect` uses internally, just exposed.
    """
    inventory = load_inventory()
    try:
        target = inventory.node(node)
        route = plan_hop_route(inventory, node)
    except AccessControlError as exc:
        _fail(str(exc))
        return

    leg = route.leg_for(node)
    if leg is None:
        _fail(f"no declared route leg for '{node}'")
        return
    dest_port = remote_port or leg.endpoint.port

    if leg.endpoint.preestablished:
        _fail(
            f"'{node}' is declared as a pre-established forward at "
            f"{leg.endpoint.hostname}:{leg.endpoint.port}, so there is nothing for this "
            f"command to build.\n"
            f"Either use that endpoint directly, or remove 'preestablished' from the route "
            f"and give the address as seen from {leg.source} so the tunnel can be built here."
        )
        return

    client = attach(node)
    if client is not None:
        info = client.call(
            "open_tunnel", dest_host=leg.endpoint.hostname, dest_port=dest_port,
            purpose=f"manual:{node}",
        )
        _hold_tunnel(f"127.0.0.1:{info['local_port']}", node, leg.endpoint.hostname, dest_port)
        client.call("close_tunnel", tunnel_id=info["tunnel_id"])
        return

    console.print(f"Opening a session to carry the tunnel ({route.describe()}) ...")
    with EphemeralSession(node, inventory=inventory) as session:
        forward = session.open_tunnel(leg.endpoint.hostname, dest_port, purpose=f"manual:{node}")
        if port and forward.local_port != port:
            console.print(
                f"[yellow]note:[/yellow] bound {forward.local_port}, not {port} "
                f"(the requested port was unavailable)"
            )
        _hold_tunnel(forward.endpoint, node, leg.endpoint.hostname, dest_port)
    del target


def _hold_tunnel(endpoint: str, node: str, dest_host: str, dest_port: int) -> None:
    console.print(
        Panel(
            f"[bold green]{endpoint}[/bold green]  ->  {dest_host}:{dest_port}  ({node})\n\n"
            f"Point any client at [bold]{endpoint}[/bold].\n"
            f"For RDP:   mstsc /v:{endpoint}\n"
            f"For SSH:   ssh -p {endpoint.split(':')[1]} <user>@127.0.0.1\n\n"
            f"Press Ctrl-C to close the tunnel.",
            title="tunnel open",
            expand=False,
        )
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[dim]tunnel closed[/dim]")


@app.command()
def shell(node: str = typer.Argument(..., help="Host or hop id")) -> None:
    """Open an interactive SSH shell through the bastion chain."""
    inventory = load_inventory()
    try:
        target = inventory.node(node)
    except AccessControlError as exc:
        _fail(str(exc))
        return

    client = attach(node)
    if client is not None:
        tunnel = client.call(
            "open_tunnel", dest_host=target.host, dest_port=target.port, purpose=f"shell:{node}"
        )
        try:
            launch_ssh_shell(
                "127.0.0.1", int(tunnel["local_port"]), username=target.user, target_label=node
            )
        finally:
            client.call("close_tunnel", tunnel_id=tunnel["tunnel_id"])
        return

    with EphemeralSession(node, inventory=inventory) as session:
        tunnel = session.open_tunnel(target.host, target.port, purpose=f"shell:{node}")
        launch_ssh_shell(
            "127.0.0.1", int(tunnel.local_port or 0), username=target.user, target_label=node
        )


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------


@app.command()
def audit(
    session_id: Optional[str] = typer.Argument(None, help="Session id; omit to list recent ones"),
    limit: int = typer.Option(20, "--limit"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Inspect the audit trail."""
    if session_id is None:
        sessions = list_sessions(limit=limit)
        if json_out:
            _emit(sessions, True)
            return
        if not sessions:
            console.print(f"No sessions recorded yet under {log_dir()}")
            return
        table = Table(show_header=True, header_style="bold")
        for column in ("session", "started", "host", "agent", "status", "steps"):
            table.add_column(column, overflow="fold")
        for entry in sessions:
            table.add_row(
                entry["session_id"],
                str(entry.get("started") or "-"),
                str(entry.get("host_id") or "-"),
                str(entry.get("agent_id") or "-"),
                str(entry.get("status")),
                f"{entry.get('steps_run', 0)} ({entry.get('steps_failed', 0)} failed)",
            )
        console.print(table)
        return

    records = load_session(session_id)
    if not records:
        _fail(f"no audit trail for session '{session_id}' under {log_dir()}")
    if json_out:
        _emit(records, True)
        return
    skip = {"timestamp", "event", "sessionId", "agentId", "seq"}
    for record in records:
        payload = {k: v for k, v in record.items() if k not in skip}
        console.print(f"[dim]{record.get('timestamp')}[/dim] [bold]{record.get('event')}[/bold]")
        _raw(f"    {payload}", "dim")


@app.command()
def timeline(
    session_id: str = typer.Argument(..., help="Session trace id (see `ac audit`)"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Show a session's execution trace: what happened, in order, with timings.

    The fastest way to answer "how far did it get, and where did it slow down"
    after a failure.
    """
    records = load_session(session_id)
    if not records:
        _fail(f"no audit trail for session '{session_id}' under {log_dir()}")

    # Same precedence as AuditLog.timeline(); `detail` is what the action itself
    # chose to surface, so it wins over the fallbacks.
    entries = [
        {
            "timestamp": r.get("timestamp"),
            "action": r.get("action"),
            "source": r.get("source"),
            "target": r.get("target"),
            "result": r.get("result"),
            "detail": (
                r.get("detail")
                or r.get("endpoint")
                or r.get("step_id")
                or r.get("operation_id")
                or ""
            ),
            "duration_s": r.get("duration_s"),
        }
        for r in records
        if r.get("action")
    ]

    if json_out:
        _emit(entries, True)
        return
    if not entries:
        console.print("No actions recorded in this session.")
        return
    for entry in entries:
        stamp = str(entry["timestamp"] or "")[11:19]
        arrow = f" {entry['source']} -> {entry['target']}" if entry.get("target") else ""
        detail = f"  {entry['detail']}" if entry["detail"] else ""
        duration = f" ({entry['duration_s']}s)" if entry.get("duration_s") else ""
        colour = "green" if entry.get("result") == "SUCCESS" else "red"
        console.print(
            f"[dim]{stamp}[/dim]  [{colour}]{entry['action']:<20}[/{colour}]", end=""
        )
        _raw(f"{arrow}{detail}{duration}")


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _raw_panel(body: str, title: str) -> Panel:
    """A panel whose body is NOT markup-parsed.

    Brief and probe output contains square brackets -- `[on failure: stop]`,
    `[math]::Round` -- which Rich would silently swallow as style tags. An
    operator approving a brief has to see it verbatim.
    """
    return Panel(Text(body), title=title, expand=False)


def _raw(text: str, style: str = "") -> None:
    """Print text that came from a remote machine or a script body.

    Always ``markup=False``: remote output and PowerShell scripts are full of
    square brackets that Rich would silently swallow as style tags, and an
    operator approving a command needs to see it verbatim.
    """
    console.print(text, style=style or None, markup=False)


def _print_result(result: dict[str, Any]) -> None:
    ok = result.get("ok")
    console.print(
        f"[{'green' if ok else 'red'}]exit {result.get('exit_code')}[/] "
        f"in {result.get('duration_s')}s on {result.get('node_id')} "
        f"via {result.get('channel')}"
    )
    if result.get("stdout"):
        _raw(result["stdout"])
    for stream in ("ps_errors", "stderr"):
        value = result.get(stream)
        if value:
            _raw("\n".join(value) if isinstance(value, list) else value, "red")
    for stream, colour in (("ps_warnings", "yellow"), ("ps_verbose", "dim")):
        for line in result.get(stream) or []:
            _raw(line, colour)


def _print_operation(result: dict[str, Any]) -> None:
    status_colour = "green" if result.get("ok") else "red"
    console.print(
        f"[bold]{result.get('operation_id')}[/bold] on {result.get('host_id')}: "
        f"[{status_colour}]{result.get('status')}[/{status_colour}] "
        f"in {result.get('duration_s')}s"
    )
    for step in result.get("steps", []):
        colour = {"ok": "green", "dry-run": "cyan", "skipped": "dim"}.get(step["status"], "red")
        console.print(
            f"\n[bold]\\[{step['step_id']}][/bold] {step.get('desc', '')} "
            f"-> [{colour}]{step['status']}[/{colour}]"
        )
        if step.get("expectation_reason"):
            _raw(f"  {step['expectation_reason']}", "red" if not step.get("ok") else "dim")
        if step.get("stdout"):
            _raw(step["stdout"], "dim")
        for line in step.get("ps_errors") or []:
            _raw(f"  {line}", "red")
        for entry in step.get("collected_logs") or []:
            console.print(f"\n  [bold yellow]collected: {entry.get('source')}[/bold yellow]")
            _raw(entry.get("content") or entry.get("error") or "", "dim")
        if step.get("hint"):
            console.print("\n  [bold cyan]hint:[/bold cyan]", end=" ")
            _raw(str(step["hint"]))
    if result.get("next_action"):
        console.print(f"\n[bold]next:[/bold] {result['next_action']}")
    if result.get("summary_file"):
        console.print(f"\n[dim]end-to-end summary: {result['summary_file']}[/dim]")


def main() -> None:
    # Before anything can open a socket: otherwise Paramiko's logging falls
    # through to logging.lastResort and prints protocol chatter to stderr, in
    # the middle of whatever prompt is on screen.
    install_quiet_logging()
    try:
        app()
    except AccessControlError as exc:
        err.print(f"[bold red]error:[/bold red] {exc}")
        raise SystemExit(1) from exc
    except KeyboardInterrupt:
        err.print("\n[yellow]cancelled.[/yellow]")
        raise SystemExit(130) from None
    except (typer.Exit, SystemExit):
        raise
    except Exception as exc:  # noqa: BLE001 - one clean line, traceback on disk
        path = record_unexpected(exc, context=" ".join(sys.argv[1:]))
        err.print(
            f"[bold red]error:[/bold red] {type(exc).__name__}: {exc}\n"
            + (f"Full traceback: {path}" if path else "")
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
