"""Live capability probing.

Which channels a host actually offers is a question about the network, not about
the config file, and getting it wrong wastes an operator's time on a path that
was never going to work.  ``ac probe`` opens the SSH chain and asks the bastion
what it can reach, then reports the channel each node can really be driven over.

The important outcome is the WinRM verdict.  If 5985 is closed on the jump
server, no amount of configuration helps and the bootstrap is:

    uv run ac rdp <jump>        # a human logs in once
    Enable-PSRemoting -Force

after which every later run is fully automated.
"""

from __future__ import annotations

import time
from typing import Any

from .audit import EV_PROBE, AuditLog
from .config import Inventory, Node
from .credentials import CredentialStore
from .errors import AccessControlError
from .route import CHANNEL_NESTED_WINRM, CHANNEL_SSH, Route, plan_route
from .transport.pshell import quote_single
from .transport.ssh import SSHHop, connect_chain
from .transport.tunnel import (
    LocalTunnel,
    forwarding_permitted,
    port_open_direct,
    port_open_via,
)
from .transport.winrm import WinRMChannel

#: Probed on every node.  Names are what the report shows the operator.
PORTS = {
    "ssh": 22,
    "wmi-dcom": 135,
    "smb": 445,
    "rdp": 3389,
    "winrm-http": 5985,
    "winrm-https": 5986,
}

#: The port each execution channel needs, best first.
CHANNEL_REQUIREMENTS = (
    ("winrm", "winrm-http"),
    ("winrm-ssl", "winrm-https"),
    ("ssh", "ssh"),
    ("wmi", "wmi-dcom"),
)


def _probe_ports(hop: SSHHop | None, host: str, ports: dict[str, int], timeout: float) -> dict[str, bool]:
    results: dict[str, bool] = {}
    for name, port in ports.items():
        if hop is None:
            results[name] = port_open_direct(host, port, timeout)
        else:
            results[name] = port_open_via(hop, host, port, timeout)
    return results


def _recommend(node: Node, open_ports: dict[str, bool]) -> dict[str, Any]:
    """Turn open ports into a recommendation the operator can act on."""
    usable = [channel for channel, port_name in CHANNEL_REQUIREMENTS if open_ports.get(port_name)]
    configured = node.automation
    interactive_ok = open_ports.get("rdp", False)

    if configured in usable:
        verdict, advice = "ok", ""
    elif usable:
        verdict = "change-config"
        advice = (
            f"configured automation is '{configured}' but that port is closed. "
            f"Set automation: {usable[0]} for '{node.id}' in inventory.yaml."
        )
    elif interactive_ok and node.is_windows:
        verdict = "bootstrap-needed"
        advice = (
            f"no automation channel is open, but RDP (3389) is. Bootstrap it once:\n"
            f"    uv run ac rdp {node.id}\n"
            f"then in that session run:  Enable-PSRemoting -Force"
        )
    else:
        verdict = "unreachable"
        advice = (
            f"nothing answered on {node.host}. Check the address in inventory.yaml, and "
            f"whether the bastion is permitted to reach it at all."
        )

    return {
        "usable_channels": usable,
        "configured_channel": configured,
        "verdict": verdict,
        "advice": advice,
        "interactive_rdp": interactive_ok,
    }


def probe_route(
    inventory: Inventory,
    host_id: str,
    creds: CredentialStore,
    *,
    audit: AuditLog | None = None,
    deep: bool = False,
    timeout: float = 6.0,
) -> dict[str, Any]:
    """Probe every node on ``host_id``'s route and report what works.

    ``deep`` additionally authenticates to a Windows jump server and asks *it*
    whether the target is reachable -- necessary because a target behind a jump
    server is usually invisible from the bastion, so a shallow probe would
    report it unreachable when the real path is fine.
    """
    route: Route = plan_route(inventory, host_id)
    started = time.monotonic()
    report: dict[str, Any] = {
        "host_id": host_id,
        "route": route.describe(),
        "channel": route.channel,
        "nodes": [],
        "deep": deep,
    }

    hops: list[SSHHop] = []
    try:
        # Reachability of each SSH hop, checked from the hop before it, using the
        # address declared for that leg rather than the node's own default.
        ssh_legs = route.ssh_legs
        if route.channel == CHANNEL_SSH:
            ssh_legs = ssh_legs[:-1]

        for leg in ssh_legs:
            node = leg.node
            previous = hops[-1] if hops else None
            address, port = leg.endpoint.hostname, leg.endpoint.port
            entry: dict[str, Any] = {
                "id": node.id,
                "role": "bastion",
                "address": f"{address}:{port}",
                "context": node.context.describe(),
                "preestablished": leg.endpoint.preestablished,
            }
            entry["ports"] = {
                "ssh": (
                    port_open_direct(address, port, timeout)
                    if previous is None or leg.endpoint.preestablished
                    else port_open_via(previous, address, port, timeout)
                )
            }
            # Recorded before authentication is attempted, and updated in place
            # afterwards. Proving a bastion is reachable is a useful result on
            # its own -- losing it because the password prompt was declined
            # would report "nothing was found" when TCP plainly worked.
            report["nodes"].append(entry)

            if not entry["ports"]["ssh"]:
                entry["verdict"] = "unreachable"
                entry["advice"] = (
                    f"cannot open a TCP connection to {address}:{port}"
                    + ("" if previous is None else f" from {previous.node_id}")
                    + (
                        ". This hop is declared as a pre-established forward, so start "
                        "that tunnel first."
                        if leg.endpoint.preestablished
                        else ". Check the address, the port, and whether you are on the VPN."
                    )
                )
                report["blocked_at"] = node.id
                return _finish(report, started, audit)

            try:
                hops.extend(
                    connect_chain([node], creds, audit=audit, endpoints=[leg.endpoint])
                )
            except AccessControlError as exc:
                entry["verdict"] = "reachable-not-authenticated"
                entry["authenticated"] = False
                entry["advice"] = (
                    f"TCP to {address}:{port} works, but authentication did not "
                    f"complete: {exc}"
                )
                report["blocked_at"] = node.id
                raise

            entry["verdict"] = "ok"
            entry["authenticated"] = True

            # The decisive question for every hop after this one. A bastion that
            # will not forward makes the whole chain impossible, and the failure
            # would otherwise look like an unreachable target.
            permitted, explanation = forwarding_permitted(hops[-1], timeout)
            entry["forwarding_permitted"] = permitted
            entry["forwarding_detail"] = explanation
            if not permitted:
                entry["verdict"] = "forwarding-blocked"
                entry["advice"] = explanation
                report["blocked_at"] = node.id
                report["forwarding_blocked_at"] = node.id
                return _finish(report, started, audit)

        origin = hops[-1] if hops else None

        # Windows jump servers and the target, probed from the last SSH hop.
        for leg in route.legs:
            node = leg.node
            if any(existing["id"] == node.id for existing in report["nodes"]):
                continue
            if leg.is_ssh and node.id == route.host.id:
                ports = {"ssh": leg.endpoint.port}
            else:
                ports = dict(PORTS)
                ports[leg.endpoint.protocol] = leg.endpoint.port
            probe_from = None if leg.endpoint.preestablished else origin
            open_ports = _probe_ports(probe_from, leg.endpoint.hostname, ports, timeout)
            entry = {
                "id": node.id,
                "role": "target" if node.id == route.host.id else "jump",
                "address": f"{leg.endpoint.hostname}:{leg.endpoint.port}",
                "probed_from": (probe_from.node_id if probe_from else "local"),
                "context": node.context.describe(),
                "preestablished": leg.endpoint.preestablished,
                "ports": open_ports,
                **_recommend(node, open_ports),
            }
            report["nodes"].append(entry)

        if deep and route.channel == CHANNEL_NESTED_WINRM:
            report["deep_result"] = _deep_probe(route, hops, creds, timeout)

    except AccessControlError as exc:
        report["error"] = str(exc)
    finally:
        for hop in reversed(hops):
            hop.close()

    return _finish(report, started, audit)


def _deep_probe(
    route: Route, hops: list[SSHHop], creds: CredentialStore, timeout: float
) -> dict[str, Any]:
    """Ask the Windows jump server whether it can reach the target.

    A target behind a jump server is normally invisible from the bastion, so this
    is the only honest way to answer "will the nested leg work?".
    """
    jump = route.windows_hops[0]
    jump_leg = route.leg_for(jump.id)
    final_leg = route.final_leg
    assert jump_leg is not None
    origin = hops[-1]

    tunnel: LocalTunnel | None = None
    channel: WinRMChannel | None = None
    try:
        if jump_leg.endpoint.preestablished:
            connect_host, connect_port = jump_leg.endpoint.hostname, jump_leg.endpoint.port
        else:
            tunnel = LocalTunnel(origin, jump_leg.endpoint.hostname, jump_leg.endpoint.port)
            tunnel.start()
            connect_host, connect_port = "127.0.0.1", int(tunnel.local_port or 0)

        cred = creds.acquire(
            jump.id,
            label=f"Jump server {jump.description or jump.id} "
            f"[{jump.qualified_user or ''}@{jump_leg.endpoint.hostname}]",
            username=jump.qualified_user,
            need_password=True,
            prompt_username=not jump.user,
            domain=jump.domain,
        )
        channel = WinRMChannel(
            jump.id,
            connect_host,
            connect_port,
            username=cred.username or "",
            password=cred.password or "",
            auth=jump.auth.transport,
            display_target=f"{jump_leg.endpoint.hostname}:{jump_leg.endpoint.port}",
        ).connect()

        target = route.host
        target_host = final_leg.endpoint.hostname
        script = (
            f"$r = Test-NetConnection -ComputerName {quote_single(target_host)} "
            f"-Port {final_leg.endpoint.port} -WarningAction SilentlyContinue; "
            f"\"winrm={{0}}\" -f $r.TcpTestSucceeded; "
            f"$r2 = Test-NetConnection -ComputerName {quote_single(target_host)} "
            f"-Port {target.rdp_port} -WarningAction SilentlyContinue; "
            f"\"rdp={{0}}\" -f $r2.TcpTestSucceeded"
        )
        result = channel.exec(script, timeout_s=int(timeout * 10) + 60)
        text = result.stdout
        return {
            "from": jump.id,
            "to": target_host,
            "winrm_reachable": "winrm=True" in text,
            "rdp_reachable": "rdp=True" in text,
            "raw": text.strip(),
            "advice": (
                ""
                if "winrm=True" in text
                else (
                    f"{jump.id} cannot reach {target_host}:{final_leg.endpoint.port}. Either "
                    f"WinRM is disabled on the target, or a firewall between them blocks it. "
                    f"From an RDP session on {jump.id}: Enable-PSRemoting -Force on the target."
                )
            ),
        }
    except AccessControlError as exc:
        return {"from": jump.id, "error": str(exc)}
    finally:
        if channel is not None:
            channel.close()
        if tunnel is not None:
            tunnel.stop()


def _finish(report: dict[str, Any], started: float, audit: AuditLog | None) -> dict[str, Any]:
    report["duration_s"] = round(time.monotonic() - started, 2)
    if audit is not None:
        audit.emit(EV_PROBE, **report)
    return report


def summarise(report: dict[str, Any]) -> str:
    """Plain-text rendering for the CLI."""
    lines = [f"Route: {report['route']}", ""]
    for node in report.get("nodes", []):
        ports = node.get("ports", {})
        open_names = [name for name, is_open in ports.items() if is_open] or ["none"]
        marker = " [pre-established tunnel]" if node.get("preestablished") else ""
        lines.append(
            f"  {node['id']:<16} {node.get('role', ''):<8} {node.get('address', ''):<24} "
            f"open: {', '.join(open_names)}{marker}"
        )
        if "forwarding_permitted" in node:
            state = "yes" if node["forwarding_permitted"] else "NO"
            lines.append(f"      tcp forwarding: {state}")
        if node.get("advice"):
            for line in node["advice"].splitlines():
                lines.append(f"      {line}")
    deep = report.get("deep_result")
    if deep:
        lines += ["", f"  From {deep.get('from')} to the target: {deep.get('raw', deep.get('error', ''))}"]
        if deep.get("advice"):
            lines.append(f"      {deep['advice']}")
    if report.get("error"):
        lines += ["", f"  error: {report['error']}"]
    return "\n".join(lines)
