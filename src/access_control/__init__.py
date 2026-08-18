"""Multi-hop bastion automation utility.

Lets an agent (or a human) reach servers through a chain of jump hosts and run
audited, permission-gated operations on them.

Design summary
--------------
A *hop* is any machine on the path (bastion, jump server).  A *host* is a final
target that operations run against.  Every host declares the ordered ``path`` of
hops used to reach it.

Automation never uses RDP -- RDP carries pixels, not exit codes.  Windows hosts
are driven over PowerShell Remoting (WinRM) tunnelled through the SSH chain, and
the last Windows-to-Windows leg uses ``Invoke-Command`` with explicit
credentials.  RDP is provided only for handing an interactive session to a human.

Credentials are never stored.  They are prompted for at each hop, held in the
memory of the session process, and wiped on disconnect.
"""

__version__ = "0.1.0"

APP_NAME = "access_control"

__all__ = ["__version__", "APP_NAME"]
