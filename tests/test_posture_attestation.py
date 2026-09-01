"""Phase 4: a posture attestation covering ac operations verifies (governance).

The governance layer builds a signed, per-org posture attestation from the
receipt ledger. When ac drives that ledger through the LighthouseGatekeeper,
the attestation for the `access-control` org must (a) count ac's own actions —
`session_open`, `remote_exec`, `permission_request` — proving the receipt-v1.1
vocabulary flows all the way into the governance artefact, and (b) verify with
the standalone `al-verify`, needing no runtime.

Needs the [lighthouse] extra plus al-governance (dev group); a plain install
skips.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("al_core", reason="requires the [lighthouse] extra")
pytest.importorskip("al_governance", reason="requires al-governance (dev group)")

from al_governance.attestation import build_attestation  # noqa: E402
from al_verify.verify import verify_attestation  # noqa: E402

from access_control.gatekeeper import LighthouseGatekeeper  # noqa: E402

ORG = "access-control"


@pytest.fixture
def driven_gatekeeper(tmp_path: Path):
    """A gatekeeper whose ledger already carries a spread of ac actions."""
    gk = LighthouseGatekeeper(data_dir=tmp_path / "al-data")
    for action, result in (
        ("SESSION_START", "SUCCESS"),
        ("SSH_CONNECT", "SUCCESS"),
        ("COMMAND_EXECUTE", "SUCCESS"),
        ("PERMISSION_REQUEST", "BLOCKED"),
        ("COMMAND_BLOCKED", "BLOCKED"),
        ("SESSION_END", "SUCCESS"),
    ):
        gk.receipt(agentId="AGT-attest", sessionId="SES-attest",
                   action=action, result=result, target="win01")
    yield gk
    gk.close()


def test_the_attestation_counts_ac_operations(driven_gatekeeper) -> None:
    att = build_attestation(driven_gatekeeper._runtime, ORG)
    by_action = att["evidence"]["by_action"]
    # the receipt-v1.1 remote-execution vocabulary reached the artefact
    assert by_action.get("session_open", 0) >= 2   # SESSION_START + SSH_CONNECT
    assert by_action.get("remote_exec", 0) >= 2     # COMMAND_EXECUTE + COMMAND_BLOCKED
    assert by_action.get("permission_request", 0) >= 1
    assert by_action.get("session_close", 0) >= 1


def test_the_attestation_verifies_with_the_standalone_verifier(driven_gatekeeper) -> None:
    att = build_attestation(driven_gatekeeper._runtime, ORG)
    # raises on any failure; returns the record_hash on success
    record_hash = verify_attestation(att, driven_gatekeeper.public_key)
    assert record_hash == att["record_hash"]


def test_tampering_with_a_count_breaks_verification(driven_gatekeeper) -> None:
    from al_verify.verify import VerificationError

    att = build_attestation(driven_gatekeeper._runtime, ORG)
    att["evidence"]["by_action"]["remote_exec"] = 999
    with pytest.raises(VerificationError):
        verify_attestation(att, driven_gatekeeper.public_key)


def test_the_attestation_quotes_the_chain_head_it_was_cut_from(driven_gatekeeper) -> None:
    att = build_attestation(driven_gatekeeper._runtime, ORG)
    assert att["chain"]["verified"] is True
    assert att["chain"]["head"], "the attestation must tie back to the ledger head"
