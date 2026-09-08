"""Remote output must never kill the CLI on a legacy Windows code page.

A Windows console defaults to cp1252. Any byte a remote machine sends that
cp1252 cannot represent -- a signer name like "Martin Prikryl" with its
caron, an installer log in any non-Latin-1 language -- used to raise
UnicodeEncodeError from inside Rich's writer, which aborted the command and
discarded every line that had not been flushed yet.
"""

from __future__ import annotations

import io
import sys

import pytest

from access_control import cli


class _Cp1252Stream(io.TextIOWrapper):
    """A stdout that encodes as cp1252, the way a stock Windows console does."""

    def __init__(self) -> None:
        super().__init__(io.BytesIO(), encoding="cp1252", errors="strict")


def test_console_streams_survive_uncodable_characters(monkeypatch):
    stream = _Cp1252Stream()
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", stream)

    cli._soften_console_encoding()

    stream.write("Martin P\u0159ikryl")
    stream.flush()


def test_soften_is_a_no_op_when_the_stream_cannot_be_reconfigured(monkeypatch):
    """A pytest-captured or piped stdout may not expose reconfigure()."""

    class _Plain:
        pass

    monkeypatch.setattr(sys, "stdout", _Plain())
    monkeypatch.setattr(sys, "stderr", _Plain())

    cli._soften_console_encoding()  # must not raise
