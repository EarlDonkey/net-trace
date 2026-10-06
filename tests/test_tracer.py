"""Tests for net_trace.tracer."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from net_trace.tracer import (
    HopResult,
    TraceUnavailable,
    _resolve_target,
    _reverse_dns,
    trace,
)


def test_hop_to_dict_includes_addr_and_hostname() -> None:
    hop = HopResult(hop=3, rtts_ms=[1.234, 1.5], addr="1.2.3.4", hostname="r1.example")
    d = hop.to_dict()
    assert d["hop"] == 3
    assert d["addr"] == "1.2.3.4"
    assert d["hostname"] == "r1.example"
    assert d["rtts_ms"] == [1.234, 1.5]


def test_hop_to_dict_omits_missing() -> None:
    hop = HopResult(hop=1, rtts_ms=[0.0])
    d = hop.to_dict()
    assert "addr" not in d
    assert "hostname" not in d


def test_is_timeout_true_when_no_addr() -> None:
    assert HopResult(hop=1).is_timeout


def test_resolve_target_success() -> None:
    with patch("socket.gethostbyname", return_value="1.2.3.4"):
        assert _resolve_target("example.com") == "1.2.3.4"


def test_resolve_target_failure_raises() -> None:
    with patch("socket.gethostbyname", side_effect=socket.gaierror):
        with pytest.raises(TraceUnavailable, match="could not resolve"):
            _resolve_target("nope.invalid")


def test_reverse_dns_success() -> None:
    with patch("socket.gethostbyaddr", return_value=("host.example", [], ["1.2.3.4"])):
        assert _reverse_dns("1.2.3.4") == "host.example"


def test_reverse_dns_failure_returns_none() -> None:
    with patch("socket.gethostbyaddr", side_effect=socket.herror):
        assert _reverse_dns("1.2.3.4") is None


def _fake_scapy_with_replies(replies: list[str | None]) -> MagicMock:
    """Build a fake scapy module whose sr1() returns a queue of replies."""
    scapy = MagicMock()
    reply_objs = []
    for src in replies:
        if src is None:
            reply_objs.append(None)
        else:
            r = MagicMock()
            r.src = src
            reply_objs.append(r)
    scapy.sr1.side_effect = reply_objs
    scapy.IP.return_value = MagicMock()
    scapy.ICMP.return_value = MagicMock()
    scapy.TCP.return_value = MagicMock()
    return scapy


def test_trace_stops_at_destination() -> None:
    # Hop 1 → 10.0.0.1, Hop 2 → destination. 1 probe each.
    fake = _fake_scapy_with_replies(["10.0.0.1", "1.2.3.4"])

    with (
        patch("net_trace.tracer._require_scapy", return_value=(fake, MagicMock())),
        patch("net_trace.tracer._resolve_target", return_value="1.2.3.4"),
        patch("net_trace.tracer._reverse_dns", return_value=None),
    ):
        hops = trace("example.com", probes=1, max_hops=10)

    assert len(hops) == 2
    assert hops[0].addr == "10.0.0.1"
    assert hops[1].addr == "1.2.3.4"


def test_trace_handles_timeouts() -> None:
    # All probes timeout → hops have no addr.
    fake = _fake_scapy_with_replies([None, None, None])

    with (
        patch("net_trace.tracer._require_scapy", return_value=(fake, MagicMock())),
        patch("net_trace.tracer._resolve_target", return_value="1.2.3.4"),
        patch("net_trace.tracer._reverse_dns", return_value=None),
    ):
        hops = trace("example.com", probes=1, max_hops=3)

    assert len(hops) == 3
    assert all(h.addr is None for h in hops)