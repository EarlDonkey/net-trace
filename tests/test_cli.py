"""Tests for net_trace.cli."""

from __future__ import annotations

import json
from unittest.mock import patch

from net_trace.cli import main
from net_trace.tracer import HopResult


def _patch_hops(hops):
    return patch("net_trace.cli.trace", return_value=hops)


def _patch_resolve(ip="1.2.3.4"):
    return patch("net_trace.cli._resolve_target", return_value=ip)


def test_human_output(capsys) -> None:
    hops = [
        HopResult(hop=1, rtts_ms=[1.2], addr="10.0.0.1"),
        HopResult(hop=2, rtts_ms=[5.6], addr="1.2.3.4"),
    ]

    with _patch_resolve(), _patch_hops(hops):
        code = main(["example.com", "-q", "1"])

    out = capsys.readouterr().out
    assert code == 0
    assert "Tracing route to example.com (1.2.3.4)" in out
    assert "10.0.0.1" in out
    assert "1.2.3.4" in out
    assert "2 hops" in out


def test_json_output(capsys) -> None:
    hops = [HopResult(hop=1, rtts_ms=[1.2], addr="10.0.0.1")]

    with _patch_resolve(), _patch_hops(hops):
        code = main(["example.com", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["target"] == "example.com"
    assert payload["resolved"] == "1.2.3.4"
    assert payload["hops"][0]["addr"] == "10.0.0.1"


def test_timeout_hop_renders_star(capsys) -> None:
    hops = [HopResult(hop=1, rtts_ms=[0.0])]

    with _patch_resolve(), _patch_hops(hops):
        main(["example.com", "-q", "1"])

    out = capsys.readouterr().out
    assert "*" in out


def test_invalid_max_hops_exits_bad_args() -> None:
    import pytest

    with pytest.raises(SystemExit) as exc:
        main(["example.com", "-m", "999"])

    assert exc.value.code == 2


def test_zero_hops_exits_error() -> None:
    with _patch_resolve(), _patch_hops([]):
        code = main(["example.com"])

    assert code == 1