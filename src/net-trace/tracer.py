"""Core traceroute logic — ICMP and TCP variants."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any


class TraceUnavailable(RuntimeError):
    """Raised when traceroute can't run (missing deps or privileges)."""


@dataclass
class HopResult:
    """Result for a single hop (TTL)."""

    hop: int
    rtts_ms: list[float] = field(default_factory=list)
    addr: str | None = None
    hostname: str | None = None

    @property
    def is_timeout(self) -> bool:
        return self.addr is None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "hop": self.hop,
            "rtts_ms": [round(r, 3) for r in self.rtts_ms],
        }
        if self.addr:
            out["addr"] = self.addr
        if self.hostname:
            out["hostname"] = self.hostname
        return out


def _require_scapy() -> tuple[Any, Any]:
    """Import scapy and check for Npcap / admin privileges on Windows."""
    try:
        import scapy.all as scapy  # type: ignore[import-untyped]
    except ImportError as exc:
        raise TraceUnavailable(
            "net-trace requires scapy: pip install \"net-trace\" "
            "(and Npcap on Windows: https://npcap.com/)"
        ) from exc

    try:
        from scapy.all import conf  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover
        raise TraceUnavailable("scapy installation looks incomplete") from exc

    return scapy, conf


def _reverse_dns(addr: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(addr)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


def _resolve_target(target: str) -> str:
    """Resolve a hostname to an IPv4 address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise TraceUnavailable(f"could not resolve {target!r}: {exc}") from exc


def trace(
    target: str,
    *,
    protocol: str = "icmp",
    port: int = 33434,
    max_hops: int = 30,
    probes: int = 3,
    timeout: float = 2.0,
    resolve: bool = True,
) -> list[HopResult]:
    """Run a traceroute and return per-hop results.

    Requires Administrator + Npcap on Windows.
    """
    scapy, _ = _require_scapy()

    dst = _resolve_target(target)
    results: list[HopResult] = []
    reached = False

    for ttl in range(1, max_hops + 1):
        hop = HopResult(hop=ttl)
        last_addr: str | None = None

        for _ in range(probes):
            try:
                rtt_ms, addr = _probe(scapy, dst, ttl, protocol, port, timeout)
            except PermissionError as exc:
                raise TraceUnavailable(
                    "traceroute requires Administrator privileges "
                    "(run PowerShell as Administrator) and Npcap installed."
                ) from exc

            if addr is None:
                hop.rtts_ms.append(0.0)
                continue

            hop.rtts_ms.append(rtt_ms)
            last_addr = addr

        if last_addr:
            hop.addr = last_addr
            if resolve:
                hop.hostname = _reverse_dns(last_addr)

        results.append(hop)

        if last_addr == dst:
            reached = True
            break

    if not reached and results:
        # We ran out of hops without reaching the target.
        pass

    return results


def _probe(
    scapy: Any,
    dst: str,
    ttl: int,
    protocol: str,
    port: int,
    timeout: float,
) -> tuple[float, str | None]:
    """Send a single probe and wait for a reply. Returns (rtt_ms, addr)."""
    import time

    if protocol == "tcp":
        pkt = scapy.IP(dst=dst, ttl=ttl) / scapy.TCP(dport=port, flags="S")
    else:  # icmp
        pkt = scapy.IP(dst=dst, ttl=ttl) / scapy.ICMP()

    start = time.perf_counter()
    reply = scapy.sr1(pkt, timeout=timeout, verbose=False)
    elapsed_ms = (time.perf_counter() - start) * 1000

    if reply is None:
        return elapsed_ms, None

    try:
        addr = reply.src
    except Exception:
        return elapsed_ms, None

    return elapsed_ms, addr


def trace_many(
    targets: list[str],
    **kwargs: Any,
) -> dict[str, list[HopResult]]:
    """Run traceroute against multiple targets sequentially.

    Sequential on purpose — parallel traceroutes fight over the same
    raw sockets and produce noisy, unreliable output.
    """
    return {t: trace(t, **kwargs) for t in targets}