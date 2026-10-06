"""Command-line interface for net-trace."""

from __future__ import annotations

import argparse
import json
import socket
import sys
from typing import NoReturn

from net_trace import __version__
from net_trace.tracer import (
    HopResult,
    TraceUnavailable,
    _resolve_target,
    trace,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_BAD_ARGS = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="net-trace",
        description=(
            "Traceroute for Windows using scapy. "
            "Requires Administrator privileges + Npcap."
        ),
        epilog="Only trace paths to hosts you are authorized to probe.",
    )
    parser.add_argument("target", help="Hostname or IP address to trace.")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=33434,
        help="Destination port for TCP probes (default: 33434).",
    )
    parser.add_argument(
        "--protocol",
        choices=["icmp", "tcp"],
        default="icmp",
        help="Probe protocol (default: icmp).",
    )
    parser.add_argument(
        "-m",
        "--max-hops",
        type=int,
        default=30,
        help="Maximum number of hops (default: 30).",
    )
    parser.add_argument(
        "-q",
        "--probes",
        type=int,
        default=3,
        help="Probes per hop (default: 3).",
    )
    parser.add_argument(
        "-w",
        "--wait",
        type=float,
        default=2.0,
        help="Timeout per probe in seconds (default: 2).",
    )
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="Skip reverse DNS lookup of each hop.",
    )
    parser.add_argument(
        "-j",
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"net-trace {__version__}",
    )
    return parser


def _print_human(
    target: str,
    dst_ip: str,
    hops: list[HopResult],
    *,
    max_hops: int,
) -> None:
    print(f"Tracing route to {target} ({dst_ip})")
    print(f"over a maximum of {max_hops} hops:\n")

    for hop in hops:
        rtts = "  ".join(
            f"{r:>7.3f} ms" if r > 0 else "       * "
            for r in hop.rtts_ms
        )
        if hop.addr:
            label = hop.hostname if hop.hostname else hop.addr
            print(f"{hop.hop:>3}  {rtts}   {label}")
        else:
            print(f"{hop.hop:>3}  {rtts}   *")

    print(f"\nTrace complete. {len(hops)} hops.")


def _print_json(target: str, dst_ip: str, hops: list[HopResult]) -> None:
    payload = {
        "target": target,
        "resolved": dst_ip,
        "hops": [h.to_dict() for h in hops],
        "total_hops": len(hops),
    }
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _fail(message: str, code: int) -> NoReturn:
    print(f"net-trace: error: {message}", file=sys.stderr)
    sys.exit(code)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.max_hops < 1 or args.max_hops > 255:
        _fail("--max-hops must be between 1 and 255", EXIT_BAD_ARGS)
    if args.probes < 1:
        _fail("--probes must be at least 1", EXIT_BAD_ARGS)
    if not 1 <= args.port <= 65535:
        _fail("--port must be between 1 and 65535", EXIT_BAD_ARGS)

    try:
        dst_ip = _resolve_target(args.target)
    except TraceUnavailable as exc:
        _fail(str(exc), EXIT_BAD_ARGS)

    try:
        hops = trace(
            args.target,
            protocol=args.protocol,
            port=args.port,
            max_hops=args.max_hops,
            probes=args.probes,
            timeout=args.wait,
            resolve=not args.no_resolve,
        )
    except TraceUnavailable as exc:
        _fail(str(exc), EXIT_BAD_ARGS)
    except KeyboardInterrupt:
        _fail("interrupted", EXIT_ERROR)
    except OSError as exc:
        _fail(f"network error: {exc}", EXIT_ERROR)

    if not hops:
        _fail("no hops recorded", EXIT_ERROR)

    if args.as_json:
        _print_json(args.target, dst_ip, hops)
    else:
        _print_human(args.target, dst_ip, hops, max_hops=args.max_hops)

    # Success if we reached the destination; otherwise still exit 0 (partial).
    # Only exit 1 if literally zero hops resolved.
    return EXIT_OK if any(h.addr for h in hops) else EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())