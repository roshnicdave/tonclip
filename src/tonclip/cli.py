from __future__ import annotations

import argparse
import asyncio
import re
import sys
from collections.abc import Sequence

from . import __version__
from .dht import DhtError, get, put
from .protocol import MAX_PAYLOAD_SIZE, ProtocolError

DEFAULT_TTL = 15 * 60
MINIMUM_TTL = 60
MAXIMUM_TTL = 60 * 60
COMMAND_TIMEOUT = 90


def main() -> None:
    try:
        raise SystemExit(asyncio.run(_run(sys.argv[1:])))
    except KeyboardInterrupt:
        raise SystemExit(130)
    except BrokenPipeError:
        raise SystemExit(0)


async def _run(args: Sequence[str]) -> int:
    parser = _parser()
    parsed = parser.parse_args(args)
    try:
        if parsed.command == "put":
            payload = sys.stdin.buffer.read(MAX_PAYLOAD_SIZE + 1)
            if len(payload) > MAX_PAYLOAD_SIZE:
                raise ProtocolError(
                    f"payload exceeds the {MAX_PAYLOAD_SIZE}-byte limit"
                )
            key, _, _ = await asyncio.wait_for(
                put(payload, _parse_ttl(parsed.ttl)), COMMAND_TIMEOUT
            )
            print(key)
        else:
            payload, _ = await asyncio.wait_for(get(parsed.key), COMMAND_TIMEOUT)
            sys.stdout.buffer.write(payload)
    except asyncio.TimeoutError:
        print("tonclip: TON DHT request timed out", file=sys.stderr)
        return 1
    except (DhtError, ProtocolError, OSError) as exc:
        print(f"tonclip: {exc}", file=sys.stderr)
        return 1
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tonclip",
        description="Put a small encrypted value in the public TON DHT.",
    )
    parser.add_argument("--version", action="version", version=f"tonclip {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    put_parser = subparsers.add_parser("put", help="read stdin and store it")
    put_parser.add_argument(
        "--ttl", default="15m", help="lifetime from 1m to 1h (default: 15m)"
    )
    get_parser = subparsers.add_parser("get", help="retrieve a value to stdout")
    get_parser.add_argument("key")
    return parser


def _parse_ttl(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([mh])", value)
    if match is None:
        raise ProtocolError("ttl must look like 5m or 1h")
    amount = int(match.group(1))
    seconds = amount * (60 if match.group(2) == "m" else 3600)
    if not MINIMUM_TTL <= seconds <= MAXIMUM_TTL:
        raise ProtocolError("ttl must be between 1m and 1h")
    return seconds
