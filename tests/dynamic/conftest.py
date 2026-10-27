"""Shared helpers for phase-2 (dynamic) tests: wire-format builders and a raw HTTP client."""
from __future__ import annotations

import asyncio
import ssl
import struct
from collections.abc import Callable

import pytest


def _dns_query(name: str, qtype: int = 1, qid: int = 0x1234, flags: int = 0x0100) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\x00"
    return struct.pack("!6H", qid, flags, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)


def _client_hello(server_name: str | None) -> bytes:
    """A real ClientHello as produced by the ssl module (first TLS record)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


async def _raw_http(port: int, request: bytes) -> bytes:
    """Send raw bytes to 127.0.0.1:<port> and read the full answer (servers close after one response)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), 10)
    writer.close()
    return data


@pytest.fixture
def dns_query() -> Callable[..., bytes]:
    return _dns_query


@pytest.fixture
def client_hello() -> Callable[[str | None], bytes]:
    return _client_hello


@pytest.fixture
def raw_http() -> Callable[[int, bytes], object]:
    return _raw_http
