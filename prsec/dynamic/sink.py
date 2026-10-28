"""prsec-sink: per-env DNS stub, catch-all HTTP recorder and TLS SNI logger.

One sink runs on every dynamic environment network (alias `sink`) and is the workbench's only
nameserver. Every outbound call the app makes therefore lands here instead of leaving:

    DNS  :53   A queries: names in hosts.json (catalog services, sink, llm-gateway, egress-proxy)
               get their real IP, every other name gets the sink's own IP. AAAA and other types
               get an empty NOERROR answer (so clients fall back to IPv4); malformed packets are
               dropped.
    HTTP :80   records every request (host, method, path, query, headers, body <= 64 KiB, client
               ip) in a bounded in-memory ring and a JSONL file, then answers from stubs.json
               (first matching StubSpec) or `200 {}`.
    TLS  :443  reads the ClientHello, records the SNI host and closes (no certificate, no tunnel).

Requests with Host `sink` and a path under /__prsec/ are the API instead of being recorded:
`GET /__prsec/health` -> {"ok": true}, `GET /__prsec/hits?contains=<s>` -> {"hits": [...]}.

hosts.json ({name: ipv4}) and stubs.json ([StubSpec, ...]) are written by the runner into the sink
dir and re-read whenever their mtime changes. Runs as non-root (the container sets
net.ipv4.ip_unprivileged_port_start=0); ports are configurable for tests.
"""
from __future__ import annotations

import argparse
import asyncio
import fnmatch
import ipaddress
import json
import logging
import os
import socket
import struct
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import TypeAdapter

from prsec.dynamic.envspec import StubSpec

log = logging.getLogger("prsec.sink")

API_HOST = "sink"
API_PREFIX = "/__prsec/"
MAX_BODY = 64 * 1024  # recorded per request
MAX_DRAIN = 8 * 1024 * 1024  # read (and discarded) beyond MAX_BODY so the client sees the answer
MAX_HEAD = 64 * 1024
RING_SIZE = 5000
IO_TIMEOUT_S = 30.0
REQUESTS_LOG = "requests.jsonl"
MAX_LOG_BYTES = 32 * 1024 * 1024  # the JSONL mirror lives on the shared host work root: stop mirroring here


# ------------------------------------------------------------------- DNS

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1
RCODE_NOERROR = 0
RCODE_NOTIMP = 4
TTL_S = 5
_QR, _OPCODE, _AA, _RD, _RA = 0x8000, 0x7800, 0x0400, 0x0100, 0x0080


@dataclass(frozen=True)
class DnsQuery:
    id: int
    flags: int
    name: str  # lowercase, no trailing dot
    qtype: int
    qclass: int
    question: bytes  # raw question section, echoed verbatim in the answer


def _read_name(data: bytes, pos: int) -> tuple[str, int]:
    """Uncompressed QNAME at `pos` -> (name, end). Raises ValueError on anything malformed."""
    labels: list[str] = []
    while True:
        n = data[pos]
        pos += 1
        if n == 0:
            break
        if n & 0xC0 or pos + n > len(data):
            raise ValueError("bad label")  # a question never needs compression pointers
        labels.append(data[pos:pos + n].decode("ascii"))
        pos += n
    name = ".".join(labels).lower()
    if len(name) > 253:
        raise ValueError("name too long")
    return name, pos


def parse_query(data: bytes) -> DnsQuery | None:
    """Parse a single-question DNS query; None for responses, multi-question or malformed packets."""
    try:
        qid, flags, qdcount = struct.unpack("!3H", data[:6])
        if flags & _QR or qdcount != 1:
            return None
        name, pos = _read_name(data, 12)
        qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
    except (struct.error, IndexError, ValueError):
        return None
    return DnsQuery(qid, flags, name, qtype, qclass, data[12:pos + 4])


def build_response(q: DnsQuery, rcode: int, ips: list[str] | tuple[str, ...] = ()) -> bytes:
    flags = _QR | (q.flags & _OPCODE) | _AA | (q.flags & _RD) | _RA | rcode
    header = struct.pack("!6H", q.id, flags, 1, len(ips), 0, 0)
    answers = b"".join(
        struct.pack("!HHHIH", 0xC00C, TYPE_A, CLASS_IN, TTL_S, 4) + socket.inet_aton(ip) for ip in ips)
    return header + q.question + answers


def dns_answer(data: bytes, resolve: Callable[[str], str]) -> bytes | None:
    """Answer bytes for one query packet, or None to drop it."""
    q = parse_query(data)
    if q is None:
        return None
    if q.flags & _OPCODE:
        return build_response(q, RCODE_NOTIMP)
    if q.qtype == TYPE_A and q.qclass == CLASS_IN:
        return build_response(q, RCODE_NOERROR, [resolve(q.name)])
    return build_response(q, RCODE_NOERROR)  # AAAA and everything else: exists, no records


class _DnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolve: Callable[[str], str]) -> None:
        self.resolve = resolve
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            out = dns_answer(data, self.resolve)
            if out is not None and self.transport is not None:
                self.transport.sendto(out, addr)
        except Exception as e:  # never let one packet take the resolver down
            log.debug("dns: dropped packet from %s: %s", addr, e)


# ------------------------------------------------------- reloadable config


class JsonFile[T]:
    """A JSON file re-parsed whenever its mtime/size changes. A broken file keeps the last good value."""

    def __init__(self, path: Path | None, parse: Callable[[Any], T], empty: T) -> None:
        self.path, self._parse, self._empty = path, parse, empty
        self._value: T = empty
        self._key: tuple[int, int] | None = None

    def _stat(self) -> tuple[int, int] | None:
        try:
            st = self.path.stat() if self.path else None
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size) if st else None

    def get(self) -> T:
        key = self._stat()
        if key != self._key:
            self._key = key
            self._value = self._load() if key else self._empty
        return self._value

    def _load(self) -> T:
        try:
            return self._parse(json.loads(self.path.read_text()))  # type: ignore[union-attr]
        except (OSError, ValueError) as e:  # pydantic ValidationError is a ValueError
            log.warning("sink: ignoring invalid %s: %s", self.path, e)
            return self._value


def parse_hosts(raw: Any) -> dict[str, str]:
    """{name: ipv4} with lowercase names; entries that are not a valid IPv4 address are skipped."""
    if not isinstance(raw, dict):
        raise ValueError("hosts.json must be an object")
    out: dict[str, str] = {}
    for name, ip in raw.items():
        try:
            out[str(name).lower().rstrip(".")] = str(ipaddress.IPv4Address(ip))
        except ValueError:
            log.warning("sink: skipping host %r -> %r", name, ip)
    return out


_STUBS = TypeAdapter(list[StubSpec])


def parse_stubs(raw: Any) -> list[StubSpec]:
    """A StubSpec list, bare or as {"stubs": [...]}."""
    if isinstance(raw, dict):
        raw = raw.get("stubs", [])
    return _STUBS.validate_python(raw)


def match_stub(stubs: list[StubSpec], host: str, method: str, path: str) -> StubSpec | None:
    for s in stubs:
        if not fnmatch.fnmatchcase(host, s.host.lower()):
            continue
        if s.method != "*" and s.method.upper() != method:
            continue
        if path.startswith(s.path_prefix):
            return s
    return None


# ---------------------------------------------------------------- recorder


def _record_matches(rec: dict[str, Any], needle: str) -> bool:
    query = rec.get("query", "")
    fields = [rec.get("host", ""), rec.get("path", ""), query, unquote(query), rec.get("body", "")]
    fields.extend(rec.get("headers", {}).values())
    return any(needle in f for f in fields)


class Recorder:
    """Bounded in-memory ring of recorded requests, mirrored to a JSONL file (best effort, and only
    up to `max_log_bytes`: after that, memory only)."""

    def __init__(self, log_file: Path | None = None, size: int = RING_SIZE, max_log_bytes: int = MAX_LOG_BYTES) -> None:
        self.ring: deque[dict[str, Any]] = deque(maxlen=size)
        self.log_file = log_file
        self.max_log_bytes = max_log_bytes
        self._log_failed = False
        self._log_bytes = 0

    def add(self, rec: dict[str, Any]) -> None:
        self.ring.append(rec)
        if self.log_file is None or self._log_failed:
            return
        line = (json.dumps(rec) + "\n").encode("utf-8")
        if self._log_bytes + len(line) > self.max_log_bytes:
            self._log_failed = True
            log.warning("sink: %s reached %d bytes (memory only from now on)", self.log_file, self.max_log_bytes)
            return
        try:
            with self.log_file.open("ab") as f:
                f.write(line)
            self._log_bytes += len(line)
        except OSError as e:
            self._log_failed = True
            log.warning("sink: cannot write %s (memory only from now on): %s", self.log_file, e)

    def hits(self, contains: str = "") -> list[dict[str, Any]]:
        return [r for r in self.ring if _record_matches(r, contains)]


def make_record(client_ip: str, host: str, *, method: str = "", path: str = "", query: str = "",
                headers: dict[str, str] | None = None, body: bytes = b"", truncated: bool = False,
                tls: bool = False) -> dict[str, Any]:
    return {
        "ts": round(time.time(), 3),
        "client_ip": client_ip,
        "tls": tls,
        "host": host,
        "method": method,
        "path": path,
        "query": query,
        "headers": headers or {},
        "body": body.decode("utf-8", "replace"),
        "body_truncated": truncated,
    }


# ------------------------------------------------------------ HTTP parsing


@dataclass
class HttpHead:
    method: str
    target: str
    headers: dict[str, str]  # original-case names; repeated headers joined with ", "

    def header(self, name: str) -> str:
        name = name.lower()
        return next((v for k, v in self.headers.items() if k.lower() == name), "")


def parse_head(raw: bytes) -> HttpHead | None:
    lines = raw.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            continue
        name, value = name.strip(), value.strip()
        headers[name] = f"{headers[name]}, {value}" if name in headers else value
    return HttpHead(parts[0].upper(), parts[1], headers)


def host_only(host: str) -> str:
    """Lowercase host without port ('[::1]:80' -> '::1', 'sink:80' -> 'sink')."""
    host = host.strip().lower()
    if host.startswith("["):
        return host[1:host.find("]")] if "]" in host else host[1:]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def split_target(target: str, host_header: str) -> tuple[str, str, str]:
    """(host, path, query) from an origin-form or absolute-form request target."""
    url = urlsplit(target)
    host = url.netloc if url.scheme in ("http", "https") and url.netloc else host_header
    return host_only(host), url.path or "/", url.query


class _Body:
    """Keeps the first MAX_BODY bytes of what it is fed; refuses more than MAX_DRAIN in total."""

    def __init__(self) -> None:
        self.kept = bytearray()
        self.total = 0

    def feed(self, data: bytes) -> None:
        self.total += len(data)
        room = MAX_BODY - len(self.kept)
        if room > 0:
            self.kept += data[:room]

    def budget(self, n: int) -> int:
        return max(0, min(n, MAX_DRAIN - self.total))


async def _read_sized(reader: asyncio.StreamReader, body: _Body, n: int) -> None:
    n = body.budget(n)
    while n > 0:
        chunk = await reader.read(min(n, 65536))
        if not chunk:
            return
        body.feed(chunk)
        n -= len(chunk)


async def _read_chunked(reader: asyncio.StreamReader, body: _Body) -> None:
    while True:
        size = int((await reader.readuntil(b"\r\n")).split(b";")[0].strip() or b"0", 16)
        if size == 0 or body.budget(size) < size:
            return  # trailers (if any) are left unread; the connection closes after the answer
        body.feed(await reader.readexactly(size))
        await reader.readexactly(2)


async def read_body(reader: asyncio.StreamReader, head: HttpHead) -> tuple[bytes, bool]:
    """(first MAX_BODY bytes, truncated). Errors end the body early instead of failing the request."""
    body = _Body()
    try:
        if "chunked" in head.header("transfer-encoding").lower():
            await _read_chunked(reader, body)
        else:
            await _read_sized(reader, body, int(head.header("content-length") or 0))
    except (ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        pass
    return bytes(body.kept), body.total > len(body.kept)


def _safe(value: str) -> str:
    return value.replace("\r", "").replace("\n", "")


_HOP_HEADERS = {"content-length", "transfer-encoding", "connection"}


def http_response(status: int, headers: dict[str, str], body: bytes, head_only: bool = False) -> bytes:
    try:
        reason = HTTPStatus(status).phrase
    except ValueError:
        reason = "Status"
    lines = [f"HTTP/1.1 {status} {reason}"]
    lines += [f"{_safe(k)}: {_safe(v)}" for k, v in headers.items() if k.lower() not in _HOP_HEADERS]
    lines += [f"Content-Length: {len(body)}", "Connection: close", "", ""]
    return "\r\n".join(lines).encode("latin-1", "replace") + (b"" if head_only else body)


def _json(status: int, payload: Any) -> tuple[int, dict[str, str], bytes]:
    return status, {"Content-Type": "application/json"}, json.dumps(payload).encode()


# ------------------------------------------------------------- TLS parsing


class _Cursor:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def uint(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def vec(self, width: int) -> bytes:
        return self.take(self.uint(width))


def _server_name(ext: bytes) -> str | None:
    names = _Cursor(_Cursor(ext).vec(2))
    while names.remaining():
        kind, name = names.uint(1), names.vec(2)
        if kind == 0:
            return name.decode("ascii").lower().rstrip(".")
    return None


def extract_sni(record: bytes) -> str | None:
    """SNI host from the first TLS record (a ClientHello), or None if absent or malformed."""
    try:
        c = _Cursor(record)
        if c.uint(1) != 22:  # handshake
            return None
        c.take(2)
        hs = _Cursor(c.vec(2))
        if hs.uint(1) != 1:  # client_hello
            return None
        hello = _Cursor(hs.take(min(hs.uint(3), hs.remaining())))
        hello.take(2 + 32)  # legacy_version, random
        hello.vec(1)  # session id
        hello.vec(2)  # cipher suites
        hello.vec(1)  # compression methods
        exts = _Cursor(hello.vec(2))
        while exts.remaining():
            etype, data = exts.uint(2), exts.vec(2)
            if etype == 0:
                return _server_name(data)
    except ValueError:  # includes UnicodeDecodeError
        return None
    return None


async def read_tls_record(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(5)
    return header + await reader.readexactly(int.from_bytes(header[3:5], "big"))


# -------------------------------------------------------------------- sink


def detect_self_ip() -> str:
    """The container's own address (Docker maps the hostname to it), else 127.0.0.1."""
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"
    return ip


def _peer_ip(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    return str(peer[0]) if peer else ""


class Sink:
    def __init__(self, self_ip: str, hosts_file: Path | None = None, stubs_file: Path | None = None,
                 log_file: Path | None = None, ring_size: int = RING_SIZE) -> None:
        self.self_ip = str(ipaddress.IPv4Address(self_ip))
        self.hosts: JsonFile[dict[str, str]] = JsonFile(hosts_file, parse_hosts, {})
        self.stubs: JsonFile[list[StubSpec]] = JsonFile(stubs_file, parse_stubs, [])
        self.recorder = Recorder(log_file, ring_size)
        self.ports: dict[str, int] = {}
        self._closers: list[Callable[[], None]] = []

    def resolve(self, name: str) -> str:
        """Hosts-map address, else the sink itself (the runner's `sink` entry beats self_ip)."""
        hosts = self.hosts.get()
        return hosts.get(name.lower().rstrip("."), hosts.get(API_HOST, self.self_ip))

    # ---- HTTP

    def api(self, method: str, path: str, query: str) -> tuple[int, dict[str, str], bytes]:
        if method not in ("GET", "HEAD"):
            return _json(405, {"error": "method not allowed"})
        if path == "/__prsec/health":
            return _json(200, {"ok": True})
        if path == "/__prsec/hits":
            contains = parse_qs(query).get("contains", [""])[0]
            return _json(200, {"hits": self.recorder.hits(contains)})
        return _json(404, {"error": "not found"})

    def stub_answer(self, host: str, method: str, path: str) -> tuple[int, dict[str, str], bytes]:
        stub = match_stub(self.stubs.get(), host, method, path)
        if stub is None:
            return _json(200, {})
        return stub.status, dict(stub.headers), stub.body.encode()

    async def _serve_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = parse_head((await reader.readuntil(b"\r\n\r\n"))[:-4])
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return
        if head is None:
            writer.write(http_response(400, {}, b""))
            return
        body, truncated = await read_body(reader, head)
        host, path, query = split_target(head.target, head.header("host"))
        if host == API_HOST and path.startswith(API_PREFIX):
            status, headers, payload = self.api(head.method, path, query)
        else:
            self.recorder.add(make_record(_peer_ip(writer), host, method=head.method, path=path, query=query,
                                          headers=head.headers, body=body, truncated=truncated))
            status, headers, payload = self.stub_answer(host, head.method, path)
        writer.write(http_response(status, headers, payload, head_only=head.method == "HEAD"))
        await writer.drain()

    async def handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _guarded(self._serve_http(reader, writer), writer, "http")

    # ---- TLS

    async def _serve_tls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            record = await read_tls_record(reader)
        except asyncio.IncompleteReadError:
            return
        self.recorder.add(make_record(_peer_ip(writer), extract_sni(record) or "", tls=True))

    async def handle_tls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _guarded(self._serve_tls(reader, writer), writer, "tls")

    # ---- lifecycle

    async def start(self, bind: str = "0.0.0.0", dns_port: int = 53, http_port: int = 80, tls_port: int = 443) -> None:
        """Start all listeners; port 0 picks a free one (see `self.ports`)."""
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(lambda: _DnsProtocol(self.resolve), local_addr=(bind, dns_port))
        self._closers.append(transport.close)
        self.ports["dns"] = transport.get_extra_info("sockname")[1]
        for name, port, handler in (("http", http_port, self.handle_http), ("tls", tls_port, self.handle_tls)):
            server = await asyncio.start_server(handler, bind, port, limit=MAX_HEAD)
            self._closers.append(server.close)
            self.ports[name] = server.sockets[0].getsockname()[1]
        log.info("sink up on %s: %s (self ip %s)", bind, self.ports, self.self_ip)

    def close(self) -> None:
        for close in self._closers:
            close()
        self._closers.clear()


async def _guarded(work: Any, writer: asyncio.StreamWriter, what: str) -> None:
    """Run one connection's work with a deadline; nothing a client sends may crash the sink."""
    try:
        await asyncio.wait_for(work, IO_TIMEOUT_S)
    except (TimeoutError, ConnectionError):
        pass
    except Exception:
        log.exception("sink %s: unexpected error", what)
    finally:
        writer.close()


# -------------------------------------------------------------------- main


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name) or default)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prsec-sink", description="Per-env DNS stub + HTTP/TLS recorder")
    p.add_argument("--data-dir", default=os.environ.get("PRSEC_SINK_DIR", "/sink"),
                   help="Holds hosts.json and stubs.json; requests.jsonl is written here")
    p.add_argument("--log-file", default=os.environ.get("PRSEC_SINK_LOG"),
                   help=f"JSONL request log (default <data-dir>/{REQUESTS_LOG})")
    p.add_argument("--self-ip", default=os.environ.get("PRSEC_SINK_SELF_IP"), help="IP unknown names resolve to")
    p.add_argument("--bind", default=os.environ.get("PRSEC_SINK_BIND", "0.0.0.0"))
    p.add_argument("--dns-port", type=int, default=_env_int("PRSEC_SINK_DNS_PORT", 53))
    p.add_argument("--http-port", type=int, default=_env_int("PRSEC_SINK_HTTP_PORT", 80))
    p.add_argument("--tls-port", type=int, default=_env_int("PRSEC_SINK_TLS_PORT", 443))
    p.add_argument("--ring-size", type=int, default=_env_int("PRSEC_SINK_RING", RING_SIZE))
    return p


async def _serve(args: argparse.Namespace) -> None:
    data = Path(args.data_dir)
    sink = Sink(args.self_ip or detect_self_ip(), data / "hosts.json", data / "stubs.json",
                Path(args.log_file) if args.log_file else data / REQUESTS_LOG, args.ring_size)
    await sink.start(args.bind, args.dns_port, args.http_port, args.tls_port)
    try:
        await asyncio.Event().wait()
    finally:
        sink.close()


def main(argv: list[str] | None = None) -> None:
    from prsec.obs.logging import setup_logging

    setup_logging("sink")
    args = build_parser().parse_args(argv)
    try:
        asyncio.run(_serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
