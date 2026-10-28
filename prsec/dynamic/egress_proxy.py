"""prsec-egress-proxy: allowlisting HTTP proxy for package installs in dynamic environments.

The workbench's install/build commands run with HTTP(S)_PROXY=http://egress-proxy:3128; the app
itself never does. The proxy sits on its own non-internal `egress` network and allows:

    CONNECT <host>:443               TLS tunnel (the proxy never sees plaintext)
    GET|HEAD http://<host>[:80]/...  plain absolute-URI requests, forwarded with Connection: close

only when <host> is on PRSEC_EGRESS_ALLOW (comma list; exact host or '*.suffix' for subdomains)
AND every address it resolves to is public (no private, loopback, link-local, multicast,
reserved, unspecified or cloud metadata address). It then connects to the vetted IP itself, not
the name, so a second lookup cannot be rebound to an internal address. The upstream always gets
`Host: <vetted host>` (a client Host header that names another host is refused), so a CDN that
routes on Host cannot be steered to a different site. Connections are bounded per client (one
env's app cannot starve the others) and globally (new ones wait briefly for a free slot); idle
connections time out and every tunnel has an absolute lifetime. One log line per decision.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import re
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

log = logging.getLogger("prsec.egress")

DEFAULT_ALLOW = (
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com",
    "proxy.golang.org", "sum.golang.org", "repo1.maven.org", "repo.maven.apache.org",
    "plugins.gradle.org", "services.gradle.org",
)
HOSTNAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}")
# Cloud metadata endpoints: a blocklist, never dialled.
_METADATA = ("169.254.169.254", "169.254.170.2", "100.100.100.200", "192.0.0.192", "fd00:ec2::254")  # NOSONAR(S1313)
METADATA_IPS = frozenset(ipaddress.ip_address(a) for a in _METADATA)
NAT64 = ipaddress.ip_network("64:ff9b::/96")
CONNECT_PORTS = frozenset({443})
HTTP_PORTS = frozenset({80})
MAX_HEAD = 16 * 1024
HEAD_TIMEOUT_S = 15.0
CONNECT_TIMEOUT_S = 10.0
QUEUE_POLL_S = 0.05

Resolver = Callable[[str, int], Awaitable[list[str]]]
Connector = Callable[[str, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]
IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class Denied(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status, self.reason = status, reason


# ------------------------------------------------------------------ policy


def parse_allow(raw: str | None) -> list[str]:
    """PRSEC_EGRESS_ALLOW as a list; unset or blank means the default registry list."""
    if not raw or not raw.strip():
        return list(DEFAULT_ALLOW)
    return [h.strip().lower().rstrip(".") for h in raw.split(",") if h.strip()]


def host_allowed(host: str, allow: list[str]) -> bool:
    """Exact match, or '*.suffix' matching any subdomain of suffix (not the suffix itself)."""
    for entry in allow:
        if entry.startswith("*."):
            if host.endswith(entry[1:]) and len(host) > len(entry) - 1:
                return True
        elif host == entry:
            return True
    return False


def _embedded_v4(ip: IpAddress) -> ipaddress.IPv4Address | None:
    if ip.version != 6:
        return None
    if ip.ipv4_mapped:  # type: ignore[union-attr]
        return ip.ipv4_mapped  # type: ignore[union-attr]
    if ip in NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def address_blocked(addr: str) -> bool:
    """True for anything that is not a plain public unicast address (unparseable counts as blocked)."""
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return True
    inner = _embedded_v4(ip)
    if inner is not None:
        return address_blocked(str(inner))
    return (ip in METADATA_IPS or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified or not ip.is_global)


async def system_resolve(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


# ----------------------------------------------------------------- parsing


@dataclass
class ProxyRequest:
    method: str
    host: str
    port: int
    path: str  # origin-form for GET/HEAD ("" for CONNECT)
    headers: list[tuple[str, str]]


def _split_hostport(value: str, default_port: int) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or "]" in port:
        return value, default_port
    return host.strip("[]"), int(port)


def _target(method: str, target: str) -> tuple[str, int, str]:
    if method == "CONNECT":
        host, port = _split_hostport(target, 443)
        return host, port, ""
    url = urlsplit(target)
    if url.scheme != "http" or not url.hostname:
        raise Denied(400, "absolute http:// URI required")
    path = (url.path or "/") + (f"?{url.query}" if url.query else "")
    return url.hostname, url.port or 80, path


def parse_request(raw: bytes) -> ProxyRequest:
    """Parse a proxy request head (without the final blank line). Raises Denied on anything off-recipe."""
    lines = raw.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise Denied(400, "bad request line")
    method = parts[0].upper()
    if method not in ("CONNECT", "GET", "HEAD"):
        raise Denied(405, f"method {method} not allowed")
    try:
        host, port, path = _target(method, parts[1])
    except ValueError as e:
        raise Denied(400, f"bad target: {e}") from e
    host = host.lower().rstrip(".")
    if not HOSTNAME.fullmatch(host):
        raise Denied(400, "bad host")
    headers = [(k.strip(), v.strip()) for k, sep, v in (ln.partition(":") for ln in lines[1:]) if sep and k.strip()]
    return ProxyRequest(method, host, port, path, headers)


_DROP = {"connection", "proxy-connection", "proxy-authorization", "keep-alive", "te", "upgrade", "host"}


def check_host_header(req: ProxyRequest) -> None:
    """A plain request's Host header(s) must name the vetted absolute-URI host (Denied otherwise)."""
    for k, v in req.headers:
        if k.lower() != "host":
            continue
        try:
            host, _ = _split_hostport(v.strip(), req.port)
        except ValueError:
            raise Denied(400, "bad Host header") from None
        if host.lower().rstrip(".") != req.host:
            raise Denied(400, "Host header does not match the request URI")


def forward_head(req: ProxyRequest) -> bytes:
    """Origin-form request head for the upstream: Host is always the vetted host, hop-by-hop
    headers are replaced by Connection: close."""
    lines = [f"{req.method} {req.path} HTTP/1.1",
             f"Host: {req.host}" if req.port == 80 else f"Host: {req.host}:{req.port}"]
    lines += [f"{k}: {v}" for k, v in req.headers if k.lower() not in _DROP]
    lines += ["Connection: close", "", ""]
    return "\r\n".join(lines).encode("latin-1")


def _has_body(req: ProxyRequest) -> bool:
    for k, v in req.headers:
        name = k.lower()
        if name == "transfer-encoding" or (name == "content-length" and v.strip() not in ("", "0")):
            return True
    return False


def _error(status: int, reason: str) -> bytes:
    body = f"prsec-egress-proxy: {reason}\n".encode()
    return (f"HTTP/1.1 {status} {'Forbidden' if status == 403 else 'Error'}\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body


# ------------------------------------------------------------------- proxy


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, idle_s: float) -> None:
    """Copy until EOF or `idle_s` without data, then half-close the writer."""
    try:
        while data := await asyncio.wait_for(reader.read(65536), idle_s):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except OSError:  # TimeoutError and ConnectionError are OSError subclasses
        writer.close()


class EgressProxy:
    def __init__(self, allow: list[str], resolver: Resolver = system_resolve,
                 connector: Connector | None = None, max_conns: int = 256, idle_s: float = 60.0,
                 max_per_client: int = 24, queue_s: float = 10.0, lifetime_s: float = 900.0) -> None:
        self.allow = allow
        self.resolver = resolver
        self.connector = connector or self._open
        self.max_conns, self.idle_s = max_conns, idle_s
        self.max_per_client, self.queue_s, self.lifetime_s = max_per_client, queue_s, lifetime_s
        self.active = 0
        self.per_client: dict[str, int] = {}
        self.port = 0
        self._server: asyncio.Server | None = None

    @staticmethod
    async def _open(ip: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.open_connection(ip, port)

    async def vet(self, req: ProxyRequest) -> list[str]:
        """Public addresses of an allowlisted host; raises Denied otherwise."""
        allowed_ports = CONNECT_PORTS if req.method == "CONNECT" else HTTP_PORTS
        if req.port not in allowed_ports:
            raise Denied(403, f"port {req.port} not allowed")
        if not host_allowed(req.host, self.allow):
            raise Denied(403, "host not on allowlist")
        try:
            ips = await asyncio.wait_for(self.resolver(req.host, req.port), CONNECT_TIMEOUT_S)
        except OSError as e:  # includes TimeoutError
            raise Denied(502, f"resolve failed: {e}") from e
        blocked = [ip for ip in ips if address_blocked(ip)]
        if not ips or blocked:
            raise Denied(403, f"resolves to non-public address {blocked or 'none'}")
        return ips

    async def _connect(self, ips: list[str], port: int) -> tuple[str, asyncio.StreamReader, asyncio.StreamWriter]:
        last: Exception | None = None
        for ip in ips:
            try:
                reader, writer = await asyncio.wait_for(self.connector(ip, port), CONNECT_TIMEOUT_S)
                return ip, reader, writer
            except OSError as e:  # includes TimeoutError
                last = e
        raise Denied(502, f"connect failed: {last}")

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client: str) -> None:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT_S)
        req = parse_request(head[:-4])
        if req.method != "CONNECT":
            if _has_body(req):
                raise Denied(400, "request bodies are not forwarded")
            check_host_header(req)
        ip, up_reader, up_writer = await self._connect(await self.vet(req), req.port)
        log.info("allow client=%s %s %s:%d -> %s", client, req.method, req.host, req.port, ip)
        try:
            if req.method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                pumps = asyncio.gather(_pump(reader, up_writer, self.idle_s), _pump(up_reader, writer, self.idle_s))
            else:  # one request per connection: later requests on it would bypass the allowlist
                up_writer.write(forward_head(req))
                pumps = _pump(up_reader, writer, self.idle_s)
            await asyncio.wait_for(pumps, self.lifetime_s)  # trickling a byte per idle_s is not forever
        finally:
            up_writer.close()

    async def _admit(self, client: str) -> None:
        """Take a slot: refuse a client at its own cap, wait up to queue_s for a global one."""
        if self.per_client.get(client, 0) >= self.max_per_client:
            raise Denied(503, "too many connections from this client")
        deadline = asyncio.get_running_loop().time() + self.queue_s
        while self.active >= self.max_conns:
            if asyncio.get_running_loop().time() >= deadline:
                raise Denied(503, "too many connections")
            await asyncio.sleep(QUEUE_POLL_S)
        self.active += 1
        self.per_client[client] = self.per_client.get(client, 0) + 1

    def _release(self, client: str) -> None:
        self.active -= 1
        left = self.per_client.get(client, 1) - 1
        if left > 0:
            self.per_client[client] = left
        else:
            self.per_client.pop(client, None)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client = str(peer[0]) if peer else "?"
        try:
            await self._admit(client)
            try:
                await self._serve(reader, writer, client)
            finally:
                self._release(client)
        except Denied as d:
            log.info("deny client=%s status=%d reason=%s", client, d.status, d.reason)
            await _refuse(reader, writer, d)
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
            pass
        except Exception:
            log.exception("egress proxy: unexpected error")
        finally:
            await _close(writer)

    async def start(self, bind: str = "0.0.0.0", port: int = 3128) -> None:
        self._server = await asyncio.start_server(self.handle, bind, port, limit=MAX_HEAD)
        self.port = self._server.sockets[0].getsockname()[1]
        log.info("egress proxy on %s:%d allow=%s", bind, self.port, ",".join(self.allow))

    def close(self) -> None:
        if self._server is not None:
            self._server.close()


async def _refuse(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, d: Denied) -> None:
    """Send the error, then briefly read what the client already sent so closing does not reset it."""
    try:
        writer.write(_error(d.status, d.reason))
        if writer.can_write_eof():
            writer.write_eof()
        await asyncio.wait_for(reader.read(MAX_HEAD), 1.0)
    except OSError:  # TimeoutError and ConnectionError are OSError subclasses
        pass


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        await writer.drain()
    except OSError:
        pass
    writer.close()


# -------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prsec-egress-proxy", description="Allowlisting proxy for package installs")
    p.add_argument("--bind", default=os.environ.get("PRSEC_EGRESS_BIND", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(os.environ.get("PRSEC_EGRESS_PORT") or 3128))
    p.add_argument("--max-conns", type=int, default=int(os.environ.get("PRSEC_EGRESS_MAX_CONNS") or 256))
    p.add_argument("--max-per-client", type=int, default=int(os.environ.get("PRSEC_EGRESS_MAX_PER_CLIENT") or 24))
    p.add_argument("--queue-s", type=float, default=float(os.environ.get("PRSEC_EGRESS_QUEUE_S") or 10))
    p.add_argument("--idle-s", type=float, default=float(os.environ.get("PRSEC_EGRESS_IDLE_S") or 60))
    p.add_argument("--lifetime-s", type=float, default=float(os.environ.get("PRSEC_EGRESS_LIFETIME_S") or 900))
    return p


async def _serve_forever(args: argparse.Namespace) -> None:
    proxy = EgressProxy(parse_allow(os.environ.get("PRSEC_EGRESS_ALLOW")), max_conns=args.max_conns, idle_s=args.idle_s,
                        max_per_client=args.max_per_client, queue_s=args.queue_s, lifetime_s=args.lifetime_s)
    await proxy.start(args.bind, args.port)
    try:
        await asyncio.Event().wait()
    finally:
        proxy.close()


def main(argv: list[str] | None = None) -> None:
    from prsec.obs.logging import setup_logging

    setup_logging("egress-proxy")
    args = build_parser().parse_args(argv)
    try:
        asyncio.run(_serve_forever(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
