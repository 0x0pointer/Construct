"""prsec-egress-proxy: allowlist, address vetting, CONNECT tunnels and plain GET forwarding.

No test touches the internet: the resolver is a dict and the connector maps the vetted public IP
to a local upstream server, so the tests also see which IP the proxy connected to.
"""
from __future__ import annotations

import asyncio

import pytest

from prsec.dynamic import egress_proxy as e

PUBLIC = "151.101.0.223"
DNS = {
    "pypi.org": [PUBLIC],
    "files.pythonhosted.org": [PUBLIC, "2a04:4e42::223"],
    "rebind.pypi.org": [PUBLIC, "10.0.0.7"],
    "meta.pypi.org": ["169.254.169.254"],
}


# ------------------------------------------------------------------ policy


@pytest.mark.parametrize(("host", "allowed"), [
    ("pypi.org", True),
    ("files.pythonhosted.org", True),
    ("cdn.npmjs.org", True),
    ("npmjs.org", False),
    ("evilnpmjs.org", False),
    ("pypi.org.evil.com", False),
    ("example.com", False),
])
def test_host_allowed_exact_and_wildcard(host, allowed):
    assert e.host_allowed(host, ["pypi.org", "files.pythonhosted.org", "*.npmjs.org"]) is allowed


def test_parse_allow_defaults_to_registries():
    assert "registry.npmjs.org" in e.parse_allow(None)


def test_parse_allow_blank_means_default():
    assert e.parse_allow("  ") == list(e.DEFAULT_ALLOW)


def test_parse_allow_custom_list():
    assert e.parse_allow(" PyPI.org., *.example.com ,") == ["pypi.org", "*.example.com"]


@pytest.mark.parametrize("addr", [
    "10.0.0.1", "172.17.0.1", "192.168.1.1", "127.0.0.1", "0.0.0.0", "169.254.169.254", "169.254.1.1",
    "100.64.0.1", "100.100.100.200", "224.0.0.1", "240.0.0.1", "255.255.255.255",
    "::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1", "::ffff:10.0.0.1", "64:ff9b::a00:1",
    "not-an-ip",
])
def test_address_blocked(addr):
    assert e.address_blocked(addr) is True


@pytest.mark.parametrize("addr", [PUBLIC, "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"])
def test_public_address_not_blocked(addr):
    assert e.address_blocked(addr) is False


# ----------------------------------------------------------------- parsing


def test_parse_connect():
    req = e.parse_request(b"CONNECT PyPI.org:443 HTTP/1.1\r\nHost: pypi.org:443")
    assert (req.method, req.host, req.port) == ("CONNECT", "pypi.org", 443)


def test_parse_absolute_get():
    req = e.parse_request(b"GET http://pypi.org/simple/x/?a=1 HTTP/1.1\r\nHost: pypi.org")
    assert (req.host, req.port, req.path) == ("pypi.org", 80, "/simple/x/?a=1")


@pytest.mark.parametrize(("raw", "status"), [
    (b"POST http://pypi.org/ HTTP/1.1", 405),
    (b"GET /simple HTTP/1.1", 400),
    (b"GET https://pypi.org/ HTTP/1.1", 400),
    (b"CONNECT pypi.org:abc HTTP/1.1", 400),
    (b"CONNECT bad_host!:443 HTTP/1.1", 400),
    (b"garbage", 400),
])
def test_parse_rejects_off_recipe_requests(raw, status):
    with pytest.raises(e.Denied) as exc:
        e.parse_request(raw)
    assert exc.value.status == status


def test_forward_head_is_origin_form_and_drops_proxy_headers():
    req = e.parse_request(b"GET http://pypi.org/simple/ HTTP/1.1\r\nProxy-Authorization: Basic eA==\r\n"
                          b"Proxy-Connection: keep-alive\r\nAccept: */*")
    head = e.forward_head(req).decode()
    assert head.startswith("GET /simple/ HTTP/1.1\r\n")
    assert "Proxy-" not in head
    assert "Host: pypi.org\r\n" in head
    assert head.endswith("Connection: close\r\n\r\n")


def test_forward_head_always_sends_the_vetted_host():
    req = e.parse_request(b"GET http://pypi.org/simple/ HTTP/1.1\r\nhost: PyPI.org.\r\nAccept: */*")
    head = e.forward_head(req).decode()
    assert head.count("ost:") == 1
    assert "Host: pypi.org\r\n" in head


def test_host_header_naming_another_site_is_refused():
    req = e.parse_request(b"GET http://pypi.org/x?d=1 HTTP/1.1\r\nHost: attacker-svc.example")
    with pytest.raises(e.Denied) as exc:
        e.check_host_header(req)
    assert exc.value.status == 400


def test_matching_host_header_is_accepted():
    req = e.parse_request(b"GET http://pypi.org/x HTTP/1.1\r\nHost: pypi.org:80")
    assert e.check_host_header(req) is None


# ------------------------------------------------------------------- vetting


def _proxy(connector=None, **kw) -> tuple[e.EgressProxy, list[str]]:
    lookups: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        lookups.append(host)
        if host not in DNS:
            raise OSError("NXDOMAIN")
        return DNS[host]

    allow = ["pypi.org", "*.pypi.org", "files.pythonhosted.org", "unknown.example"]
    return e.EgressProxy(allow, resolver=resolver, connector=connector, **kw), lookups


def _vet(target: bytes) -> list[str]:
    proxy, _ = _proxy()
    return asyncio.run(proxy.vet(e.parse_request(target)))


def test_vet_returns_public_ips():
    assert _vet(b"CONNECT files.pythonhosted.org:443 HTTP/1.1") == [PUBLIC, "2a04:4e42::223"]


@pytest.mark.parametrize(("target", "status"), [
    (b"CONNECT example.com:443 HTTP/1.1", 403),  # not allowlisted
    (b"CONNECT pypi.org:22 HTTP/1.1", 403),  # port
    (b"GET http://pypi.org:8080/ HTTP/1.1", 403),  # port
    (b"CONNECT rebind.pypi.org:443 HTTP/1.1", 403),  # one private address is enough to refuse
    (b"CONNECT meta.pypi.org:443 HTTP/1.1", 403),  # metadata
    (b"CONNECT unknown.example:443 HTTP/1.1", 502),  # resolve failure
])
def test_vet_refuses(target, status):
    with pytest.raises(e.Denied) as exc:
        _vet(target)
    assert exc.value.status == status


# -------------------------------------------------------------------- live


async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()
    writer.close()


async def _run_live(upstream_handler, body, **kw):
    """Start an upstream on 127.0.0.1 and a proxy whose connector maps every vetted IP onto it."""
    upstream = await asyncio.start_server(upstream_handler, "127.0.0.1", 0)
    up_port = upstream.sockets[0].getsockname()[1]
    connected: list[tuple[str, int]] = []

    async def connector(ip: str, port: int):
        connected.append((ip, port))
        return await asyncio.open_connection("127.0.0.1", up_port)

    proxy, lookups = _proxy(connector, **kw)
    await proxy.start("127.0.0.1", 0)
    try:
        return await body(proxy.port), connected, lookups
    finally:
        proxy.close()
        upstream.close()


def test_connect_tunnel_uses_vetted_ip_without_re_resolving():
    async def body(port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n")
        status = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        writer.write(b"ping")
        echoed = await asyncio.wait_for(reader.readexactly(4), 5)
        writer.close()
        return status, echoed

    (status, echoed), connected, lookups = asyncio.run(_run_live(_echo, body))
    assert status.startswith(b"HTTP/1.1 200")
    assert echoed == b"ping"
    assert connected == [(PUBLIC, 443)]
    assert lookups == ["pypi.org"]


def test_plain_get_is_forwarded_in_origin_form(raw_http):
    seen: list[bytes] = []

    async def upstream(reader, writer):
        seen.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    async def body(port):
        return await raw_http(port, b"GET http://pypi.org/simple/ HTTP/1.1\r\nHost: pypi.org\r\n\r\n")

    resp, connected, _ = asyncio.run(_run_live(upstream, body))
    assert resp.endswith(b"\r\n\r\nok")
    assert seen[0].startswith(b"GET /simple/ HTTP/1.1\r\n")
    assert connected == [(PUBLIC, 80)]


def test_denied_request_gets_403_and_no_connection(raw_http):
    async def body(port):
        return await raw_http(port, b"CONNECT rebind.pypi.org:443 HTTP/1.1\r\n\r\n")

    resp, connected, _ = asyncio.run(_run_live(_echo, body))
    assert resp.startswith(b"HTTP/1.1 403")
    assert connected == []


def test_get_with_body_is_refused(raw_http):
    async def body(port):
        return await raw_http(port, b"GET http://pypi.org/ HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc")

    resp, _, _ = asyncio.run(_run_live(_echo, body))
    assert resp.startswith(b"HTTP/1.1 400")


def test_connection_limit_returns_503(raw_http):
    async def body(port):
        return await raw_http(port, b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n")

    resp, connected, _ = asyncio.run(_run_live(_echo, body, max_conns=0, queue_s=0))
    assert resp.startswith(b"HTTP/1.1 503")
    assert connected == []


def test_idle_tunnel_is_closed():
    async def body(port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n")
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        rest = await asyncio.wait_for(reader.read(), 5)  # closes after idle_s without traffic
        writer.close()
        return rest

    rest, _, _ = asyncio.run(_run_live(_echo, body, idle_s=0.2))
    assert rest == b""


def test_connect_failure_is_502(raw_http):
    async def body(port):
        return await raw_http(port, b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n")

    async def run():
        async def refuse(ip: str, port: int):
            raise ConnectionRefusedError("refused")

        proxy, _ = _proxy(refuse)
        await proxy.start("127.0.0.1", 0)
        try:
            return await body(proxy.port)
        finally:
            proxy.close()

    assert asyncio.run(run()).startswith(b"HTTP/1.1 502")


def test_mismatched_host_is_refused_live(raw_http):
    async def body(port):
        return await raw_http(port, b"GET http://pypi.org/x HTTP/1.1\r\nHost: attacker-svc.example\r\n\r\n")

    resp, connected, _ = asyncio.run(_run_live(_echo, body))
    assert resp.startswith(b"HTTP/1.1 400")
    assert connected == []


def test_per_client_limit_returns_503(raw_http):
    async def body(port):
        return await raw_http(port, b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n")

    resp, connected, _ = asyncio.run(_run_live(_echo, body, max_per_client=0))
    assert resp.startswith(b"HTTP/1.1 503")
    assert connected == []


def test_slots_are_released_per_client():
    proxy, _ = _proxy()

    async def run():
        await proxy._admit("10.0.0.5")
        await proxy._admit("10.0.0.5")
        proxy._release("10.0.0.5")
        proxy._release("10.0.0.5")

    asyncio.run(run())
    assert proxy.per_client == {}
    assert proxy.active == 0


def test_tunnel_has_an_absolute_lifetime():
    async def body(port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n")
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        sent = 0
        try:
            for _ in range(40):  # keeps the tunnel busy, well inside idle_s, for 2 s
                writer.write(b"x")
                await writer.drain()
                sent += 1
                await asyncio.sleep(0.05)
        except ConnectionError:
            pass
        writer.close()
        return sent

    sent, _, _ = asyncio.run(_run_live(_echo, body, idle_s=5, lifetime_s=0.2))
    assert sent < 40
