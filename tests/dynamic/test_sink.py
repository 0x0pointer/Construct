"""prsec-sink: DNS codec + resolution, HTTP recorder / stubs / hits API, TLS SNI recording."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
from pathlib import Path

import pytest

from prsec.dynamic import sink as s
from prsec.dynamic.envspec import StubSpec

SELF_IP = "10.9.0.2"


def _answer(packet: bytes, hosts: dict[str, str] | None = None) -> bytes:
    out = s.dns_answer(packet, lambda name: (hosts or {}).get(name, SELF_IP))
    assert out is not None
    return out


def _rcode(resp: bytes) -> int:
    return struct.unpack("!H", resp[2:4])[0] & 0xF


def _ancount(resp: bytes) -> int:
    return struct.unpack("!H", resp[6:8])[0]


def _status_body(resp: bytes) -> tuple[int, bytes]:
    head, _, body = resp.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), body


# ------------------------------------------------------------------- DNS codec


def test_parse_query_reads_name_type_and_id(dns_query):
    q = s.parse_query(dns_query("API.Stripe.com", qtype=28, qid=7))
    assert q is not None
    assert (q.id, q.name, q.qtype) == (7, "api.stripe.com", 28)


def test_a_query_for_known_host_gets_its_ip(dns_query):
    resp = _answer(dns_query("db"), {"db": "10.9.0.5"})
    assert resp[-4:] == socket.inet_aton("10.9.0.5")


def test_a_query_for_unknown_host_gets_sink_ip(dns_query):
    resp = _answer(dns_query("abc123.canary.invalid"))
    assert resp[-4:] == socket.inet_aton(SELF_IP)


def test_a_answer_is_well_formed(dns_query):
    query = dns_query("example.com", qid=0xBEEF)
    resp = _answer(query)
    assert resp[:2] == b"\xbe\xef"
    assert struct.unpack("!H", resp[2:4])[0] & 0x8000
    assert _ancount(resp) == 1
    assert resp[12:len(query)] == query[12:]  # question echoed verbatim
    assert _rcode(resp) == s.RCODE_NOERROR


def test_aaaa_query_gets_noerror_without_answers(dns_query):
    resp = _answer(dns_query("example.com", qtype=s.TYPE_AAAA))
    assert _rcode(resp) == s.RCODE_NOERROR
    assert _ancount(resp) == 0


def test_other_type_gets_empty_answer(dns_query):
    resp = _answer(dns_query("example.com", qtype=15))  # MX
    assert _ancount(resp) == 0


def test_non_query_opcode_is_notimp(dns_query):
    resp = _answer(dns_query("example.com", flags=0x2800))  # opcode 5 (UPDATE)
    assert _rcode(resp) == s.RCODE_NOTIMP


@pytest.mark.parametrize("packet", [
    b"",
    b"\x00" * 5,
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",  # no question
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05abc",  # truncated label
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01",  # pointer loop
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\xff\xfe\x00\x00\x01\x00\x01",  # non-ascii
    b"\x12\x34\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01",  # two questions
    b"\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01",  # a response
])
def test_malformed_packets_are_dropped(packet):
    assert s.dns_answer(packet, lambda _: SELF_IP) is None


# ------------------------------------------------------- hosts / stubs reload


def test_resolve_reloads_hosts_when_file_changes(tmp_path):
    hosts = tmp_path / "hosts.json"
    hosts.write_text(json.dumps({"db": "10.9.0.5"}))
    sink = s.Sink(SELF_IP, hosts_file=hosts)
    assert sink.resolve("DB.") == "10.9.0.5"
    hosts.write_text(json.dumps({"db": "10.9.0.66", "cache": "10.9.0.7"}))
    os.utime(hosts, ns=(1, 1))  # mtime_ns differs even on coarse-grained filesystems
    assert sink.resolve("db") == "10.9.0.66"


def test_missing_hosts_file_resolves_everything_to_sink(tmp_path):
    sink = s.Sink(SELF_IP, hosts_file=tmp_path / "nope.json")
    assert sink.resolve("db") == SELF_IP


def test_unknown_names_resolve_to_the_runners_sink_entry(tmp_path):
    hosts = tmp_path / "hosts.json"
    hosts.write_text(json.dumps({"sink": "10.9.0.2", "db": "10.9.0.5"}))
    sink = s.Sink(SELF_IP, hosts_file=hosts)
    assert sink.resolve("api.stripe.com") == "10.9.0.2"


def test_broken_hosts_file_keeps_last_good_value(tmp_path):
    hosts = tmp_path / "hosts.json"
    hosts.write_text(json.dumps({"db": "10.9.0.5"}))
    sink = s.Sink(SELF_IP, hosts_file=hosts)
    sink.resolve("db")
    hosts.write_text("{not json")
    assert sink.resolve("db") == "10.9.0.5"


def test_parse_hosts_skips_invalid_addresses():
    assert s.parse_hosts({"db": "10.0.0.1", "bad": "not-an-ip", "v6": "::1"}) == {"db": "10.0.0.1"}


def test_parse_stubs_accepts_wrapped_list():
    assert s.parse_stubs({"stubs": [{"host": "x"}]})[0].host == "x"


@pytest.mark.parametrize(("host", "method", "path", "expected"), [
    ("api.stripe.com", "POST", "/v1/charges", "charge"),
    ("api.stripe.com", "GET", "/v1/charges", "any"),
    ("hooks.slack.com", "POST", "/x", None),
])
def test_match_stub_uses_glob_method_and_prefix(host, method, path, expected):
    stubs = [StubSpec(host="*.stripe.com", method="post", path_prefix="/v1/charges", body="charge"),
             StubSpec(host="api.stripe.com", body="any")]
    hit = s.match_stub(stubs, host, method, path)
    assert (hit.body if hit else None) == expected


# ------------------------------------------------------------- HTTP helpers


@pytest.mark.parametrize(("raw", "host"), [("Sink:80", "sink"), ("[::1]:8080", "::1"), ("example.com.", "example.com")])
def test_host_only_strips_port_and_case(raw, host):
    assert s.host_only(raw) == host


def test_split_target_prefers_absolute_uri_host():
    assert s.split_target("http://evil.test:8080/a?b=1", "other") == ("evil.test", "/a", "b=1")


def test_record_matches_any_field():
    rec = s.make_record("1.2.3.4", "h", path="/p", query="q=tok%2Fen", headers={"X-A": "in-header"}, body=b"in-body")
    assert s.Recorder().hits("x") == []
    r = s.Recorder()
    r.add(rec)
    assert [len(r.hits(n)) for n in ("h", "/p", "tok/en", "in-header", "in-body", "absent")] == [1, 1, 1, 1, 1, 0]


def test_recorder_ring_is_bounded():
    r = s.Recorder(size=3)
    for i in range(5):
        r.add(s.make_record("ip", f"h{i}"))
    assert [x["host"] for x in r.ring] == ["h2", "h3", "h4"]


def test_recorder_writes_jsonl(tmp_path):
    log_file = tmp_path / "requests.jsonl"
    r = s.Recorder(log_file)
    r.add(s.make_record("ip", "a"))
    r.add(s.make_record("ip", "b"))
    assert [json.loads(line)["host"] for line in log_file.read_text().splitlines()] == ["a", "b"]


def test_recorder_survives_unwritable_log(tmp_path):
    r = s.Recorder(tmp_path / "missing-dir" / "requests.jsonl")
    r.add(s.make_record("ip", "a"))
    assert len(r.ring) == 1


def test_http_response_strips_injected_newlines_and_framing_headers():
    out = s.http_response(201, {"X-A": "a\r\nSet-Cookie: x", "Content-Length": "999"}, b"hi")
    assert b"X-A: aSet-Cookie: x\r\n" in out
    assert b"Content-Length: 999" not in out


# ----------------------------------------------------------------- SNI


def test_extract_sni_from_real_client_hello(client_hello):
    assert s.extract_sni(client_hello("Api.Stripe.com")) == "api.stripe.com"


def test_extract_sni_without_server_name(client_hello):
    assert s.extract_sni(client_hello(None)) is None


@pytest.mark.parametrize("record", [b"", b"\x16\x03\x01\x00\x05\x01\x00", b"\x17\x03\x03\x00\x01\x00", b"GET / HTTP/1.1\r\n"])
def test_extract_sni_rejects_garbage(record):
    assert s.extract_sni(record) is None


def test_extract_sni_on_truncated_hello(client_hello):
    hello = client_hello("example.com")
    assert all(s.extract_sni(hello[:n]) in (None, "example.com") for n in range(0, len(hello), 7))


# ------------------------------------------------------------- live server


async def _with_sink(tmp_path: Path, body):
    (tmp_path / "hosts.json").write_text(json.dumps({"db": "10.9.0.5"}))
    stubs = [{"host": "*.stripe.com", "path_prefix": "/v1", "status": 402, "body": "{\"error\": \"card\"}"}]
    (tmp_path / "stubs.json").write_text(json.dumps(stubs))
    sink = s.Sink(SELF_IP, tmp_path / "hosts.json", tmp_path / "stubs.json", tmp_path / "requests.jsonl")
    await sink.start("127.0.0.1", 0, 0, 0)
    try:
        return await body(sink)
    finally:
        sink.close()


def test_live_http_records_and_answers_default(tmp_path, raw_http):
    async def body(sink):
        resp = await raw_http(sink.ports["http"], b"POST /hook?id=TOKEN1 HTTP/1.1\r\nHost: abc.canary.invalid\r\n"
                                                  b"X-Trace: t\r\nContent-Length: 5\r\n\r\nhello")
        return resp, sink.recorder.ring[0]

    resp, rec = asyncio.run(_with_sink(tmp_path, body))
    assert _status_body(resp) == (200, b"{}")
    assert (rec["host"], rec["method"], rec["path"], rec["query"], rec["body"]) == \
        ("abc.canary.invalid", "POST", "/hook", "id=TOKEN1", "hello")
    assert rec["client_ip"] == "127.0.0.1"


def test_live_http_answers_from_stub(tmp_path, raw_http):
    async def body(sink):
        return await raw_http(sink.ports["http"], b"GET /v1/charges HTTP/1.1\r\nHost: api.stripe.com\r\n\r\n")

    assert _status_body(asyncio.run(_with_sink(tmp_path, body))) == (402, b'{"error": "card"}')


def test_live_hits_api_filters_and_is_not_recorded(tmp_path, raw_http):
    async def body(sink):
        port = sink.ports["http"]
        await raw_http(port, b"GET /a HTTP/1.1\r\nHost: x.test\r\nUser-Agent: CANARY42\r\n\r\n")
        await raw_http(port, b"GET /b HTTP/1.1\r\nHost: y.test\r\n\r\n")
        resp = await raw_http(port, b"GET /__prsec/hits?contains=CANARY42 HTTP/1.1\r\nHost: sink:80\r\n\r\n")
        return resp, len(sink.recorder.ring)

    resp, recorded = asyncio.run(_with_sink(tmp_path, body))
    status, payload = _status_body(resp)
    assert status == 200
    assert [h["path"] for h in json.loads(payload)["hits"]] == ["/a"]
    assert recorded == 2


def test_live_health(tmp_path, raw_http):
    async def body(sink):
        return await raw_http(sink.ports["http"], b"GET /__prsec/health HTTP/1.1\r\nHost: sink\r\n\r\n")

    assert json.loads(_status_body(asyncio.run(_with_sink(tmp_path, body)))[1]) == {"ok": True}


def test_live_large_body_is_truncated(tmp_path, raw_http):
    big = b"A" * (s.MAX_BODY + 1000)

    async def body(sink):
        head = f"PUT /up HTTP/1.1\r\nHost: h\r\nContent-Length: {len(big)}\r\n\r\n".encode()
        resp = await raw_http(sink.ports["http"], head + big)
        return resp, sink.recorder.ring[0]

    resp, rec = asyncio.run(_with_sink(tmp_path, body))
    assert _status_body(resp)[0] == 200
    assert len(rec["body"]) == s.MAX_BODY
    assert rec["body_truncated"] is True


def test_live_chunked_body_is_decoded(tmp_path, raw_http):
    async def body(sink):
        await raw_http(sink.ports["http"], b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
                                           b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        return sink.recorder.ring[0]["body"]

    assert asyncio.run(_with_sink(tmp_path, body)) == "hello world"


def test_live_garbage_gets_400_and_sink_keeps_serving(tmp_path, raw_http):
    async def body(sink):
        bad = await raw_http(sink.ports["http"], b"\x00\x01garbage\r\n\r\n")
        good = await raw_http(sink.ports["http"], b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
        return bad, good

    bad, good = asyncio.run(_with_sink(tmp_path, body))
    assert _status_body(bad)[0] == 400
    assert _status_body(good)[0] == 200


def test_live_tls_records_sni(tmp_path, client_hello):
    async def body(sink):
        reader, writer = await asyncio.open_connection("127.0.0.1", sink.ports["tls"])
        writer.write(client_hello("hooks.example.org"))
        await writer.drain()
        await asyncio.wait_for(reader.read(), 10)  # the sink closes after the hello
        writer.close()
        return sink.recorder.ring[0]

    rec = asyncio.run(_with_sink(tmp_path, body))
    assert (rec["host"], rec["tls"]) == ("hooks.example.org", True)


def test_live_dns_over_udp(tmp_path, dns_query):
    async def body(sink):
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            await loop.sock_sendto(sock, b"junk", ("127.0.0.1", sink.ports["dns"]))
            await loop.sock_sendto(sock, dns_query("db"), ("127.0.0.1", sink.ports["dns"]))
            data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 512), 5)
        return data

    assert asyncio.run(_with_sink(tmp_path, body))[-4:] == socket.inet_aton("10.9.0.5")


def test_jsonl_written_by_live_sink(tmp_path, raw_http):
    async def body(sink):
        await raw_http(sink.ports["http"], b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")

    asyncio.run(_with_sink(tmp_path, body))
    assert json.loads((tmp_path / "requests.jsonl").read_text())["path"] == "/x"


def test_parser_reads_ports_from_env(monkeypatch):
    monkeypatch.setenv("PRSEC_SINK_HTTP_PORT", "8080")
    assert s.build_parser().parse_args([]).http_port == 8080
