"""EventTail: incremental, no-follow reader of the stage's live events.jsonl."""
import json
import os

from prsec.adapters.runner import common
from prsec.adapters.runner.common import EVENTS_FILE, EventTail
from prsec.sandbox.entrypoint import run


def line(text: str) -> str:
    return json.dumps({"kind": "message", "text": text}) + "\n"


def test_file_name_matches_the_entrypoint():
    assert EVENTS_FILE == run.EVENTS_FILE


def test_missing_file_reads_nothing(tmp_path):
    assert EventTail(tmp_path).read() == []


def test_reads_only_new_complete_lines(tmp_path):
    t = EventTail(tmp_path)
    f = tmp_path / EVENTS_FILE
    f.write_text(line("a") + '{"kind": "mess')
    assert [e["text"] for e in t.read()] == ["a"]
    with f.open("a") as fh:
        fh.write('age", "text": "b"}\n' + line("c"))
    assert [e["text"] for e in t.read()] == ["b", "c"]
    assert t.read() == []


def test_skips_garbage(tmp_path):
    (tmp_path / EVENTS_FILE).write_text("not json\n[1]\n\n" + line("ok"))
    assert [e["text"] for e in EventTail(tmp_path).read()] == ["ok"]


def test_rewritten_file_is_read_from_the_start(tmp_path):
    t = EventTail(tmp_path)
    f = tmp_path / EVENTS_FILE
    f.write_text(line("first") + line("second"))
    t.read()
    f.write_text(line("new"))
    assert [e["text"] for e in t.read()] == ["new"]


def test_symlink_is_not_followed(tmp_path):
    target = tmp_path / "host.jsonl"
    target.write_text(line("secret"))
    out = tmp_path / "out"
    out.mkdir()
    (out / EVENTS_FILE).symlink_to(target)
    assert EventTail(out).read() == []


def test_fifo_is_not_read(tmp_path):
    os.mkfifo(tmp_path / EVENTS_FILE)
    assert EventTail(tmp_path).read() == []


def test_read_is_bounded_and_overlong_partial_line_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "TAIL_READ_MAX", 64)
    monkeypatch.setattr(common, "TAIL_LINE_MAX", 100)
    f = tmp_path / EVENTS_FILE
    f.write_text("x" * 300 + "\n" + line("after"))
    t = EventTail(tmp_path)
    got = []
    for _ in range(20):
        got += t.read()
    assert [e["text"] for e in got] == ["after"]
