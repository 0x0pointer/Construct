import json

import pytest

from prsec.sandbox.cli.cite import main

CODE = "def handler(req):\n    name = req.args['n']\n    os.system('echo ' + name)\n"


@pytest.fixture
def root(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "h.py").write_text(CODE)
    return src


def write(tmp_path, doc):
    p = tmp_path / "out.json"
    p.write_text(json.dumps(doc))
    return p


def test_all_ok(tmp_path, root, capsys):
    doc = {"hypothesis_id": "H1", "citations": [{"file": "h.py", "line": 3, "quote": "os.system('echo ' + name)"}],
           "guards": [{"description": "none", "citation": {"file": "h.py", "line": 2, "quote": "name = req.args['n']"}}]}
    assert main(["check", str(write(tmp_path, doc)), "--root", str(root)]) == 0
    out = capsys.readouterr().out
    assert "2/2 citations verified" in out and "$.guards[0].citation" in out


def test_failure_exits_1(tmp_path, root, capsys):
    doc = {"sink": {"file": "h.py", "line": 3, "quote": "subprocess.run(cmd, shell=True)"},
           "path": [{"file": "../etc/passwd", "line": 1, "quote": "root:x:0:0"}, {"file": "h.py", "line": 0, "quote": "x"}]}
    assert main(["check", str(write(tmp_path, doc)), "--root", str(root)]) == 1
    out = capsys.readouterr().out
    assert out.count("FAIL") == 3 and "malformed citation" in out and "0/3" in out


def test_root_from_env(tmp_path, root, monkeypatch):
    monkeypatch.setenv("PRSEC_CITE_ROOT", str(root))
    doc = [{"file": "h.py", "line": 1, "quote": "def handler(req):"}]
    assert main(["check", str(write(tmp_path, doc))]) == 0


def test_no_citations_and_bad_input(tmp_path, root, capsys):
    assert main(["check", str(write(tmp_path, {"a": 1})), "--root", str(root)]) == 0
    assert "no citations found" in capsys.readouterr().out
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert main(["check", str(bad), "--root", str(root)]) == 2
    assert main(["check", str(bad), "--root", str(tmp_path / "missing")]) == 2
