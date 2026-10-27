from pathlib import Path

import pytest

from prsec.citations import snippet, verify_all, verify_citation
from prsec.stages.outputs import Citation

CODE = """\
import os


def get_user(request):
    user_id = request.args["id"]
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)


def health():
    return "ok"
"""


@pytest.fixture
def root(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    (src / "app" / "views.py").write_text(CODE)
    (tmp_path / "secret.txt").write_text("top secret\n")
    return src


def cit(file="app/views.py", line=6, quote='query = f"SELECT * FROM users WHERE id = {user_id}"', end_line=None):
    return Citation(file=file, line=line, quote=quote, end_line=end_line)


def test_exact_quote(root):
    assert verify_citation(cit(), root) is None


def test_whitespace_and_small_drift_tolerated(root):
    assert verify_citation(cit(quote='  query =   f"SELECT * FROM users WHERE id = {user_id}"  '), root) is None
    assert verify_citation(cit(quote='query = f"SELECT * FROM user WHERE id={user_id}"'), root) is None


def test_line_off_by_two_is_tolerated(root):
    assert verify_citation(cit(line=4), root) is None
    assert verify_citation(cit(line=8), root) is None


def test_wrong_location_rejected(root):
    err = verify_citation(cit(line=11), root)
    assert err and "does not match" in err


def test_hallucinated_quote_rejected(root):
    err = verify_citation(cit(quote="cursor.execute('DELETE FROM users WHERE ' + name)"), root)
    assert err and "does not match" in err


def test_multiline_quote(root):
    quote = 'user_id = request.args["id"]\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    return db.execute(query)'
    assert verify_citation(cit(line=5, end_line=7, quote=quote), root) is None
    assert verify_citation(cit(line=5, quote=quote), root) is None


def test_quote_much_longer_than_window_rejected(root):
    err = verify_citation(cit(line=11, quote=CODE), root)
    assert err


def test_out_of_range(root):
    assert "out of range" in verify_citation(cit(line=99), root)
    assert "end_line out of range" in verify_citation(cit(line=6, end_line=99), root)
    assert "end_line out of range" in verify_citation(cit(line=6, end_line=5), root)


@pytest.mark.parametrize("file", ["../secret.txt", "app/../../secret.txt", "/etc/passwd", "."])
def test_traversal_rejected(root, file):
    err = verify_citation(cit(file=file, line=1, quote="top secret"), root)
    assert err and ("escapes" in err or "does not exist" in err)


def test_symlink_escape_rejected(root):
    (root / "link.txt").symlink_to(root.parent / "secret.txt")
    assert "escapes" in verify_citation(cit(file="link.txt", line=1, quote="top secret"), root)


def test_absolute_path_inside_root_accepted(root):
    assert verify_citation(cit(file=str(root / "app/views.py")), root) is None


def test_missing_file_and_short_quote(root):
    assert "does not exist" in verify_citation(cit(file="nope.py"), root)
    assert "too short" in verify_citation(cit(quote=" } "), root)


def test_verify_all(root):
    errs = verify_all([cit(), cit(line=99), cit(file="../secret.txt")], root)
    assert len(errs) == 2


def test_snippet(root):
    assert snippet(root, "app/views.py", 6) == '    query = f"SELECT * FROM users WHERE id = {user_id}"'
    assert snippet(root, "app/views.py", 5, 7).count("\n") == 2
    assert snippet(root, "../secret.txt", 1) == ""
    assert snippet(root, "app/views.py", 500) == ""


@pytest.mark.parametrize("quote", ["return", "return db", "self.", "if (", "{user_id}", "SELECT * FROM"])
def test_generic_fragment_rejected(root, quote):
    err = verify_citation(cit(line=7, quote=quote), root)
    assert err and ("full line" in err or "too short" in err or "does not match" in err)


def test_short_full_line_accepted(root):
    assert verify_citation(cit(line=11, quote='return "ok"'), root) is None
    assert verify_citation(cit(line=7, quote="return db.execute(query)"), root) is None


def test_container_workdir_path_accepted(root):
    assert verify_citation(cit(file="/work/src/app/views.py"), root) is None
    assert "escapes" in verify_citation(cit(file="/work/other/app/views.py"), root)
    assert snippet(root, "/work/src/app/views.py", 7) == "    return db.execute(query)"


def test_repo_relative(root):
    from prsec.citations import repo_relative

    assert repo_relative("/work/src/app/views.py") == "app/views.py"
    assert repo_relative("./app/views.py") == "app/views.py"
    assert repo_relative(str(root / "app/views.py"), root) == "app/views.py"
    assert repo_relative("app/views.py") == "app/views.py"
    assert repo_relative("/etc/passwd") == "/etc/passwd"
