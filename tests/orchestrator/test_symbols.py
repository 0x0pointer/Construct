from prsec.orchestrator.symbols import enclosing_symbol


def test_python_method(tmp_path):
    (tmp_path / "svc.py").write_text("class OrderService:\n    def refund(self, o):\n        x = 1\n        db.execute(q)\n\ndef top():\n    pass\n")
    assert enclosing_symbol(tmp_path, "svc.py", 4) == "OrderService.refund"
    assert enclosing_symbol(tmp_path, "svc.py", 7) == "top"


def test_go_receiver_and_js(tmp_path):
    (tmp_path / "h.go").write_text("package x\n\nfunc (s *Store) Get(id string) error {\n\treturn s.db.Query(id)\n}\n")
    assert enclosing_symbol(tmp_path, "h.go", 4) == "Store.Get"
    (tmp_path / "r.ts").write_text("export const getUser = async (req, res) => {\n  if (x) {\n    db.query(req.params.id)\n  }\n}\n")
    assert enclosing_symbol(tmp_path, "r.ts", 3) == "getUser"
    (tmp_path / "C.java").write_text("class C {\n  public User find(String id) {\n    return q(id);\n  }\n}\n")
    assert enclosing_symbol(tmp_path, "C.java", 3) == "find"


def test_traversal_and_missing(tmp_path):
    assert enclosing_symbol(tmp_path, "../etc/passwd", 1) is None
    assert enclosing_symbol(tmp_path, "nope.py", 1) is None
