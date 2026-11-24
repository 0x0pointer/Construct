from pathlib import Path
import re


ROOT = Path(__file__).parents[2]
TEMPLATE_DIR = ROOT / "prsec" / "dashboard" / "templates"
STATIC_DIR = ROOT / "prsec" / "dashboard" / "static"


def _dashboard_files():
    files = sorted(TEMPLATE_DIR.glob("*.html"))
    if STATIC_DIR.exists():
        files.extend(sorted(path for path in STATIC_DIR.rglob("*") if path.is_file()))
    return files


def test_dashboard_templates_do_not_load_remote_assets():
    remote_asset_patterns = [
        re.compile(r"""<(?:script|iframe)[^>]+\bsrc=["']https?://""", re.IGNORECASE),
        re.compile(r"""<link[^>]+\bhref=["']https?://""", re.IGNORECASE),
        re.compile(r"""url\(\s*["']?https?://""", re.IGNORECASE),
    ]
    for path in _dashboard_files():
        text = path.read_text()
        lowered = text.lower()
        for pattern in remote_asset_patterns:
            assert not pattern.search(text), f"remote asset reference found in {path}"
        for needle in ("unpkg.com", "htmx.org"):
            assert needle not in lowered, f"third-party asset reference found in {path}"


def test_dashboard_templates_do_not_introduce_unsafe_rendering_hooks():
    forbidden = [
        re.compile(r"\|safe\b"),
        re.compile(r"""\son[a-z]+\s*=""", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"eval\s*\(", re.IGNORECASE),
        re.compile(r"new Function\b", re.IGNORECASE),
    ]
    for path in TEMPLATE_DIR.glob("*.html"):
        text = path.read_text()
        for pattern in forbidden:
            assert not pattern.search(text), f"unsafe rendering hook found in {path}: {pattern.pattern}"


def test_base_template_defines_self_contained_responsive_design():
    base = (TEMPLATE_DIR / "base.html").read_text()
    for snippet in (
        ".topnav",
        ".app-main",
        ".page-header",
        ".card",
        ".table-wrap",
        "form.filters",
        ".badge",
        ":focus-visible",
        "@media (prefers-color-scheme: dark)",
        "@media (max-width: 900px)",
        "data-dashboard-partial",
        "data-poll-url",
    ):
        assert snippet in base
    assert "<script src=" not in base
    assert "htmx.org" not in base
