import pytest

from prsec.sarif.fingerprint import fingerprint, normalise_entry_point, normalise_file, normalise_symbol

BASE = fingerprint("sqli", "app/orders.py", "OrderRepo.find", "GET /orders/{id}")


def test_shape():
    assert len(BASE) == 32 and int(BASE, 16) >= 0


@pytest.mark.parametrize(
    "file,symbol,ep",
    [
        ("./app/orders.py", "OrderRepo.find", "GET /orders/{id}"),
        ("app/orders.PY", "OrderRepo.find", "GET /orders/{id}"),
        ("app\\orders.py", "OrderRepo.find", "GET /orders/{id}"),
        ("/app/orders.py", "OrderRepo.find", "GET /orders/{id}"),
        ("app/orders.py", "  OrderRepo.find(self, order_id: int) ", "GET /orders/{id}"),
        ("app/orders.py", "def OrderRepo.find(self)", "GET /orders/{id}"),
        ("app/orders.py", "OrderRepo::find", "GET /orders/{id}"),
        ("app/orders.py", "OrderRepo.find", "get /orders/123"),
        ("app/orders.py", "OrderRepo.find", "GET /orders/:id"),
        ("app/orders.py", "OrderRepo.find", "GET  /orders/<int:order_id>?debug=1"),
        ("app/orders.py", "OrderRepo.find", "GET /orders/[orderId]/"),
        ("app/orders.py", "OrderRepo.find", "GET /orders/0b7e4c1a-1f2e-4d3c-9a8b-7c6d5e4f3a2b"),
    ],
)
def test_stable_across_cosmetic_changes(file, symbol, ep):
    assert fingerprint("sqli", file, symbol, ep) == BASE


def test_line_numbers_do_not_participate():
    # The API has no line input at all: moving the sink inside the same symbol keeps identity.
    assert fingerprint("sqli", "app/orders.py", "OrderRepo.find", "GET /orders/1") == BASE


@pytest.mark.parametrize(
    "args",
    [
        ("xss", "app/orders.py", "OrderRepo.find", "GET /orders/{id}"),
        ("sqli", "app/order_repo.py", "OrderRepo.find", "GET /orders/{id}"),
        ("sqli", "app/orders.py", "OrderRepo.find_all", "GET /orders/{id}"),
        ("sqli", "app/orders.py", "OrderRepo.find", "POST /orders/{id}"),
        ("sqli", "app/orders.py", "OrderRepo.find", "GET /orders/{id}/items"),
        ("sqli", "app/orders.py", None, "GET /orders/{id}"),
        ("sqli", "app/orders.py", "OrderRepo.find", None),
    ],
)
def test_identity_changes(args):
    assert fingerprint(*args) != BASE


def test_normalisers():
    assert normalise_file("./src//a/./B.TS") == "src/a/B.ts"
    assert normalise_file("Makefile") == "Makefile"
    assert normalise_symbol("async function handler(req, res)") == "handler"
    assert normalise_symbol("Foo#bar") == "Foo.bar"
    assert normalise_entry_point("queue  consumer   orders.created") == "queue consumer orders.created"
    assert normalise_entry_point("/a/42/b") == "/a/{}/b"
    assert normalise_entry_point("POST /api/v1/users") == "POST /api/v1/users"  # v1 is not a param
