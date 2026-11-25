What I changed
- Restored the executable bit on `.fabro/scripts/fabro-run-titles` so it can still be run directly via its shebang.
- Added a regression test in `tests/fabro/test_run_titles.py` to assert the watcher script remains executable.

Coverage for the reviewer todo item
- Todo item 1 (`.fabro/scripts/fabro-run-titles` lost mode `100755`): covered by `tests/fabro/test_run_titles.py::test_watcher_script_remains_executable`.

Tests I ran
- `pytest tests/fabro/test_run_titles.py::test_watcher_script_remains_executable -q`
- `pytest tests/fabro/test_run_titles.py -q`
- `pytest -m 'not docker and not k8s and not live_harness' -q`

Noticed, not touched
- Pytest emits an existing `pytest_asyncio` deprecation warning about `asyncio_default_fixture_loop_scope`.
- Pytest emits an existing Starlette/httpx deprecation warning from `fastapi.testclient`.

STATUS: DONE