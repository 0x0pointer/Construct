"""A tiny stand-in for an agent CLI. Behaviour is selected by $FAKE_MODE.

usage: fake_harness_cli.py <output_path> <state_dir> [--resume SID]   (prompt on stdin)
"""
import json
import sys
import time
from pathlib import Path

VALID = {"decision": "light", "rationale": "touches the login handler", "risk_tags": ["authz"]}
INVALID = {"decision": "maybe", "rationale": 42}


def emit(obj) -> None:
    print(json.dumps(obj), flush=True)


def main() -> int:
    import os

    out, state = Path(sys.argv[1]), Path(sys.argv[2])
    resume = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--resume" else None
    prompt = sys.argv[5] if resume and len(sys.argv) > 5 else sys.stdin.read()
    mode = os.environ.get("FAKE_MODE", "valid")

    counter = state / "fake_calls"
    n = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(n))
    with (state / "prompts.jsonl").open("a") as f:
        f.write(json.dumps({"call": n, "resume": resume, "prompt": prompt}) + "\n")

    emit({"type": "session", "id": resume or f"sess-{n}"})
    emit({"type": "message", "text": f"call {n} mode {mode}"})
    emit({"type": "tool_call", "tool": "bash", "input": "cat /work/in/diff.patch"})
    usd = 10.0 if mode == "expensive" else 0.01
    emit({"type": "usage", "usd": usd, "in": 100, "out": 20})

    if resume is not None and resume != "sess-1":
        print(f"unknown session {resume}", file=sys.stderr)
        return 9

    def write(doc) -> None:
        out.write_text(doc if isinstance(doc, str) else json.dumps(doc))

    match mode:
        case "valid":
            write(VALID)
        case "invalid_then_valid":
            write(INVALID if n == 1 else VALID)
        case "not_json_then_valid":
            write("here is my answer: {decision: light}" if n == 1 else VALID)
        case "never_valid" | "expensive":
            write(INVALID)
        case "no_output":
            pass
        case "sleep":
            time.sleep(60)
        case "write_then_sleep":
            write(VALID)
            time.sleep(60)
        case "garbage_ok":
            print("\x00\x1b[31mnot json at all {{{", flush=True)
            print("", flush=True)
            print('{"type": 17}', flush=True)
            write(VALID)
        case "garbage_crash":
            print("\x00\x1b[31mSegmentation fault (core dumped) {{{", flush=True)
            print("fatal: auth failed", file=sys.stderr)
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
