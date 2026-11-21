"""Machine-readable progress events for the GUI (RAMBreaker v2).

When RAMBREAKER_PROGRESS=1 the analysis process prints one line per event:
    @@RB {"ev": "...", "t": <epoch>, ...}
The GUI parses these from the child's stdout; everything else on stdout is
the human log. Without the env var every call is a no-op.

Events:
  stage        {"name", "state": "start"|"done"|"skip"|"fail", "detail"}
  batch        {"plugins": [...], "eta_s", "jobs", "engine"}
  plugin       {"plugin", "state": "running"|"done"|"failed"|"timeout"|"retry",
                "timeout_s", "expected_s", "duration_s", "rows"}
  info         {"msg"}            (plain-language narration)
  result       {"output_dir", "report"}
"""

import json
import os
import sys
import threading
import time

_ON = os.environ.get("RAMBREAKER_PROGRESS") == "1"
_lock = threading.Lock()


def enabled() -> bool:
    return _ON


def emit(ev: str, **fields) -> None:
    if not _ON:
        return
    rec = {"ev": ev, "t": round(time.time(), 3)}
    rec.update(fields)
    try:
        line = "@@RB " + json.dumps(rec, default=str)
        with _lock:
            out = sys.__stdout__ or sys.stdout
            out.write(line + "\n")
            out.flush()
    except Exception:
        pass


def stage(name: str, state: str = "start", detail: str = "") -> None:
    emit("stage", name=name, state=state, detail=detail)


def info(msg: str) -> None:
    emit("info", msg=msg)
