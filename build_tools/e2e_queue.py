"""GUI end-to-end test of the dump queue (v2.4): drives the real MainWindow offscreen with real
analysis child processes. usage: e2e_queue.py <out_dir> <shots_dir> <preset index> <dump> <dump> [...]
Exit 0 = every check passed. A JSON report is written to <shots_dir>/e2e_queue.json."""
import json
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))
from PySide6.QtWidgets import QApplication, QMessageBox

OUT, SHOTS, PRESET = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
DUMPS = sys.argv[4:]
SHOTS.mkdir(parents=True, exist_ok=True)
app = QApplication([])
from gui import main_window as mw

mw.load_settings = lambda: dict(mw.DEFAULT_SETTINGS, tour_on_start=False)
mw.save_settings = lambda s: None
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.Yes)
QMessageBox.information = staticmethod(lambda *a, **k: QMessageBox.Ok)
QMessageBox.warning = staticmethod(lambda *a, **k: QMessageBox.Ok)
rep = {"checks": [], "runs": []}


def check(name, cond, detail=""):
    rep["checks"].append({"name": name, "ok": bool(cond), "detail": str(detail)[:300]})
    print(("PASS " if cond else "FAIL ") + name, detail if not cond else "", flush=True)


def pump(secs):
    end = time.time() + secs
    while time.time() < end:
        app.processEvents()
        time.sleep(0.05)


w = mw.MainWindow()
w.resize(1600, 960)
w.show()
w.setup.out.setText(str(OUT))
w.setup.preset.setCurrentIndex(PRESET)
pump(0.5)
check("queue is empty, Start queue disabled", not w.setup.qstart.isEnabled() and w.setup.qlist.count() == 0)

# one dump through the 'Memory dump' field, the rest as a multi-file drop / picker result
w.setup.dump.setText(DUMPS[0])
w.queue_add()
w.setup.dump.setText("")
w.queue_add(DUMPS[1:] + [DUMPS[0], str(OUT / "does_not_exist.raw")])     # a duplicate + a missing file
pump(0.3)
check("all dumps queued once (duplicate and missing file ignored)",
      w.setup.qlist.count() == len(DUMPS) == len(w.run_queue), (w.setup.qlist.count(), len(w.run_queue)))
check("Start queue enabled and shows the count", w.setup.qstart.isEnabled() and f"({len(DUMPS)})" in w.setup.qstart.text(),
      w.setup.qstart.text())
cases = [Path(q["case"]) for q in w.run_queue]
check("every dump has its own case folder", len(set(cases)) == len(cases), cases)
w.grab().save(str(SHOTS / "queue_ready.png"))

t0 = time.time()
w.queue_start()
pump(2)
check("first dump started, the others wait", w.runner.running() and len(w.run_queue) == len(DUMPS) - 1 and w.queue_active)
check("status bar names the queue position", "Queue 1/" in w.st_msg.text() if hasattr(w, "st_msg") else True)
order, seen, shot = [], None, False
deadline = time.time() + float(os.environ.get("RB_QUEUE_TIMEOUT", "5400"))
while w.queue_active and time.time() < deadline:
    pump(1)
    cur = w._queue_cur["dump"] if w._queue_cur else None
    if cur and cur != seen:
        seen = cur
        order.append(cur)
        print(f"[{int(time.time() - t0)} s] running {Path(cur).name}; waiting: {len(w.run_queue)}", flush=True)
    if not shot and w.runner.running() and time.time() - t0 > 20:
        w.grab().save(str(SHOTS / "queue_running.png"))
        shot = True
pump(2)
w.grab().save(str(SHOTS / "queue_done.png"))
check("queue ended by itself", not w.queue_active and not w.runner.running(), f"timeout={time.time() >= deadline}")
check("dumps ran in the order they were queued", [str(Path(o)) for o in order] == [str(Path(d)) for d in DUMPS], order)
check("queue list is empty afterwards", w.setup.qlist.count() == 0 and not w.run_queue)
log_text = "\n".join(str(x) for x in getattr(w.log, "_lines", [])) if hasattr(w.log, "_lines") else ""
for c, d in zip(cases, DUMPS):
    summ = c / "SUMMARY.txt"
    jsons = list((c / "json").glob("*.json")) if (c / "json").is_dir() else []
    ok_n = fail_n = None
    if summ.is_file():
        t = summ.read_text(encoding="utf-8", errors="replace")
        for ln in t.splitlines():
            if ln.startswith("Succeeded:"):
                ok_n = int(ln.split(":")[1])
            if ln.startswith("Failed:"):
                fail_n = int(ln.split(":")[1])
    rep["runs"].append({"dump": d, "case": str(c), "summary": summ.is_file(), "json_files": len(jsons),
                        "succeeded": ok_n, "failed": fail_n})
    check(f"{Path(d).name}: analysis output exists (SUMMARY + plugin JSON)", summ.is_file() and len(jsons) >= 5,
          (summ.is_file(), len(jsons)))
    check(f"{Path(d).name}: plugins succeeded", (ok_n or 0) >= 5 and (fail_n or 0) <= 2, (ok_n, fail_n))
check("the last case is the one loaded in the window", w.case is not None and Path(w.case) == cases[-1], w.case)
check("queue results recorded for every dump, all completed",
      len(rep["runs"]) == len(DUMPS) and "Queue finished" in w.monitor.stage.text(), w.monitor.stage.text())
rep["seconds"] = round(time.time() - t0)
rep["stage_text"] = w.monitor.stage.text()
(SHOTS / "e2e_queue.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
bad = [c for c in rep["checks"] if not c["ok"]]
print(f"RESULT {len(rep['checks']) - len(bad)} / {len(rep['checks'])}  ({rep['seconds']} s)", flush=True)
w.close()
os._exit(1 if bad else 0)
