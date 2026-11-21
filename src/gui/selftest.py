"""GUI self-test: screenshots of every state + help coverage + layout checks.

Usage: python -m gui.selftest <screenshots_dir> [results_dir]
"""

import json
import sys
import time
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QLabel, QWidget

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))


def pump(sec=0.3):
    end = time.time() + sec
    app = QApplication.instance()
    while time.time() < end:
        app.processEvents()
        time.sleep(0.01)


def layout_issues(root: QWidget):
    issues = []
    for w in root.findChildren(QLabel):
        if not w.isVisible() or w.wordWrap() or not w.text() or "<" in w.text():
            continue
        need = w.fontMetrics().horizontalAdvance(w.text().split("\n")[0])
        if need > w.width() + 2 and w.width() > 0:
            issues.append(f"truncated label: '{w.text()[:50]}' needs {need}px has {w.width()}px")
    for w in root.findChildren(QWidget):
        if w.isVisible() and w.property("help_key") and (w.width() < 8 or w.height() < 8):
            issues.append(f"tiny control: {w.metaObject().className()} {w.property('help_key')}")
    return issues


def extraction_pages(w, shot, report, check):
    """Extraction workspace on the loaded case: every page, real data."""
    xv = w.xview
    w.open_extract()
    for _ in range(60):                      # lists load in background threads
        pump(0.25)
        if not xv._loaders:
            break
    xv.dump.setText(xv.dump.text())
    report["extract_counts"] = {"files": len(xv.f_model.rows), "procs": len(xv.p_model.rows)}
    xv.tabs.setCurrentIndex(0)
    xv.f_search.setText({"linux": "/etc/", "mac": "/etc/"}.get(xv.info.get("os"), "evtx"))
    pump(0.6)
    ids = xv.f_proxy.visible_ids()[:3]
    xv.f_model.set_checked(ids)
    pump(0.4)
    shot("extract_files_dark")
    report["extract_files_shown"] = xv.f_proxy.rowCount()
    xv.tabs.setCurrentIndex(1)
    xv.p_flagged.setChecked(any(r["flags"] for r in xv.p_model.rows))
    xv.p_model.set_checked([r["pid"] for r in xv.p_model.rows if r["flags"]][:2])
    pump(0.6)
    shot("extract_processes_dark")
    xv.p_flagged.setChecked(False)
    xv.tabs.setCurrentIndex(2)
    xv.v_mode_reg.setChecked(True)
    flagged = [r for r in xv.v_pmodel.rows if any("Injection" in f for f in r["flags"])] or xv.v_pmodel.rows[:1]
    if flagged:
        pid = flagged[0]["pid"]
        for i in range(xv.v_pproxy.rowCount()):
            ix = xv.v_pproxy.index(i, 1)
            if str(ix.data()) == pid:
                xv.v_pview.setCurrentIndex(ix)
                break
        for _ in range(60):
            pump(0.25)
            if not xv._loaders:
                break
        xv.v_inj_b.click()
        pump(0.4)
        report["extract_regions"] = {"pid": pid, "regions": len(xv.v_rmodel.rows),
                                     "checked": len(xv.v_rmodel.checked)}
    shot("extract_vad_region_dark")
    xv.v_mode_proc.setChecked(True)
    pump(0.4)
    shot("extract_vad_process_dark")
    xv.tabs.setCurrentIndex(3)
    xv.h_terms.setPlainText("go.microsoft.com\nzqxjNotPresent7731")
    pump(0.4)
    shot("extract_hunt_dark")
    xv.tabs.setCurrentIndex(4)
    pump(0.4)
    shot("extract_export_dark")
    report["help_extract"] = check(xv)
    report["layout_extract"] = layout_issues(w)
    w.apply_theme("light")
    xv.tabs.setCurrentIndex(2)
    pump(0.6)
    shot("extract_vad_light")
    w.apply_theme("dark")
    from gui.widgets import HelpPopup
    p = HelpPopup.show_for("x.v.modereg", xv.v_mode_reg)
    pump(0.4)
    w.grab().save(str(Path(sys.argv[1]) / "gui_extract_help_vadmode.png"))
    p.close()


def guides_and_controls(w, out, report):
    """Click the real '?' of each guided setting like a user, walk every page and
    animation frame, and check what the split Plugin category / Fast mode
    controls hand to the CLI for every preset."""
    from gui import main_window as mw
    from gui.widgets import HelpButton
    from gui.help_guide import GuideWindow
    g = {}
    for theme in ("dark", "light"):
        w.apply_theme(theme)
        pump(0.3)
        for key in ("setup.preset", "setup.category", "setup.fastmode", "setup.speed"):
            btn = next((b for b in w.findChildren(HelpButton) if b.property("help_key") == key), None)
            if btn is None:
                g[f"{theme}:{key}"] = {"error": "no ? button"}
                continue
            btn.click()
            pump(0.5)
            win = GuideWindow._open.get(key)
            if win is None:
                g[f"{theme}:{key}"] = {"error": "guide did not open"}
                continue
            pages = []
            for i in range(len(win.g["pages"])):
                win.pages.setCurrentRow(i)
                pump(0.3)
                mv = win.movie
                n = mv.frameCount() if mv else 0
                frames = []
                for f in range(max(1, n)):
                    if mv:
                        win._step(1 if f else 0)
                        pump(0.15)
                    frames.append(win.step.text())
                    if theme == "dark" or i == 0:
                        win.grab().save(str(out / f"gui_guide_{theme}_{key.split('.')[1]}_p{i}_f{f}.png"))
                text = win.text.toPlainText()
                pages.append({"page": win.g["pages"][i][0], "movie_ok": bool(mv and mv.isValid()),
                              "frames": n, "steps_seen": frames, "text_chars": len(text),
                              "unfilled": "{" in text and "}" in text})
            g[f"{theme}:{key}"] = {"title": win.windowTitle(), "modal": win.isModal(), "pages": pages}
            win.close()
            pump(0.2)
    w.apply_theme("dark")
    report["guides"] = g
    # controls -> CLI -m for every preset, and the Fast mode lock
    s = w.setup
    s.dump.setText("C:/fake.raw")
    rows = []
    for i, (name, cmd, mode) in enumerate(mw.PRESETS):
        s.preset.setCurrentIndex(i)
        pump(0.05)
        a = s.build_args(w.s)
        rows.append({"preset": name, "expect": [cmd, mode], "got": [a[0], a[a.index("-m") + 1]],
                     "fast_box": s.fast.isChecked(), "category_enabled": s.category.isEnabled()})
    report["presets_to_cli"] = rows
    s.preset.setCurrentIndex(0)
    s.fast.setChecked(False)
    s.category.setCurrentIndex(2)
    s.fast.setChecked(True)
    pump(0.2)
    shot_path = out / "gui_setup_fastmode_on.png"
    w.grab().save(str(shot_path))
    report["fast_lock"] = {"m": s.build_args(w.s)[s.build_args(w.s).index("-m") + 1],
                           "category": s.category.currentText(), "category_enabled": s.category.isEnabled(),
                           "note_visible": s.fast_note.isVisible()}
    s.fast.setChecked(False)
    s.category.setCurrentIndex(2)
    report["category_only"] = s.build_args(w.s)[s.build_args(w.s).index("-m") + 1]
    s.preset.setCurrentIndex(1)
    pump(0.2)
    w.grab().save(str(out / "gui_setup_standard.png"))


def main():
    main_with_app(QApplication(sys.argv))


def main_with_app(app):
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    res_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    from gui import main_window as mw
    from gui.help_check import check
    mw.load_settings = lambda: dict(mw.DEFAULT_SETTINGS, tour_on_start=False)
    mw.save_settings = lambda s: None
    w = mw.MainWindow()
    w.resize(1600, 960)
    w.show()
    pump(0.8)
    report = {}
    shot = lambda name: (w.grab().save(str(out / f"gui_{name}.png")), report.setdefault("shots", []).append(name))
    shot("idle_dark")
    report["help_main"] = check(w)
    report["layout_idle"] = layout_issues(w)
    # dialogs: help coverage too
    for cls in (mw.SettingsDialog, mw.GlossaryDialog, mw.AboutDialog):
        d = cls(w.s, w) if cls is mw.SettingsDialog else cls(w)
        d.show()
        pump(0.3)
        d.grab().save(str(out / f"gui_dialog_{cls.__name__}.png"))
        report[f"help_{cls.__name__}"] = check(d)
        d.close()
    # loading state: synthetic progress events through the real handlers
    w.setup.dump.setText(str(res_dir or "C:/fake.raw"))
    w.state = {"plugins": {}, "total": 0, "done": 0, "failed": 0, "timeouts": 0, "jobs": 4,
               "expected": {}, "detect_done": False, "step": 0, "steps": 8, "size_gb": 2.0,
               "cmd": "core", "batch_t": time.time(), "running_since": {}}
    w.t0 = time.time() - 95
    w.monitor.anim.start()
    w._spin.start()
    plugs = ["windows.info.Info", "windows.pslist.PsList", "windows.pstree.PsTree",
             "windows.cmdline.CmdLine", "windows.netscan.NetScan", "windows.malfind.Malfind",
             "windows.dlllist.DllList", "windows.handles.Handles", "windows.svcscan.SvcScan",
             "windows.filescan.FileScan", "windows.mftscan.MFTScan", "windows.vadinfo.VadInfo"]
    w._on_event({"ev": "stage", "name": "Detecting OS", "state": "start"})
    w._on_event({"ev": "stage", "name": "Detecting OS", "state": "done", "os_type": "windows",
                 "engine": "vol3"})
    w._on_event({"ev": "stage", "name": "Running Volatility plugins (parallel)", "state": "start",
                 "index": 1, "of": 8})
    w._on_event({"ev": "batch", "plugins": plugs, "jobs": 4, "eta_s": 180,
                 "expected": {p: 5 + 4 * i for i, p in enumerate(plugs)}})
    for p in plugs[:7]:
        w._on_event({"ev": "plugin", "plugin": p, "state": "running", "timeout_s": 300})
        w._on_event({"ev": "plugin", "plugin": p, "state": "done", "duration_s": 3.2})
    w._on_event({"ev": "plugin", "plugin": plugs[7], "state": "failed", "duration_s": 1.1})
    for p in plugs[8:11]:
        w._on_event({"ev": "plugin", "plugin": p, "state": "running", "timeout_s": 420})
    w._on_event({"ev": "plugin", "plugin": plugs[11], "state": "running", "timeout_s": 120})
    w._on_event({"ev": "plugin", "plugin": plugs[11], "state": "retry", "timeout_s": 300})
    for lvl, t in (("info", "[i] Step 1/8: Running Volatility plugins (parallel)..."),
                   ("ok", "[+] [7/12] windows.dlllist.DllList completed (3.2s)"),
                   ("warn", "[!] windows.vadinfo.VadInfo timed out after 120s - killed; retrying once"),
                   ("error", "[x] windows.handles.Handles FAILED: Unsatisfied requirement")):
        w._on_log(lvl, t)
    w.runner.last_activity = time.time()
    w._tick.start()
    w.runner.running = lambda: True
    w._update_actions()
    pump(1.5)
    w._heartbeat()
    pump(0.5)
    shot("loading_dark")
    report["layout_loading"] = layout_issues(w)
    # responsiveness probe: event-loop latency while animating
    lat = []
    for _ in range(20):
        t = time.time()
        QTimer.singleShot(0, lambda: lat.append(time.time() - t))
        pump(0.05)
    report["event_loop_latency_ms_max"] = round(1000 * max(lat), 1) if lat else None
    # finished state with real results
    w.runner.running = lambda: False
    if res_dir and res_dir.is_dir():
        w.case = res_dir
        w._on_finished(0, False)
        pump(1.0)
        shot("finished_dark")
        # open a few result tabs
        for i in range(w.results.tree.topLevelItem(0).childCount()):
            it = w.results.tree.topLevelItem(0).child(i)
            if it.text(0) in ("Processes", "Network"):
                w.results._open_item(it, 0)
        pump(0.6)
        shot("results_tabs_dark")
        report["help_results"] = check(w)
        extraction_pages(w, shot, report, check)
    # error state
    w.runner.running = lambda: False
    w._on_finished(1, False)
    pump(0.5)
    shot("error_dark")
    # light theme
    w.apply_theme("light")
    pump(0.6)
    shot("finished_light")
    w.apply_theme("dark")
    # help popup + tour
    from gui.widgets import HelpPopup
    p = HelpPopup.show_for("setup.known", w.setup.known)
    pump(0.4)
    w.grab().save(str(out / "gui_help_popup_window.png"))
    p.grab().save(str(out / "gui_help_popup.png"))
    p.close()
    guides_and_controls(w, out, report)
    w.start_tour()
    pump(0.6)
    w.grab().save(str(out / "gui_tour.png"))
    (out / "gui_selftest.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    m = report["help_main"]
    print(f"help main: ok={m['ok']} missing={len(m['missing'])} invalid={len(m['invalid'])}")
    for k, v in report.items():
        if k.startswith("help_") and (v["missing"] or v["invalid"]):
            print(k, "MISSING:", v["missing"][:20], "INVALID:", v["invalid"][:10])
    print("layout idle:", report["layout_idle"][:10])
    print("layout loading:", report["layout_loading"][:10])
    print("latency ms max:", report["event_loop_latency_ms_max"])
    for k, v in report.get("guides", {}).items():
        if "error" in v:
            print("GUIDE", k, "ERROR", v["error"])
            continue
        bad = [p["page"] for p in v["pages"] if not p["movie_ok"] or p["text_chars"] < 200 or p["unfilled"]]
        print(f"guide {k}: {len(v['pages'])} pages, frames {[p['frames'] for p in v['pages']]}, "
              f"modal={v['modal']}, bad={bad}")
    bad = [r for r in report.get("presets_to_cli", []) if r["got"] != r["expect"]]
    print("presets -> CLI:", len(report.get("presets_to_cli", [])), "checked, mismatches:", bad)
    print("fast lock:", report.get("fast_lock"), " category only -m:", report.get("category_only"))


if __name__ == "__main__":
    main()
