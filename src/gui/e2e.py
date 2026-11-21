"""End-to-end GUI run: real analysis child process, screenshots, checks.

RAMBreaker.exe --e2e <dump> <shots_dir> [preset_index] [ioc_list]
"""

import json
import os
import time
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication


def run(dump: str, shots: str, preset: int = 1, ioc: str = "") -> int:
    from gui import main_window as mw
    app = QApplication.instance()
    mw.load_settings = lambda: dict(mw.DEFAULT_SETTINGS, tour_on_start=False)
    mw.save_settings = lambda s: None
    out = Path(shots)
    out.mkdir(parents=True, exist_ok=True)
    w = mw.MainWindow()
    w.resize(1600, 960)
    w.show()
    w.setup.dump.setText(dump)
    w.setup.preset.setCurrentIndex(preset)
    if ioc:
        w.setup.ioc.setText(ioc)
    import os
    if os.environ.get("RB_E2E_OS"):                 # "I already know this image"
        w.setup.known.setChecked(True)
        w.setup.os.setCurrentText(os.environ["RB_E2E_OS"])
        w.setup.v2zip.setText(os.environ.get("RB_E2E_V2ZIP", ""))
        w.setup.profile.setCurrentText(os.environ.get("RB_E2E_PROFILE", ""))
    rep = {"dump": dump, "preset": mw.PRESETS[preset][0], "lat_ms": [], "shots": []}

    # DFIR + Threat Intel: answer the options window like a user (local checks only unless
    # RB_E2E_VTKEY is set), screenshot it, and check the threat-intel output afterwards
    class _AutoTI(mw.ThreatIntelDialog):
        def exec(self):
            self.show()
            QApplication.processEvents()
            time.sleep(0.4)
            QApplication.processEvents()
            self.grab().save(str(out / "e2e_ti_dialog.png"))
            rep["shots"].append("e2e_ti_dialog")
            key = os.environ.get("RB_E2E_VTKEY", "")
            self.key.setText(key)
            self.remember.setChecked(False)
            self.novt.setChecked(not key)
            if os.environ.get("RB_E2E_YARASET"):
                self.yset.setCurrentIndex(max(0, self.yset.findData(os.environ["RB_E2E_YARASET"])))
            rep["ti_dialog"] = {"databases": self.db.table.rowCount(), "db_state": self.db.state.text(),
                                "vt": bool(key), "cli": self.cli_args()}
            self._accept()
            return True
    mw.ThreatIntelDialog = _AutoTI
    t0 = time.time()
    last = {"t": time.time()}

    def probe():                       # UI responsiveness: timer drift
        now = time.time()
        rep["lat_ms"].append(round((now - last["t"] - 0.25) * 1000, 1))
        last["t"] = now

    pt = QTimer(interval=250, timeout=probe)
    pt.start()
    shots_at = [15, 60, 180]

    def snap():
        el = time.time() - t0
        while shots_at and el >= shots_at[0]:
            n = f"e2e_running_{shots_at.pop(0)}s"
            w.grab().save(str(out / f"{n}.png"))
            rep["shots"].append(n)

    st = QTimer(interval=1000, timeout=snap)
    st.start()

    def done(code, stopped):
        rep["exit_code"] = code
        rep["duration_s"] = round(time.time() - t0, 1)
        if code == 0 and os.environ.get("RB_E2E_EXTRACT") == "1":
            QTimer.singleShot(1500, extract_chain)
        else:
            QTimer.singleShot(1500, finish)

    # ---- optional: drive the Extraction workspace like a user (RB_E2E_EXTRACT=1)
    xsteps = []

    def extract_chain():
        w.grab().save(str(out / "e2e_finished.png"))
        w.open_extract()
        xv = w.xview
        rep["extract"] = []

        def wait_lists(then, n=[0]):
            if xv._loaders and n[0] < 240:
                n[0] += 1
                QTimer.singleShot(250, lambda: wait_lists(then))
            else:
                then()

        def step_files():
            picks = {"windows": ("\\drivers\\etc\\hosts", "system.evtx"), "linux": ("/etc/passwd", "/etc/hosts"),
                     "mac": ("/private/var/log/system.log", "/private/etc/hosts")}.get(xv.info.get("os"), ())
            ids = [xv.f_model.rid(r) for r in xv.f_model.rows if r.get("dumpable")
                   and any(r["path"].lower().endswith(p) for p in picks)][:3]
            xv.tabs.setCurrentIndex(0)
            xv.f_model.set_checked(ids)
            w.grab().save(str(out / "e2e_extract_files_ticked.png"))
            xsteps.append("files")
            xv.f_go.click() if ids else next_step("")

        def step_procs():
            rows = [r for r in xv.p_model.rows if r["flags"]] or xv.p_model.rows[-3:]
            xv.tabs.setCurrentIndex(1)
            xv.p_model.set_checked([rows[0]["pid"]] if rows else [])
            if rows:
                hunt_pid[0] = rows[0]["pid"]
                hunt_pid.append(str(rows[0].get("name") or ""))
            xsteps.append("procs")
            xv.p_go.click() if rows else next_step("")

        def step_vad():
            xv.tabs.setCurrentIndex(2)
            xv.v_mode_reg.setChecked(True)
            cand = [r for r in xv.v_pmodel.rows if any("Injection" in f for f in r["flags"])]
            if not cand:
                return next_step("")
            for i in range(xv.v_pproxy.rowCount()):
                ix = xv.v_pproxy.index(i, 1)
                if str(ix.data()) == cand[0]["pid"]:
                    xv.v_pview.setCurrentIndex(ix)

            def go(n=[0]):
                if xv.v_list_b.isVisible() and not xv.job and n[0] == 0:
                    n[0] = 1                          # no region list yet: press "List regions"
                    rep["vad_listed_on_demand"] = cand[0]["pid"]
                    xv.v_list_b.click()
                if (xv.job or xv._loaders) and n[0] < 3600:
                    n[0] += 1
                    return QTimer.singleShot(500, go)
                rep["vad_regions"] = {"pid": cand[0]["pid"], "rows": len(xv.v_rmodel.rows),
                                      "title": xv.v_rtitle.text()}
                xv.v_inj_b.click()
                if not xv.v_rmodel.checked and xv.v_rmodel.rows:     # no flagged region: take the first
                    xv.v_rmodel.set_checked([xv.v_rmodel.rows[0]["start"]])
                w.grab().save(str(out / "e2e_extract_vad_ticked.png"))
                xsteps.append("vad")
                if xv.v_rmodel.checked:
                    xv.v_go.click()
                else:
                    next_step("")
            wait_lists(go)

        hunt_pid = [""]

        def step_hunt():
            # an IOC value from the dump, the hunted process's own name (in its own
            # memory: cmdline/PEB), and a term that is not in the dump at all
            irp = w.case / "iocs" / "ioc_results.json"
            ir = json.loads(irp.read_text(encoding="utf-8")) if irp.is_file() else {}
            vals = [v for k in ("domain", "url_http", "email", "domains", "urls", "emails") for v in
                    ((ir.get("results") or {}).get(k) or {}).get("values", [])]
            terms = [vals[0] if vals else "kernel32.dll"]
            pname = hunt_pid[1] if len(hunt_pid) > 1 else ""
            if pname and pname not in terms:
                terms.append(pname)
            terms.append("zqxjNotPresent7731")
            xv.tabs.setCurrentIndex(3)
            xv.h_terms.setPlainText(chr(10).join(terms))
            xv.h_pids.setText(hunt_pid[0])
            rep["hunt_terms"] = terms
            rep["hunt_pid"] = hunt_pid[0]
            xsteps.append("hunt")
            xv.h_go.click()

        def step_export():
            xv.tabs.setCurrentIndex(4)
            rep["export_available"] = xv.e_list.count()
            xsteps.append("export")
            xv.e_go.click()

        chain = [step_files, step_procs, step_vad, step_hunt, step_export]

        def next_step(manifest):
            if manifest:
                m = json.loads(Path(manifest).read_text(encoding="utf-8"))
                rep["extract"].append({"kind": m.get("kind"), "ok": m.get("ok"), "empty": m.get("empty"),
                                       "failed": m.get("failed"), "manifest": manifest})
                if m.get("kind") == "hunt":
                    rep["hunt_title"] = xv.h_title.text()
                    rep["hunt_rows"] = len(xv.h_model.rows)
                w.grab().save(str(out / f"e2e_extract_{m['kind']}_done.png"))
            if chain:
                QTimer.singleShot(800, chain.pop(0))
            else:
                QTimer.singleShot(800, finish)

        xv.job_finished.connect(next_step)
        wait_lists(lambda: next_step(""))

    def walk_results():
        """Open every node of the Results navigator like a user; record what each page shows."""
        from PySide6.QtWidgets import QLabel
        rv = w.results
        pages = {}
        big = 25 * 1024 * 1024

        def visit(it, path):
            t = it.text(0)
            name = f"{path}/{t}" if path else t
            e = rv._loaders.get(id(it))
            skip = False
            if e and path.split("/")[-1].startswith("Plugins ("):
                jp = w.case / "json" / f"{t}.json"
                skip = jp.is_file() and jp.stat().st_size > big
            if e and t.startswith("Extraction"):
                e = None                          # opens the workspace, tested above
            if e and not skip:
                t_open = time.perf_counter()
                rv._open_item(it, 0)
                app.processEvents()
                pg = rv.tabs.currentWidget()
                info = {"type": type(pg).__name__, "ms": round((time.perf_counter() - t_open) * 1000)}
                if hasattr(pg, "model") and hasattr(pg.model, "rowCount"):
                    info["rows"] = pg.model.rowCount()
                if isinstance(pg, QLabel) and "Could not load" in pg.text():
                    info["error"] = pg.text()[:200]
                pages[name] = info
                if not path or path.count("/") == 0 or "Findings" in path:
                    safe = "".join(ch if ch.isalnum() else "_" for ch in t)[:40]
                    w.grab().save(str(out / f"e2e_results_{safe}.png"))
                while rv.tabs.count() > 3:
                    rv.tabs.removeTab(0)
            elif skip:
                pages[name] = {"skipped": "json > 25 MB"}
            for i in range(it.childCount()):
                visit(it.child(i), name)

        if rv.tree.topLevelItemCount():
            visit(rv.tree.topLevelItem(0), "")
        rep["results_pages"] = pages
        rep["results_page_errors"] = [k for k, v in pages.items() if v.get("error")]
        rep["results_slowest_ms"] = sorted(((v.get("ms", 0), k) for k, v in pages.items()), reverse=True)[:5]

    def finish():
        n_run = len(rep["lat_ms"])                # drift during the run + extraction chain
        try:
            walk_results()
        except Exception as ex:                   # never lose the report over the walk
            rep["results_walk_error"] = repr(ex)
        walk = rep["lat_ms"][n_run:]              # samples taken while pages were opening
        rep["ui_walk_max_drift_ms"] = max(walk) if walk else None
        run_lat = rep["lat_ms"][:n_run]
        rep["ui_run_max_drift_ms"] = max(run_lat) if run_lat else None
        w.grab().save(str(out / "e2e_finished.png"))
        rep["shots"].append("e2e_finished")
        rep["results_nodes"] = [w.results.tree.topLevelItem(0).child(i).text(0)
                                for i in range(w.results.tree.topLevelItem(0).childCount())] \
            if w.results.tree.topLevelItemCount() else []
        rep["stage_text"] = w.monitor.stage.text()
        rep["plugins"] = {p: it.text(1) for p, it in w.state.get("plugins", {}).items()}
        lat = [x for x in rep["lat_ms"] if x is not None]
        rep["ui_max_drift_ms"] = max(lat) if lat else None
        rep["ui_p95_drift_ms"] = sorted(lat)[int(0.95 * (len(lat) - 1))] if lat else None
        rep["log_lines"] = len(w.log.lines)
        tij = Path(w.case) / "threat_intelligence" / "ti_report.json" if w.case else None
        if tij is not None and tij.is_file():
            t = json.loads(tij.read_text(encoding="utf-8"))
            rep["ti"] = {"objects": t.get("objects"), "dumps": t.get("dumps"), "hash_quality": t.get("hash_quality"),
                         "yara": t.get("yara_by_severity"), "feeds": t.get("feed_by_confidence"),
                         "vt": t.get("vt"), "shortlist": t.get("shortlist_total"),
                         "report_has_tab": "pageThreatIntel" in (Path(w.case) / "report.html").read_text(
                             encoding="utf-8", errors="replace")}
        (out / "e2e_report.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
        print(json.dumps({k: v for k, v in rep.items() if k not in ("lat_ms", "plugins")}, indent=1))
        app.exit(0 if rep["exit_code"] == 0 else 2)

    w.runner.finished.connect(done)
    QTimer.singleShot(800, w.start_run)
    return app.exec()
