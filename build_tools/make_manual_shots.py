"""Screenshots of every RAMBreaker view for the user manual, from a finished real case.

Usage, from the project root, with RAMBREAKER_HOME pointing at an installed copy (so the
settings, rule sets and output folder on screen are those of a normal install):
    set RAMBREAKER_HOME=C:\\Tools\\RAMBreaker_v2.5.0
    runtime\\py3\\Scripts\\python.exe build_tools\\make_manual_shots.py <out_dir> <case_dir> <dump> [<queue dump> ...]

Unlike gui.selftest there are no simulated progress events: the case is opened the way
'Load results' does it, so the run monitor and every result page show the real run.
<dump> is the memory image the case came from (shown in the setup panel); the optional
queue dumps are added to the dump queue (not started) for the queue screenshot.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from PySide6.QtWidgets import QApplication  # noqa: E402


def main():
    out, case, dump, queue = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4:]
    out.mkdir(parents=True, exist_ok=True)
    app = QApplication(sys.argv[:1])
    from gui import main_window as mw
    from gui.help_check import check
    from gui.help_guide import GuideWindow
    from gui.selftest import extraction_pages, pump
    from gui.widgets import HelpButton, HelpPopup

    base = mw.load_settings()
    mw.load_settings = lambda: dict(base, tour_on_start=False)
    mw.save_settings = lambda s: None
    w = mw.MainWindow()
    w.resize(1600, 960)
    w.show()
    pump(0.8)
    taken = []

    def shot(name, widget=None):
        (widget or w).grab().save(str(out / f"{name}.png"))
        taken.append(name)

    # --- setup panel
    shot("01_main_idle")
    w.setup.dump.setText(dump)
    pump(0.4)
    shot("02_setup_dump_chosen")
    w.setup.fast.setChecked(True)
    pump(0.3)
    shot("03_setup_fast_mode")
    w.setup.fast.setChecked(False)
    w.setup.preset.setCurrentIndex(len(mw.PRESETS) - 1)          # DFIR + Threat Intel
    pump(0.3)
    shot("04_setup_preset_dfir_ti")
    w.setup.preset.setCurrentIndex(0)

    # --- the finished case, every page of the navigator
    w.open_case(case)
    pump(1.5)
    shot("10_case_loaded")
    root = w.results.tree.topLevelItem(0)

    def open_shot(it, prefix="11_results_"):
        w.results._open_item(it, 0)
        pump(0.8)
        slug = re.sub(r"[^a-z0-9]+", "_", re.sub(r"\s*\(\d+\)$", "", it.text(0)).lower()).strip("_")
        shot(prefix + slug)

    def count(it):
        m = re.search(r"\((\d+)\)$", it.text(0))
        return int(m.group(1)) if m else 0

    for i in range(root.childCount()):
        it = root.child(i)
        label = it.text(0)
        kids = [it.child(k) for k in range(it.childCount())]
        if label.startswith("Extraction"):
            continue
        if label == "Findings":
            for k in kids:
                open_shot(k)
        elif label.startswith("IOCs"):                 # a folder of IOC tables: two readable ones
            pref = [k for t in ("domain", "url", "ipv4") for k in kids if k.text(0).startswith(t + " (")]
            for k in (pref + sorted(kids, key=count, reverse=True))[:2]:
                open_shot(k, "11_results_ioc_")
        elif label.startswith("Plugins"):              # a folder of plugin tables: one example
            pick = next((k for k in kids if "malfind" in k.text(0).lower()), kids[0] if kids else None)
            if pick:
                open_shot(pick, "11_results_plugin_")
        elif not kids:
            open_shot(it)

    # --- Extraction workspace (same walk as the selftest; shot names get a gui_ prefix there)
    report = {}
    extraction_pages(w, lambda n: shot(f"20_{n}"), report, check)
    pump(0.5)

    # --- Threat intel options + local databases
    d = mw.ThreatIntelDialog(w.s, case.name, w)
    d.show()
    pump(0.6)
    shot("30_ti_dialog", d)
    d.close()
    from gui.ti_dialog import DatabasesDialog
    d = DatabasesDialog(w)
    d.show()
    pump(0.6)
    shot("31_ti_databases", d)
    d.close()

    # --- dialogs, help, guide, tour
    for cls, name in ((mw.SettingsDialog, "40_settings"), (mw.GlossaryDialog, "41_glossary"),
                      (mw.AboutDialog, "42_about")):
        d = cls(w.s, w) if cls is mw.SettingsDialog else cls(w)
        d.show()
        pump(0.4)
        shot(name, d)
        d.close()
    p = HelpPopup.show_for("setup.preset", w.setup.preset)
    pump(0.4)
    shot("43_help_popup_window")
    p.close()
    btn = next((b for b in w.findChildren(HelpButton) if b.property("help_key") == "setup.preset"), None)
    if btn:
        btn.click()
        pump(0.8)
        g = GuideWindow._open.get("setup.preset")
        if g:
            shot("44_help_guide", g)
            g.close()
    w.start_tour()
    pump(0.6)
    shot("45_tour")
    for t in w.findChildren(mw.TourOverlay):
        t.finish()
    pump(0.3)

    # --- light theme
    w.apply_theme("light")
    w.open_case(case)
    pump(1.0)
    shot("50_case_loaded_light")
    w.apply_theme("dark")
    pump(0.4)

    # --- dump queue (added, not started)
    if queue:
        w.open_case(case)
        w.queue_add(queue)
        pump(0.4)
        area = w.setup.parentWidget().parentWidget()          # the setup panel's QScrollArea
        if hasattr(area, "ensureWidgetVisible"):
            area.ensureWidgetVisible(w.setup.qlist)
            pump(0.2)
            area.horizontalScrollBar().setValue(0)             # keep the labels in view
        pump(0.4)
        shot("60_queue")

    print(f"{len(taken)} screenshots -> {out}")
    print("extraction:", report.get("extract_counts"), report.get("extract_regions"))


if __name__ == "__main__":
    main()
