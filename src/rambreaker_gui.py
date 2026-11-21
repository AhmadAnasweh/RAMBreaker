"""RAMBreaker entry point (GUI by default; `--cli ...` runs the toolkit CLI).

The packaged RAMBreaker.exe is this script. The GUI launches analyses by
re-invoking the same exe with --cli, so GUI and CLI share one code path.
"""

import multiprocessing
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if getattr(sys, "frozen", False):
    # packaged: the toolkit source ships as plain files in <exe dir>\app
    _APP = Path(sys.executable).resolve().parent / "app"
    if _APP.is_dir():
        sys.path.insert(0, str(_APP))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def _run_cli(argv):
    os.environ.setdefault("PYTHONUTF8", "1")
    sys.argv = ["crescent_toolkit.py"] + argv
    import runpy
    runpy.run_path(str(HERE / "crescent_toolkit.py") if not getattr(sys, "frozen", False)
                   else str(Path(sys._MEIPASS) / "crescent_toolkit.py"), run_name="__main__")


_FAULT_FILE = None


def _enable_fault_log():
    """A native crash in Qt (access violation, heap corruption) kills the
    process without a Python traceback; faulthandler writes the Python stack of
    every thread to logs/gui_fault_<time>.log first. The file is removed again
    on a clean exit, so only real crashes leave one."""
    global _FAULT_FILE
    try:
        import faulthandler
        import time
        base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else HERE.parent
        d = base / "logs"
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"gui_fault_{time.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}.log"
        _FAULT_FILE = open(p, "w", encoding="utf-8")
        faulthandler.enable(_FAULT_FILE, all_threads=True)
        return p
    except Exception:
        return None


def _close_fault_log(p):
    try:
        import faulthandler
        faulthandler.disable()
        _FAULT_FILE.close()
        if p and p.stat().st_size == 0:
            p.unlink()
    except Exception:
        pass


def _run_gui():
    fault = _enable_fault_log()
    try:
        return _run_gui_main()
    finally:
        _close_fault_log(fault)


def _run_gui_main():
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QIcon
    from PySide6.QtWidgets import QApplication
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("RAMBreaker.Workstation.2")
        except Exception:
            pass
    app = QApplication(sys.argv)
    app.setApplicationName("RAMBreaker")
    app.setOrganizationName("RAMBreaker")
    app.setFont(QFont("Segoe UI", 9))
    ico = HERE / "gui" / "app.ico"
    if getattr(sys, "frozen", False):
        ico = Path(sys._MEIPASS) / "gui" / "app.ico"
    if ico.is_file():
        app.setWindowIcon(QIcon(str(ico)))
    if len(sys.argv) >= 4 and sys.argv[1] == "--e2e":
        from gui import e2e
        return e2e.run(sys.argv[2], sys.argv[3],
                       int(sys.argv[4]) if len(sys.argv) > 4 else 1,
                       sys.argv[5] if len(sys.argv) > 5 else "")
    if len(sys.argv) >= 2 and sys.argv[1] == "--selftest":
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        from gui import selftest
        selftest.main_with_app(app)
        return 0
    from gui.main_window import MainWindow
    w = MainWindow()
    w.show()
    if len(sys.argv) > 1 and Path(sys.argv[-1]).is_file():
        w.setup.dump.setText(sys.argv[-1])        # "Open with RAMBreaker"
    return app.exec()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        _run_cli(sys.argv[2:])
    else:
        sys.exit(_run_gui())
