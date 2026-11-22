"""RAMBreaker main window."""

import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QEvent, QPoint, QRect, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QDragEnterEvent, QDropEvent, QKeySequence, QPainter, QPen
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDockWidget,
                               QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox,
                               QProgressBar, QPushButton, QScrollArea, QSizePolicy,
                               QStatusBar, QTextBrowser, QToolBar, QToolButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from gui import help_registry, icons, theme
from gui.extract_view import ExtractView
from gui.ti_dialog import DatabasesDialog, ThreatIntelDialog
from gui.log_console import LogConsole
from gui.ram_anim import RamAnimation
from gui.results_view import ResultsView
from gui.retry_dialog import RetryDialog
from gui.runner import AnalysisRunner
from gui.widgets import (ComboBox, HelpButton, HelpMode, HelpPopup, Spinner, SpinBox, helped,
                         set_theme, with_help)

SRC = Path(__file__).resolve().parent.parent
if getattr(sys, "frozen", False):
    SRC = Path(sys.executable).resolve().parent / "app"
sys.path.insert(0, str(SRC))
from modules import platform_compat  # noqa: E402

APP = "RAMBreaker"
VERSION = "2.6.0"

PRESETS = [
    ("Standard (recommended)", "core", "full"),
    ("Quick triage", "extract", "fast"),
    ("Full DFIR (+ EVTX carving)", "full", "full"),
    ("Malware hunt", "core", "malware"),
    ("Network focus", "core", "network"),
    ("Persistence focus", "core", "persistence"),
    ("Registry focus", "core", "registry"),
    ("DFIR + Threat Intel (dump all, YARA, feeds, VirusTotal)", "dfir-ti", "full"),
]
POST_S_PER_GB = 45.0          # strings+IOC+email+sigma+report, measured on Win2.raw

# The CLI has ONE plugin-set switch (-m fast|full|malware|network|persistence|
# registry) that mixes "how much" (fast = quick subset) with "what about"
# (a category). The GUI shows the two ideas as two controls and folds them back
# into the same -m value, so the CLI and every older case stay unchanged.
CATEGORIES = [                 # (CLI -m value when Fast mode is off, label)
    ("full", "All categories"),
    ("malware", "Malware"),
    ("network", "Network"),
    ("persistence", "Persistence"),
    ("registry", "Registry"),
]
SPEED_MODES = [                # (CLI --speed / settings value, label)
    ("normal", "normal (RAM guard on)"),
    ("fast", "fast (tighter RAM budget)"),
    ("fastest", "fastest (no RAM guard)"),
]


def mode_for(category: str, fast: bool) -> str:
    """GUI controls -> CLI -m value. Fast mode is one quick cross-category set."""
    if fast:
        return "fast"
    return category if category in dict(CATEGORIES) else "full"


def split_mode(mode: str):
    """CLI -m value (or an older preset/setting) -> (category, fast mode)."""
    m = (mode or "full").strip().lower()
    if m == "fast":
        return "full", True
    return (m if m in dict(CATEGORIES) else "full"), False


def speed_combo(value: str) -> QComboBox:
    cb = ComboBox()
    cb.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
    cb.setMinimumContentsLength(12)
    for v, label in SPEED_MODES:
        cb.addItem(label, v)
    set_combo_data(cb, value, "normal")
    return cb


def set_combo_data(cb: QComboBox, value, default=None) -> None:
    i = cb.findData(value)
    if i < 0 and default is not None:
        i = cb.findData(default)
    cb.setCurrentIndex(max(0, i))


def settings_path() -> Path:
    return platform_compat.app_root() / "config" / "gui_settings.json"


DEFAULT_SETTINGS = {"theme": "dark", "output_dir": "", "jobs": 4, "speed": "normal",
                    "fixed_timeout": False, "timeout": 600, "ioc_attribution": True,
                    "animation": True, "tour_on_start": True, "tour_done": False,
                    "vt_rate": 4.0, "vt_max": 100, "yara_set": "core", "yara_custom_dir": "",
                    # v2.5: dumped files go into password-protected ZIPs (modules/safe_zip.py)
                    "protect_dumps": True, "zip_password": "infected"}


def load_settings() -> dict:
    s = dict(DEFAULT_SETTINGS)
    try:
        s.update(json.loads(settings_path().read_text(encoding="utf-8")))
    except Exception:
        pass
    return s


def save_settings(s: dict) -> None:
    p = settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(s, indent=2), encoding="utf-8")


def plugin_list(os_type: str, engine: str, mode: str) -> List[str]:
    """Plugin names a run would execute (for the pre-run ETA)."""
    # Parse the PLUGINS dict statically (ast) instead of importing the
    # extractor: keeps the GUI process light and free of analysis imports.
    try:
        import ast
        f = SRC / "modules" / f"extractor.{os_type}.py"
        tree = ast.parse(f.read_text(encoding="utf-8"))
        P = {}
        for node in tree.body:
            tgts = node.targets if isinstance(node, ast.Assign) else \
                [node.target] if isinstance(node, ast.AnnAssign) else []
            if any(getattr(t, "id", "") == "PLUGINS" for t in tgts) and node.value is not None:
                P = ast.literal_eval(node.value)
                break
        s = P.get(f"{engine}-{os_type}-{mode}") or P.get(f"{engine}-{os_type}-full", "")
        return s.split()
    except Exception:
        return []


# ═══════════════════════════════════════════════════════════════════ setup
class DropZone(QLabel):
    dropped = Signal(str)
    dropped_many = Signal(list)          # v2.4: several dumps dropped at once -> queue

    def __init__(self):
        super().__init__("Drop a memory dump here\n(.raw  .mem  .vmem  .lime  .dmp  .bin  .img)")
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        self.setMinimumHeight(70)
        self.setObjectName("Muted")
        self._style(False)

    def _style(self, hot):
        c = theme.palette(QApplication.instance().property("rb_theme") or "dark")
        self.setStyleSheet(f"QLabel{{border:1px dashed {c['accent'] if hot else c['border_hi']};"
                           f"background:{c['accent_lo'] if hot else c['panel2']};color:{c['muted']};}}")

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._style(True)

    def dragLeaveEvent(self, e):
        self._style(False)

    def dropEvent(self, e: QDropEvent):
        self._style(False)
        urls = e.mimeData().urls()
        if len(urls) > 1:
            self.dropped_many.emit([u.toLocalFile() for u in urls])
        elif urls:
            self.dropped.emit(urls[0].toLocalFile())


class SetupPanel(QWidget):
    changed = Signal()

    def __init__(self, settings: dict):
        super().__init__()
        self.s = settings
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(5)
        t = QLabel("New analysis")
        t.setObjectName("H2")
        lay.addWidget(t)
        self.drop = DropZone()
        helped(self.drop, "setup.drop")
        lay.addWidget(self.drop)
        self.dump = QLineEdit()
        self.dump.setPlaceholderText("Path to the memory image")
        self.browse = QPushButton("Browse...")
        helped(self.browse, "setup.browse")
        row = QHBoxLayout()
        row.addWidget(with_help(self.dump, "setup.dump", "Memory dump"), 1)
        row.addWidget(self.browse)
        row.addWidget(HelpButton("setup.browse"))
        lay.addLayout(row)
        self.preset = ComboBox()
        for name, _c, _m in PRESETS:
            self.preset.addItem(name)
        lay.addWidget(with_help(self.preset, "setup.preset", "Preset"))
        lay.addWidget(self._section("What to analyse"))
        self.category = ComboBox()
        self.category.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.category.setMinimumContentsLength(12)
        for v, label in CATEGORIES:
            self.category.addItem(label, v)
        lay.addWidget(with_help(self.category, "setup.category", "Plugin category"))
        self.engine = ComboBox()
        self.engine.addItems(["Auto", "Volatility 3", "Volatility 2"])
        lay.addWidget(with_help(self.engine, "setup.engine", "Engine"))
        # known-image shortcut
        self.known = QCheckBox("I already know this image")
        lay.addWidget(with_help(self.known, "setup.known"))
        self.knownbox = QFrame()
        self.knownbox.setObjectName("Panel")
        kl = QVBoxLayout(self.knownbox)
        kl.setContentsMargins(8, 6, 8, 6)
        self.os = ComboBox()
        self.os.addItems(["windows", "linux", "mac"])
        kl.addWidget(with_help(self.os, "setup.os", "OS"))
        self.osver = QLineEdit()
        self.osver.setPlaceholderText("e.g. Windows 10 22H2 / Ubuntu 22.04")
        kl.addWidget(with_help(self.osver, "setup.version", "OS version"))
        self.profile = ComboBox()
        self.profile.setEditable(True)
        self.profile.addItems(["", "WinXPSP2x86", "WinXPSP3x86", "Win7SP0x86", "Win7SP1x86",
                               "Win7SP0x64", "Win7SP1x64", "Win2008R2SP1x64", "Win8SP1x64",
                               "Win81U1x64", "Win10x64_10586", "Win10x64_14393", "Win10x64_15063",
                               "Win10x64_16299", "Win10x64_17134", "Win10x64_17763",
                               "Win10x64_18362", "Win10x64_19041", "Win2012R2x64", "Win2016x64_14393"])
        kl.addWidget(with_help(self.profile, "setup.profile", "Vol2 profile"))
        self.isf = QLineEdit()
        self.isf.setPlaceholderText("Linux/macOS: your own .json / .json.xz")
        self.isfb = QPushButton("...")
        self.isfb.setFixedWidth(34)
        helped(self.isfb, "setup.isfbrowse")
        r2 = QHBoxLayout()
        r2.addWidget(with_help(self.isf, "setup.isf", "Symbol file"), 1)
        r2.addWidget(self.isfb)
        kl.addLayout(r2)
        self.v2zip = QLineEdit()
        self.v2zip.setPlaceholderText("Old Linux: Vol2 profile .zip")
        self.v2zipb = QPushButton("...")
        self.v2zipb.setFixedWidth(34)
        helped(self.v2zipb, "setup.v2zipbrowse")
        r5 = QHBoxLayout()
        r5.addWidget(with_help(self.v2zip, "setup.v2zip", "Vol2 profile zip"), 1)
        r5.addWidget(self.v2zipb)
        kl.addLayout(r5)
        lay.addWidget(self.knownbox)
        self.knownbox.setVisible(False)
        # speed: how MUCH runs (fast mode) and how hard the PC works (jobs, RAM)
        lay.addWidget(self._section("Speed"))
        self.fast = QCheckBox("Quick plugin set")
        lay.addWidget(with_help(self.fast, "setup.fastmode", "Fast mode"))
        self.fast_note = QLabel("Fast mode runs one quick set that covers every category, "
                                "so Plugin category is fixed to 'All categories'.")
        self.fast_note.setObjectName("Muted")
        self.fast_note.setWordWrap(True)
        self.fast_note.setVisible(False)
        lay.addWidget(self.fast_note)
        self.jobs = SpinBox()
        self.jobs.setRange(1, 16)
        self.jobs.setValue(int(settings.get("jobs", 4)))
        lay.addWidget(with_help(self.jobs, "setup.jobs", "Parallel jobs"))
        self.speed = speed_combo(settings.get("speed", "normal"))
        lay.addWidget(with_help(self.speed, "setup.speed", "RAM / jobs mode"))
        lay.addWidget(self._section("Inputs and output"))
        # ioc list
        self.ioc = QLineEdit()
        self.ioc.setPlaceholderText("Optional: one IOC per line")
        self.iocb = QPushButton("...")
        self.iocb.setFixedWidth(34)
        helped(self.iocb, "setup.iocbrowse")
        self.iocc = QToolButton()
        helped(self.iocc, "setup.iocclear")
        r3 = QHBoxLayout()
        r3.addWidget(with_help(self.ioc, "setup.ioclist", "IOC list"), 1)
        r3.addWidget(self.iocb)
        r3.addWidget(self.iocc)
        lay.addLayout(r3)
        self.out = QLineEdit(settings.get("output_dir") or str(platform_compat.app_root() / "output"))
        self.outb = QPushButton("...")
        self.outb.setFixedWidth(34)
        helped(self.outb, "setup.outbrowse")
        r4 = QHBoxLayout()
        r4.addWidget(with_help(self.out, "setup.output", "Output folder"), 1)
        r4.addWidget(self.outb)
        lay.addLayout(r4)
        self.est = QLabel("Estimated time: pick a dump")
        self.est.setWordWrap(True)
        self.est.setObjectName("Muted")
        lay.addWidget(with_help(self.est, "setup.estimate"))
        self.start = QPushButton("Start analysis")
        self.start.setObjectName("Primary")
        self.start.setMinimumHeight(34)
        lay.addWidget(with_help(self.start, "setup.start"))
        # v2.4 queue: several dumps analysed one after another with the options above
        # buttons first: they must be visible without scrolling the panel
        self.qlist = QListWidget()
        self.qlist.setMaximumHeight(92)
        qr = QHBoxLayout()
        self.qadd = QPushButton("Add to queue")
        helped(self.qadd, "setup.queue.add")
        self.qremove = QPushButton("Remove")
        helped(self.qremove, "setup.queue.remove")
        self.qstart = QPushButton("Start queue")
        helped(self.qstart, "setup.queue.start")
        qr.addWidget(self.qadd)
        qr.addWidget(self.qremove)
        qr.addWidget(self.qstart, 1)
        lay.addLayout(qr)
        lay.addWidget(self._section("Queue - several dumps, one after another"))
        lay.addWidget(with_help(self.qlist, "setup.queue.list"))
        lay.addStretch(1)
        # wiring
        self.preset.currentIndexChanged.connect(self._preset)
        self.fast.toggled.connect(self._fast_toggled)
        self.known.toggled.connect(self.knownbox.setVisible)
        for w in (self.dump, self.isf, self.ioc, self.out, self.osver):
            w.textChanged.connect(self.changed)
        for w in (self.preset, self.category, self.engine, self.os, self.speed):
            w.currentIndexChanged.connect(self.changed)
        self.jobs.valueChanged.connect(self.changed)
        self.known.toggled.connect(self.changed)
        self.fast.toggled.connect(self.changed)
        self.set_mode(PRESETS[0][2])
        self.drop.dropped.connect(self.dump.setText)
        self.browse.clicked.connect(self._pick_dump)
        self.isfb.clicked.connect(lambda: self._pick(self.isf, "Symbol file (*.json *.xz)"))
        self.v2zipb.clicked.connect(lambda: self._pick(self.v2zip, "Vol2 profile (*.zip)"))
        self.iocb.clicked.connect(lambda: self._pick(self.ioc, "IOC lists (*.txt *.csv *.ioc);;All (*)"))
        self.iocc.clicked.connect(self.ioc.clear)
        self.outb.clicked.connect(self._pick_out)

    def retheme(self, c):
        self.iocc.setIcon(icons.icon("x", c["text"], 14))
        for b in (self.isfb, self.iocb, self.outb, self.v2zipb):
            b.setText("")
            b.setIcon(icons.icon("folder-open", c["text"], 16))
        self.browse.setIcon(icons.icon("folder-open", c["text"], 16))
        self.drop._style(False)

    @staticmethod
    def _section(text: str) -> QLabel:
        l = QLabel(text.upper())
        l.setObjectName("Section")
        return l

    def _preset(self, i):
        self.set_mode(PRESETS[i][2])

    def _fast_toggled(self, on: bool):
        if on:
            set_combo_data(self.category, "full")
        self.category.setEnabled(not on)
        self.fast_note.setVisible(on)

    def set_mode(self, mode: str) -> None:
        """Show a CLI -m value (preset, older setting) on the two controls."""
        cat, fast = split_mode(mode)
        self.fast.setChecked(fast)
        self._fast_toggled(fast)
        set_combo_data(self.category, cat, "full")

    def mode_value(self) -> str:
        """The two controls folded back into the CLI -m value."""
        return mode_for(self.category.currentData() or "full", self.fast.isChecked())

    def speed_value(self) -> str:
        return self.speed.currentData() or "normal"

    def set_speed(self, value: str) -> None:
        set_combo_data(self.speed, value, "normal")

    def _pick_dump(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Open memory dump", "",
                                            "Memory images (*.raw *.mem *.vmem *.lime *.dmp *.bin "
                                            "*.img *.dd *.core *.elf);;All files (*)")
        if fn:
            self.dump.setText(fn)

    def _pick(self, field, flt):
        fn, _ = QFileDialog.getOpenFileName(self, "Select file", "", flt)
        if fn:
            field.setText(fn)

    def _pick_out(self):
        d = QFileDialog.getExistingDirectory(self, "Output folder", self.out.text())
        if d:
            self.out.setText(d)

    def case_dir(self) -> Path:
        p = Path(self.dump.text().strip().strip('"'))
        suffix = p.suffix.lstrip(".")
        name = f"{p.stem}_{suffix}" if suffix else p.stem
        return Path(self.out.text().strip() or platform_compat.app_root() / "output") / name

    def build_args(self, s: dict) -> List[str]:
        dump = self.dump.text().strip().strip('"')
        cmd = PRESETS[self.preset.currentIndex()][1]
        a = [cmd, "-i", dump, "-o", str(self.case_dir()), "-m", self.mode_value(),
             "-j", str(self.jobs.value()), "--speed", self.speed_value(), "--no-telemetry"]
        eng = self.engine.currentIndex()
        if eng == 1:
            a.append("--vol3")
        elif eng == 2:
            a.append("--vol2")
        if self.known.isChecked():
            a += ["--os", self.os.currentText()]
            if self.profile.currentText().strip():
                a += ["--profile", self.profile.currentText().strip()]
            if self.isf.text().strip():
                a += ["--symbol-isf", self.isf.text().strip()]
            if self.v2zip.text().strip():
                a += ["--vol2-profile-zip", self.v2zip.text().strip()]
        if self.ioc.text().strip():
            a += ["--ioc-list", self.ioc.text().strip()]
            if not s.get("ioc_attribution", True):
                a.append("--no-ioc-attribution")
        if s.get("fixed_timeout"):
            a += ["--fixed-timeout", "--timeout", str(int(s.get("timeout", 600)))]
        return a

    def estimate(self, size_gb: Optional[float] = None) -> str:
        """Pre-run ETA. `size_gb` replaces reading the dump (help media generator)."""
        dump = Path(self.dump.text().strip().strip('"'))
        if size_gb is None and not dump.is_file():
            return "Estimated time: pick an existing dump file"
        try:
            from modules import timeout_model as tm
            size = size_gb if size_gb is not None else \
                tm.image_size_gb(str(dump))             # also sets the image format (crash dump/raw)
            os_t = self.os.currentText() if self.known.isChecked() else "windows"
            eng = "vol2" if self.engine.currentIndex() == 2 else "vol3"
            plugs = plugin_list(os_t, eng, self.mode_value())
            m = tm.get_model()
            # same rule as extractor.windows: per-process-on-demand plugins whose
            # predicted cost exceeds 30 min are not run up front
            plugs = [p for p in plugs if not (p == "windows.vadinfo.VadInfo"
                                              and m.expected(p, eng, os_t, size) > 1800)]
            total, _ = m.estimate_total(plugs, eng, os_t, size, self.jobs.value())
            cmd = PRESETS[self.preset.currentIndex()][1]
            post = 0 if cmd == "extract" else POST_S_PER_GB * size
            assume = "" if self.known.isChecked() else " (assuming Windows until detection)"
            return (f"Estimated time: ~{tm._fmt(total + post + 30)} for {len(plugs)} plugins on "
                    f"{size:.1f} GB{assume}. Refined live during the run.")
        except Exception as e:
            return f"Estimated time unavailable ({e})"


# ═══════════════════════════════════════════════════════════════ monitor
class RunMonitor(QWidget):
    def __init__(self, c: dict):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(6)
        self.anim = RamAnimation(c)
        lay.addWidget(with_help(self.anim, "prog.ram"))
        self.stage = QLabel("Idle - pick a memory dump and press Start")
        self.stage.setObjectName("H2")
        lay.addWidget(with_help(self.stage, "prog.stage"))
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setFormat("%p %")
        lay.addWidget(with_help(self.bar, "prog.overall"))
        g = QGridLayout()
        self.elapsed = QLabel("Elapsed: -")
        self.eta = QLabel("ETA: -")
        self.beat = QLabel("Last activity: -")
        self.counts = QLabel("Plugins: -")
        for i, w in enumerate((self.elapsed, self.eta, self.counts)):
            g.addWidget(w, 0, i)
        g.addWidget(with_help(self.beat, "prog.heartbeat"), 1, 0, 1, 3)
        lay.addLayout(g)
        self.plugins = QTreeWidget()
        self.plugins.setColumnCount(5)
        self.plugins.setHeaderLabels(["Plugin", "State", "Time", "Limit", "Retry"])
        self.plugins.setRootIsDecorated(False)
        self.plugins.setAlternatingRowColors(True)
        self.plugins.header().setSectionResizeMode(0, QHeaderView.Stretch)
        for i in (1, 2, 3, 4):
            self.plugins.header().setSectionResizeMode(i, QHeaderView.ResizeToContents)
        lay.addWidget(with_help(self.plugins, "prog.plugins"), 1)


# ═══════════════════════════════════════════════════════════════ dialogs
class SettingsDialog(QDialog):
    def __init__(self, s: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.s = dict(s)
        lay = QVBoxLayout(self)
        self.theme = ComboBox()
        self.theme.addItems(["dark", "light"])
        self.theme.setCurrentText(s.get("theme", "dark"))
        lay.addWidget(with_help(self.theme, "set.theme", "Theme"))
        self.out = QLineEdit(s.get("output_dir", ""))
        self.out.setPlaceholderText(str(platform_compat.app_root() / "output"))
        ob = QPushButton("...")
        ob.setFixedWidth(34)
        helped(ob, "set.outbrowse")
        r = QHBoxLayout()
        r.addWidget(with_help(self.out, "set.outdir", "Default output"), 1)
        r.addWidget(ob)
        lay.addLayout(r)
        self.jobs = SpinBox()
        self.jobs.setRange(1, 16)
        self.jobs.setValue(int(s.get("jobs", 4)))
        lay.addWidget(with_help(self.jobs, "set.jobs", "Parallel jobs"))
        self.speed = speed_combo(s.get("speed", "normal"))
        lay.addWidget(with_help(self.speed, "set.speed", "RAM / jobs mode"))
        self.fixed = QCheckBox("Use one fixed timeout for every plugin")
        self.fixed.setChecked(bool(s.get("fixed_timeout")))
        lay.addWidget(with_help(self.fixed, "set.fixedto"))
        self.tmo = SpinBox()
        self.tmo.setRange(30, 86400)
        self.tmo.setValue(int(s.get("timeout", 600)))
        lay.addWidget(with_help(self.tmo, "set.timeout", "Fixed timeout (s)"))
        self.attr = QCheckBox("Attribute IOC hits to processes")
        self.attr.setChecked(bool(s.get("ioc_attribution", True)))
        lay.addWidget(with_help(self.attr, "set.attrib"))
        self.anim = QCheckBox("Show the RAM animation")
        self.anim.setChecked(bool(s.get("animation", True)))
        lay.addWidget(with_help(self.anim, "set.anim"))
        self.tour = QCheckBox("Show the guided tour at start-up")
        self.tour.setChecked(bool(s.get("tour_on_start", True)))
        lay.addWidget(with_help(self.tour, "set.tour"))
        tidb = QPushButton("Threat-intel databases (YARA rules, threat feeds) ...")
        tidb.clicked.connect(lambda: DatabasesDialog(self).exec())
        lay.addWidget(with_help(tidb, "set.tidb"))
        bb = QHBoxLayout()
        bb.addStretch(1)
        ok = QPushButton("Save")
        ok.setObjectName("Primary")
        helped(ok, "set.ok")
        ca = QPushButton("Cancel")
        helped(ca, "set.cancel")
        bb.addWidget(ok)
        bb.addWidget(ca)
        lay.addLayout(bb)
        ob.clicked.connect(self._pick)
        ok.clicked.connect(self.accept)
        ca.clicked.connect(self.reject)
        self.setMinimumWidth(520)

    def _pick(self):
        d = QFileDialog.getExistingDirectory(self, "Default output folder", self.out.text())
        if d:
            self.out.setText(d)

    def result_settings(self) -> dict:
        self.s.update(theme=self.theme.currentText(), output_dir=self.out.text().strip(),
                      jobs=self.jobs.value(), speed=self.speed.currentData() or "normal",
                      fixed_timeout=self.fixed.isChecked(), timeout=self.tmo.value(),
                      ioc_attribution=self.attr.isChecked(), animation=self.anim.isChecked(),
                      tour_on_start=self.tour.isChecked())
        return self.s


class GlossaryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Glossary")
        self.resize(760, 460)
        lay = QVBoxLayout(self)
        self.q = QLineEdit()
        self.q.setPlaceholderText("Search terms and definitions...")
        self.q.setClearButtonEnabled(True)
        lay.addWidget(with_help(self.q, "gl.search"))
        row = QHBoxLayout()
        self.lst = QListWidget()
        helped(self.lst, "gl.list")
        self.txt = QTextBrowser()
        helped(self.txt, "gl.text")
        row.addWidget(self.lst, 1)
        row.addWidget(self.txt, 2)
        lay.addLayout(row, 1)
        cl = QPushButton("Close")
        helped(cl, "dlg.close")
        lay.addWidget(cl, 0, Qt.AlignRight)
        cl.clicked.connect(self.accept)
        self.q.textChanged.connect(self._fill)
        self.lst.currentTextChanged.connect(self._show)
        self._fill("")

    def _fill(self, q):
        self.lst.clear()
        q = q.lower()
        for k, v in sorted(help_registry.GLOSSARY.items()):
            if not q or q in k.lower() or q in v.lower():
                self.lst.addItem(k)
        if self.lst.count():
            self.lst.setCurrentRow(0)

    def _show(self, k):
        if k:
            self.txt.setHtml(f"<h3>{k}</h3><p>{help_registry.GLOSSARY.get(k, '')}</p>")


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"About {APP}")
        self.resize(640, 420)
        lay = QVBoxLayout(self)
        t = QLabel(f"{APP} {VERSION}")
        t.setObjectName("H1")
        lay.addWidget(t)
        tb = QTextBrowser()
        vers = ""
        for p in (platform_compat.app_root() / "VERSIONS.md", SRC.parent / "VERSIONS.md"):
            if p.is_file():
                vers = p.read_text(encoding="utf-8", errors="replace")
                break
        tb.setPlainText("Memory-forensics workstation around Volatility 2 and Volatility 3.\n"
                        "Analyses run locally; dumps and results are never uploaded.\n\n"
                        + (vers or "VERSIONS.md not found") +
                        "\n\nIcons: Lucide (ISC licence). Sigma rules: SigmaHQ (DRL 1.1).\n"
                        "Volatility 3: Volatility Software License. Volatility 2: GPLv2.")
        helped(tb, "about.text")
        lay.addWidget(tb, 1)
        cl = QPushButton("Close")
        helped(cl, "dlg.close")
        lay.addWidget(cl, 0, Qt.AlignRight)
        cl.clicked.connect(self.accept)


class TourOverlay(QWidget):
    """Dims the window and highlights one area at a time."""

    def __init__(self, win, steps):
        super().__init__(win)
        self.win = win
        self.steps = steps
        self.i = 0
        self.setObjectName("TourOverlay")
        self.setAttribute(Qt.WA_StyledBackground, False)
        self.setAttribute(Qt.WA_NoSystemBackground, True)
        self.setStyleSheet("QWidget#TourOverlay { background: transparent; }")
        self.setAutoFillBackground(False)
        self.card = QFrame(self)
        self.card.setObjectName("Panel")
        cl = QVBoxLayout(self.card)
        self.title = QLabel()
        self.title.setObjectName("H2")
        self.body = QLabel()
        self.body.setWordWrap(True)
        self.body.setFixedWidth(340)
        btns = QHBoxLayout()
        self.back = QPushButton("Back")
        helped(self.back, "tour.back")
        self.next = QPushButton("Next")
        self.next.setObjectName("Primary")
        helped(self.next, "tour.next")
        self.skip = QPushButton("Skip tour")
        helped(self.skip, "tour.skip")
        btns.addWidget(self.skip)
        btns.addStretch(1)
        btns.addWidget(self.back)
        btns.addWidget(self.next)
        cl.addWidget(self.title)
        cl.addWidget(self.body)
        cl.addLayout(btns)
        self.back.clicked.connect(lambda: self.go(-1))
        self.next.clicked.connect(lambda: self.go(1))
        self.skip.clicked.connect(self.finish)
        self.setFocusPolicy(Qt.StrongFocus)
        win.installEventFilter(self)

    def start(self):
        self.setGeometry(self.win.rect())
        self.show()
        self.raise_()
        self.setFocus()
        self.go(0)

    def eventFilter(self, o, e):
        if o is self.win and e.type() == QEvent.Resize:
            self.setGeometry(self.win.rect())
            self.go(0)
        return False

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Escape:
            self.finish()

    def target_rect(self) -> QRect:
        w = self.steps[self.i][0]()
        if w is None or not w.isVisible():
            return QRect()
        tl = w.mapTo(self.win, QPoint(0, 0))
        return QRect(tl, w.size()).adjusted(-4, -4, 4, 4)

    def go(self, d):
        self.i = max(0, min(len(self.steps) - 1, self.i + d))
        _, title, text = self.steps[self.i]
        self.title.setText(f"{self.i + 1}/{len(self.steps)}  {title}")
        self.body.setText(text)
        self.back.setEnabled(self.i > 0)
        self.next.setText("Finish" if self.i == len(self.steps) - 1 else "Next")
        if d > 0 and self.i == len(self.steps) - 1 and self.next.text() == "Finish" \
                and getattr(self, "_at_end", False):
            self.finish()
            return
        self._at_end = self.i == len(self.steps) - 1
        self.card.adjustSize()
        r = self.target_rect()
        if r.width() > self.width() * 0.6:          # wide target: put the card below it
            x = max(8, min(r.left() + 40, self.width() - self.card.width() - 8))
            y = r.bottom() + 12 if r.bottom() + 12 + self.card.height() < self.height() else \
                max(8, r.top() - self.card.height() - 12)
        else:
            x = r.right() + 12 if r.right() + 12 + self.card.width() < self.width() else \
                max(8, r.left() - self.card.width() - 12)
            y = min(max(8, r.top()), self.height() - self.card.height() - 8)
        if r.isNull():
            x, y = (self.width() - self.card.width()) // 2, (self.height() - self.card.height()) // 2
        self.card.move(x, y)
        self.update()

    def finish(self):
        self.win.removeEventFilter(self)
        self.hide()
        self.deleteLater()
        self.win.tour_finished()

    def paintEvent(self, _):
        p = QPainter(self)
        dim = QColor(0, 0, 0, 150)
        r = self.target_rect().intersected(self.rect())
        if r.isNull():
            p.fillRect(self.rect(), dim)
            return
        W, H = self.width(), self.height()
        # darken the four bands around the target; the target stays live
        p.fillRect(QRect(0, 0, W, r.top()), dim)
        p.fillRect(QRect(0, r.bottom() + 1, W, H - r.bottom() - 1), dim)
        p.fillRect(QRect(0, r.top(), r.left(), r.height()), dim)
        p.fillRect(QRect(r.right() + 1, r.top(), W - r.right() - 1, r.height()), dim)
        p.setPen(QPen(QColor(theme.DARK["accent"]), 2))
        p.drawRect(r)


# ═══════════════════════════════════════════════════════════════ window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.s = load_settings()
        self.c = theme.palette(self.s["theme"])
        set_theme(self.c)
        QApplication.instance().setProperty("rb_theme", self.s["theme"])
        self.setWindowTitle(f"{APP} {VERSION} - Memory Forensics Workstation")
        self.resize(1480, 920)
        self.runner = AnalysisRunner(self)
        self.helpmode = HelpMode()
        self.case: Optional[Path] = None
        self.t0 = 0.0
        self.state: Dict = {}
        self.rows: Dict[str, QTreeWidgetItem] = {}     # every plugin row of the case (all runs)
        self.row_info: Dict[str, Dict] = {}            # plugin -> {state, last_limit_s, error, parent}
        self.retry_queue: List[Dict] = []              # [{plugin, timeout}] waiting for the run to end
        self.run_queue: List[Dict] = []                # v2.4: dumps waiting to be analysed (see queue_add)
        self.queue_active = False                      # True between "Start queue" and the last dump
        self.queue_pos = 0
        self.queue_results: List[Dict] = []
        self._queue_cur: Optional[Dict] = None
        self._build()
        self.apply_theme(self.s["theme"])
        self.runner.event.connect(self._on_event)
        self.runner.log_line.connect(self._on_log)
        self.runner.finished.connect(self._on_finished)
        self._tick = QTimer(self, interval=1000, timeout=self._heartbeat)
        self._spin = QTimer(self, interval=120, timeout=self._spin_icons)
        self._est = QTimer(self, singleShot=True, interval=300,
                           timeout=lambda: self.setup.est.setText(self.setup.estimate()))
        self.setup.changed.connect(self._est.start)
        self._spin_frame = 0
        self._update_actions()
        if self.s.get("tour_on_start", True) and not self.s.get("tour_done"):
            QTimer.singleShot(600, self.start_tour)

    # ----------------------------------------------------------------- build
    def _act(self, text, icon_name, key, slot, shortcut=None, checkable=False):
        a = QAction(text, self)
        a.setProperty("icon_name", icon_name)
        a.setProperty("help_key", key)
        a.setToolTip(help_registry.tooltip(key))
        a.setCheckable(checkable)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        a.triggered.connect(slot)
        return a

    def _build(self):
        A = self._act
        self.a_open = A("Open dump", "open", "tb.open", self.setup_pick_dump, "Ctrl+O")
        self.a_load = A("Load results", "folder-tree", "tb.loadresults", self.load_results, "Ctrl+L")
        self.a_run = A("Start", "play", "tb.run", self.start_run, "F5")
        self.a_stop = A("Stop", "stop", "tb.stop", self.stop_run, "Shift+F5")
        self.a_out = A("Output folder", "folder", "tb.output", self.open_output)
        self.a_rep = A("HTML report", "report", "tb.report", self.open_report, "Ctrl+R")
        self.a_extract = A("Extract", "file-down", "tb.extract", self.open_extract, "Ctrl+E")
        self.a_help = A("Help mode", "help", "tb.helpmode", self.toggle_help, "F1", True)
        self.a_tour = A("Tour", "tour", "tb.tour", self.start_tour)
        self.a_gloss = A("Glossary", "glossary", "tb.glossary", lambda: GlossaryDialog(self).exec())
        self.a_set = A("Settings", "settings", "tb.settings", self.open_settings, "Ctrl+,")
        self.a_theme = A("Theme", "theme", "tb.theme", self.toggle_theme)
        self.a_about = A("About", "info", "tb.about", lambda: AboutDialog(self).exec())
        self.a_ti = A("Threat intel on this case", "radar", "tb.ti", lambda: self.start_ti_case(False))
        self.a_ticont = A("Continue VirusTotal lookups", "refresh-cw", "tb.ticont",
                          lambda: self.start_ti_case(True))
        self.a_tidb = A("Threat-intel databases", "database", "tb.tidb",
                        lambda: DatabasesDialog(self).exec())
        self.actions_all = [self.a_open, self.a_load, self.a_run, self.a_stop, self.a_out,
                            self.a_rep, self.a_extract, self.a_help, self.a_tour, self.a_gloss, self.a_set,
                            self.a_theme, self.a_about, self.a_ti, self.a_ticont, self.a_tidb]
        mb = self.menuBar()
        m = mb.addMenu("&File")
        for a in (self.a_open, self.a_load, self.a_out, self.a_rep):
            m.addAction(a)
        m.addSeparator()
        m.addAction("Exit", self.close)
        m = mb.addMenu("&Analysis")
        m.addAction(self.a_run)
        m.addAction(self.a_stop)
        m.addAction(self.a_extract)
        m.addSeparator()
        m.addAction(self.a_ti)
        m.addAction(self.a_ticont)
        m.addAction(self.a_tidb)
        m = mb.addMenu("&View")
        m.addAction(self.a_theme)
        self.view_menu = m
        m = mb.addMenu("&Help")
        for a in (self.a_help, self.a_tour, self.a_gloss, self.a_about):
            m.addAction(a)
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(QSize(18, 18))
        tb.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.addToolBar(tb)
        for a in (self.a_open, self.a_load):
            tb.addAction(a)
        tb.addSeparator()
        for a in (self.a_run, self.a_stop):
            tb.addAction(a)
        tb.addSeparator()
        for a in (self.a_out, self.a_rep, self.a_extract):
            tb.addAction(a)
        sp = QWidget()
        sp.setObjectName("Spacer")
        sp.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        tb.addWidget(sp)
        for a in (self.a_help, self.a_tour, self.a_gloss, self.a_theme, self.a_set, self.a_about):
            tb.addAction(a)
        self.toolbar = tb
        for a in self.actions_all:
            w = tb.widgetForAction(a)
            if w:
                w.setProperty("help_key", a.property("help_key"))
                if a is self.a_help:
                    w.setProperty("help_mode_switch", True)
        # central = results, docks = setup / monitor / log
        self.results = ResultsView()
        self.setCentralWidget(self.results)
        self.setup = SetupPanel(self.s)
        self.setup.start.clicked.connect(self.start_run)
        self.setup.qadd.clicked.connect(lambda: self.queue_add())
        self.setup.qremove.clicked.connect(self.queue_remove)
        self.setup.qstart.clicked.connect(self.queue_start)
        self.setup.drop.dropped_many.connect(self.queue_add)
        sc = QScrollArea()
        sc.setWidget(self.setup)
        sc.setWidgetResizable(True)
        sc.setFrameShape(QFrame.NoFrame)
        sc.setMinimumWidth(380)
        self.d_setup = self._dock("Case setup", sc, Qt.LeftDockWidgetArea)
        self.monitor = RunMonitor(self.c)
        self.d_mon = self._dock("Run monitor", self.monitor, Qt.RightDockWidgetArea)
        self.log = LogConsole()
        self.log.openf.clicked.connect(self.open_logfile)
        self.d_log = self._dock("Live log", self.log, Qt.BottomDockWidgetArea)
        self.xview = ExtractView(self.log.append)
        self.xview.bind_protection(self.s, save_settings)
        self.results.extract_opener = lambda: self.xview
        self.xview.job_finished.connect(self._extraction_done)
        self._focus_hidden: List[QDockWidget] = []
        self.results.tabs.currentChanged.connect(self._extract_focus)
        self.resizeDocks([self.d_setup, self.d_mon], [400, 470], Qt.Horizontal)
        self.resizeDocks([self.d_log], [220], Qt.Vertical)
        for d in (self.d_setup, self.d_mon, self.d_log):
            self.view_menu.addAction(d.toggleViewAction())
        # status bar
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.st_icon = QLabel()
        self.st_text = QLabel("Ready")
        self.st_pulse = QLabel()
        self.st_pulse.setFixedWidth(14)
        self.st_elapsed = QLabel("")
        self.st_eta = QLabel("")
        sb.addWidget(self.st_icon)
        sb.addWidget(self.st_text, 1)
        sb.addPermanentWidget(self.st_pulse)
        sb.addPermanentWidget(self.st_elapsed)
        sb.addPermanentWidget(self.st_eta)
        self.setAcceptDrops(True)
        QTimer.singleShot(0, lambda: self._tag_internal(self))

    def _dock(self, title, w, area):
        d = QDockWidget(title, self)
        d.setObjectName(title.replace(" ", "_"))
        d.setWidget(w)
        d.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable |
                      QDockWidget.DockWidgetClosable)
        self.addDockWidget(area, d)
        QTimer.singleShot(0, lambda d=d: self._tag_internal(d))
        return d

    def _tag_internal(self, root):
        """Give Qt's own sub-buttons (dock float/close, overflow chevrons) help."""
        for b in root.findChildren(QWidget):
            n = b.objectName()
            if n == "qt_dockwidget_floatbutton":
                helped(b, "dock.float")
            elif n == "qt_dockwidget_closebutton":
                helped(b, "dock.close")
            elif n in ("qt_toolbar_ext_button", "qt_menubar_ext_button"):
                helped(b, "ui.more")

    # ----------------------------------------------------------------- theme
    def apply_theme(self, name):
        self.s["theme"] = name
        self.c = theme.palette(name)
        set_theme(self.c)
        QApplication.instance().setProperty("rb_theme", name)
        icons.clear_cache()
        import tempfile
        xf = Path(tempfile.gettempdir()) / f"rb_close_{name}.svg"
        xf.write_bytes(icons.svg_bytes("x", self.c["muted"]))
        xu = xf.as_posix()
        QApplication.instance().setStyleSheet(
            theme.stylesheet(self.c) +
            f"QTabBar::close-button {{ image: url('{xu}'); subcontrol-position: right; "
            f"width: 12px; height: 12px; margin: 2px; }}"
            f"QTabBar::close-button:hover {{ background: {self.c['panel3']}; }}")
        for a in self.actions_all:
            a.setIcon(icons.icon(a.property("icon_name"), self.c["text"], 18))
        self.a_run.setIcon(icons.icon("play", self.c["ok"], 18))
        self.a_stop.setIcon(icons.icon("stop", self.c["err"], 18))
        self.setup.retheme(self.c)
        self.xview.retheme()
        self.monitor.anim.set_theme(self.c)
        self.log.retheme()
        for hb in self.findChildren(HelpButton):
            hb.setIcon(icons.icon("help", self.c["muted"], 14))
        self._set_status("Ready" if not self.runner.running() else self.st_text.text(), "ok")

    def toggle_theme(self):
        self.apply_theme("light" if self.s["theme"] == "dark" else "dark")
        save_settings(self.s)

    # -------------------------------------------------------------- actions
    def _update_actions(self):
        run = self.runner.running()
        self.a_run.setEnabled(not run)
        self.setup.start.setEnabled(not run)
        n = len(self.run_queue)
        self.setup.qstart.setText(f"Start queue ({n})" if n and not self.queue_active else
                                  f"Queue running - {n} left" if self.queue_active else "Start queue")
        self.setup.qstart.setEnabled(bool(n) and not self.queue_active)
        self.setup.qremove.setEnabled(bool(n))
        self.a_stop.setEnabled(run)
        has = self.case is not None and self.case.is_dir()
        self.a_out.setEnabled(has)
        self.a_rep.setEnabled(has and (self.case / "report.html").is_file())
        self.a_extract.setEnabled(has)
        self.a_ti.setEnabled(has and not run)
        self.a_ticont.setEnabled(has and not run and (self.case / "threat_intelligence" / "inventory.json").is_file())
        self.xview.set_analysis_running(run)

    def setup_pick_dump(self):
        self.setup._pick_dump()

    def toggle_help(self, on):
        self.helpmode.set_active(on)
        self._set_status("Help mode ON - click any control to learn about it (F1 to leave)"
                         if on else "Help mode off", "info")

    def open_settings(self):
        d = SettingsDialog(self.s, self)
        if d.exec():
            old = self.s["theme"]
            self.s = d.result_settings()
            save_settings(self.s)
            if self.s["theme"] != old:
                self.apply_theme(self.s["theme"])
            self.setup.jobs.setValue(int(self.s["jobs"]))
            self.setup.set_speed(self.s["speed"])
            if self.s.get("output_dir"):
                self.setup.out.setText(self.s["output_dir"])

    def load_results(self):
        d = QFileDialog.getExistingDirectory(self, "Open a RAMBreaker output folder",
                                             str(platform_compat.app_root() / "output"))
        if d:
            self.open_case(Path(d))

    def open_case(self, case: Path):
        """Load an existing case: results tree, Extraction workspace, and the plugin list
        with retry buttons (from the case folder)."""
        self.case = Path(case)
        self.results.load(self.case)
        self.xview.set_case(self.case)
        if not self.runner.running():
            self._clear_rows()
            self.state = {"plugins": {}}
            self._sync_rows_from_case()
            n = sum(1 for i in self.row_info.values()
                    if i.get("state") in ("failed", "timeout", "skipped", "not run"))
            self.monitor.stage.setText(f"Case loaded - {len(self.rows)} plugins"
                                       + (f", {n} can be retried (button in the Retry column)" if n else ""))
        self._update_actions()

    def _extract_focus(self, _i=None):
        """Give the Extraction workspace the full width: the setup and monitor
        panels step aside while it is the current tab (not during a run) and
        come back when another tab is chosen."""
        on_x = self.results.tabs.currentWidget() is self.xview
        if on_x and not self.runner.running():
            for d in (self.d_setup, self.d_mon):
                if d.isVisible() and not d.isFloating():
                    d.hide()
                    self._focus_hidden.append(d)
        elif not on_x and self._focus_hidden:
            for d in self._focus_hidden:
                d.show()
            self._focus_hidden = []

    def _extraction_done(self, _manifest: str):
        """Refresh the navigator (new 'Extraction' entries) and stay on the workspace."""
        if self.case and self.case.is_dir():
            self.results.load(self.case)
            self.results.open_widget(self.xview, "Extraction")

    def open_extract(self):
        if not (self.case and self.case.is_dir()):
            QMessageBox.information(self, APP, "Load a case first: run an analysis or use Load results.")
            return
        if self.xview.case != self.case:
            self.xview.set_case(self.case)
        self.results.open_widget(self.xview, "Extraction")

    def open_output(self):
        if self.case:
            platform_compat.open_path(self.case)

    def open_report(self):
        if self.case and (self.case / "report.html").is_file():
            platform_compat.open_path(self.case / "report.html")

    def open_logfile(self):
        if self.case and (self.case / "crescent_toolkit.log").is_file():
            platform_compat.open_path(self.case / "crescent_toolkit.log")

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        u = e.mimeData().urls()
        if len(u) > 1:
            self.queue_add([x.toLocalFile() for x in u])
        elif u:
            self.setup.dump.setText(u[0].toLocalFile())

    # ------------------------------------------------------------------ run
    def start_run(self):
        dump = Path(self.setup.dump.text().strip().strip('"'))
        if not dump.is_file():
            QMessageBox.warning(self, APP, "Pick an existing memory dump first.")
            return
        ioc = self.setup.ioc.text().strip()
        if ioc and not Path(ioc).is_file():
            QMessageBox.warning(self, APP, "The IOC list file does not exist.")
            return
        extra_env = {}
        ti_args: List[str] = []
        if PRESETS[self.setup.preset.currentIndex()][1] == "dfir-ti":
            d = ThreatIntelDialog(self.s, dump.name, self)
            if not d.exec():
                return
            o = d.result_opts()
            self.s.update(vt_rate=o["vt_rate"], vt_max=o["vt_max"], yara_set=o["yara_set"],
                          yara_custom_dir=o["yara_custom_dir"], protect_dumps=o["protect_dumps"],
                          zip_password=o["zip_password"])
            save_settings(self.s)
            ti_args = d.cli_args()
            extra_env = {"RAMBREAKER_VT_KEY": o["vt_key"]}
        self._start_entry(self._entry_for(dump, extra_env, ti_args))

    def _entry_for(self, dump: Path, extra_env=None, ti_args=None) -> Dict:
        """One analysis job (dump + the options chosen in the setup panel right now)."""
        cur = self.setup.dump.text()
        self.setup.dump.blockSignals(True)
        try:
            self.setup.dump.setText(str(dump))
            case = self.setup.case_dir()
            args = self.setup.build_args(self.s) + list(ti_args or [])
        finally:
            self.setup.dump.setText(cur)
            self.setup.dump.blockSignals(False)
        note = self.setup.osver.text().strip() if self.setup.known.isChecked() else ""
        return {"dump": str(dump), "case": str(case), "args": args, "env": dict(extra_env or {}),
                "jobs": self.setup.jobs.value(), "note": note,
                "label": f"{dump.name}  -  {self.setup.preset.currentText()}"}

    def _start_entry(self, entry: Dict):
        dump = Path(entry["dump"])
        extra_env = entry["env"]
        self.case = Path(entry["case"])
        self.case.mkdir(parents=True, exist_ok=True)
        args = entry["args"]
        self.state = {"plugins": {}, "total": 0, "done": 0, "failed": 0, "timeouts": 0,
                      "jobs": entry["jobs"], "expected": {}, "detect_done": False,
                      "step": 0, "steps": 8, "size_gb": dump.stat().st_size / 1024 ** 3,
                      "cmd": args[0], "batch_t": 0.0, "running_since": {}}
        self._clear_rows()
        self.monitor.bar.setValue(0)
        self.log._clear()
        self.log.logfile = self.case / "crescent_toolkit.log"
        self.log.start_session_file(platform_compat.app_root() / "logs" /
                                    f"rambreaker_{time.strftime('%Y%m%d_%H%M%S')}_{dump.stem}.log")
        if self.s.get("animation", True):
            self.monitor.anim.show()
            self.monitor.anim.start()
        else:
            self.monitor.anim.hide()
        self.t0 = time.time()
        self.monitor.stage.setText("Starting analysis process...")
        if self.queue_active:
            self.log.append("event", f"Queue: dump {self.queue_pos} of {self.queue_pos + len(self.run_queue)}"
                                     f" - {dump.name}")
        self.log.append("event", f"Starting: {' '.join(args)}")
        if entry.get("note"):
            self.log.append("event", f"Operator notes - OS version: {entry['note']}")
        self.runner.start(args, cwd=str(SRC), extra_env=extra_env)
        self._tick.start()
        self._spin.start()
        self._set_status((f"Queue {self.queue_pos}/{self.queue_pos + len(self.run_queue)}: " if self.queue_active
                          else "") + f"Analysing {dump.name}", "running")
        for d in self._focus_hidden:                  # panels set aside by the Extraction tab
            d.show()
        self._focus_hidden = []
        self._update_actions()
        self.d_mon.raise_()

    # ---------------------------------------------------------------- queue
    def queue_add(self, paths=None):
        """Add dumps to the queue with the options chosen in the setup panel right now.
        No paths: the dump in the 'Memory dump' field, or - if it is empty - a file picker
        that accepts several files."""
        if not paths:
            one = self.setup.dump.text().strip().strip('"')
            if one and Path(one).is_file():
                paths = [one]
            else:
                paths, _ = QFileDialog.getOpenFileNames(
                    self, "Add memory dumps to the queue", "",
                    "Memory images (*.raw *.mem *.vmem *.lime *.dmp *.bin *.img *.dd *.core *.elf);;All files (*)")
        files = [Path(p) for p in (paths or []) if p and Path(p).is_file()]
        if not files:
            if paths:
                QMessageBox.warning(self, APP, "None of the chosen files exists.")
            return
        ioc = self.setup.ioc.text().strip()
        if ioc and not Path(ioc).is_file():
            QMessageBox.warning(self, APP, "The IOC list file does not exist.")
            return
        extra_env, ti_args = {}, []
        if PRESETS[self.setup.preset.currentIndex()][1] == "dfir-ti":
            d = ThreatIntelDialog(self.s, f"{len(files)} queued dump(s)", self)
            if not d.exec():
                return
            o = d.result_opts()
            self.s.update(vt_rate=o["vt_rate"], vt_max=o["vt_max"], yara_set=o["yara_set"],
                          yara_custom_dir=o["yara_custom_dir"], protect_dumps=o["protect_dumps"],
                          zip_password=o["zip_password"])
            save_settings(self.s)
            ti_args = d.cli_args()
            extra_env = {"RAMBREAKER_VT_KEY": o["vt_key"]}
        have = {(q["dump"], q["case"]) for q in self.run_queue}
        added = 0
        for f in files:
            e = self._entry_for(f, extra_env, ti_args)
            if (e["dump"], e["case"]) in have:
                continue                               # same dump + same case folder is already queued
            have.add((e["dump"], e["case"]))
            self.run_queue.append(e)
            self.setup.qlist.addItem(e["label"])
            self.setup.qlist.item(self.setup.qlist.count() - 1).setToolTip(
                f"{e['dump']}\nCase folder: {e['case']}\nCommand: {' '.join(e['args'])}")
            added += 1
        self.log.append("event", f"Queue: {added} dump(s) added, {len(self.run_queue)} waiting"
                        + ("" if self.queue_active else " - press 'Start queue' to run them"))
        self._update_actions()

    def queue_remove(self):
        """Remove the selected queue entries (or the last one when nothing is selected)."""
        rows = sorted({i.row() for i in self.setup.qlist.selectedIndexes()}, reverse=True) or \
            ([len(self.run_queue) - 1] if self.run_queue else [])
        for r in rows:
            if 0 <= r < len(self.run_queue):
                self.run_queue.pop(r)
                self.setup.qlist.takeItem(r)
        self._update_actions()

    def queue_start(self):
        if not self.run_queue:
            QMessageBox.information(self, APP, "The queue is empty. Use 'Add to queue' first.")
            return
        self.queue_active = True
        self.queue_pos = 0
        self.queue_results = []
        if self.runner.running():
            self.log.append("event", f"Queue: {len(self.run_queue)} dump(s) will start when the current run ends")
            self._update_actions()
        else:
            self._queue_next()

    def _queue_next(self):
        while self.run_queue:
            e = self.run_queue.pop(0)
            self.setup.qlist.takeItem(0)
            self.queue_pos += 1
            if not Path(e["dump"]).is_file():
                self.log.append("error", f"Queue: {e['dump']} no longer exists - skipped")
                self.queue_results.append({"label": e["label"], "ok": False, "text": "dump file missing", "case": ""})
                continue
            self._queue_cur = e
            self._start_entry(e)
            return
        self._queue_done()

    def _queue_done(self):
        self.queue_active = False
        self._queue_cur = None
        okn = sum(1 for r in self.queue_results if r["ok"])
        self.log.append("ok" if okn == len(self.queue_results) else "warn",
                        f"Queue finished: {okn} of {len(self.queue_results)} dump(s) completed")
        for r in self.queue_results:
            self.log.append("ok" if r["ok"] else "error", f"  {r['label']}: {r['text']}"
                            + (f"  ->  {r['case']}" if r["case"] else ""))
        self._set_status(f"Queue finished: {okn} of {len(self.queue_results)} completed",
                         "ok" if okn == len(self.queue_results) else "warn")
        self.monitor.stage.setText(f"Queue finished - {okn} of {len(self.queue_results)} dump(s) completed; "
                                   "the last case is loaded, open the others with Load results")
        self._update_actions()

    def start_ti_case(self, vt_only: bool = False):
        """Threat intel on the loaded case (no new analysis): dump + hash + YARA + feeds +
        VirusTotal, or (vt_only) continue the VirusTotal lookups of an earlier run."""
        if self.runner.running() or not (self.case and self.case.is_dir()):
            return
        from modules import case_index
        image = case_index.locate_image(self.case, self.setup.dump.text().strip().strip('"'))
        if not image and not vt_only:
            f, _ = QFileDialog.getOpenFileName(self, "Memory dump of this case", "",
                                               "Memory images (*.raw *.mem *.vmem *.lime *.dmp *.bin *.img);;All files (*)")
            if not f:
                return
            image = f
        d = ThreatIntelDialog(self.s, self.case.name, self)
        if vt_only:
            d.setWindowTitle("Continue VirusTotal lookups")
        if not d.exec():
            return
        o = d.result_opts()
        if vt_only and not o["vt_key"]:
            QMessageBox.information(self, APP, "Continuing VirusTotal lookups needs a VirusTotal key.")
            return
        self.s.update(vt_rate=o["vt_rate"], vt_max=o["vt_max"], yara_set=o["yara_set"],
                      yara_custom_dir=o["yara_custom_dir"], protect_dumps=o["protect_dumps"],
                          zip_password=o["zip_password"])
        save_settings(self.s)
        args = ["ti", "-o", str(self.case), "--no-telemetry"] + (["-i", image] if image else []) + d.cli_args()
        if vt_only:
            args.append("--vt-only")
        size = Path(image).stat().st_size / 1024 ** 3 if image and Path(image).is_file() else 1.0
        self.state = {"plugins": {}, "total": 0, "done": 0, "failed": 0, "timeouts": 0,
                      "jobs": self.setup.jobs.value(), "expected": {}, "detect_done": True,
                      "step": 0, "steps": 8, "size_gb": size, "cmd": "ti", "batch_t": 0.0,
                      "running_since": {}}
        self._clear_rows()
        self.monitor.bar.setValue(0)
        self.log._clear()
        self.log.logfile = self.case / "crescent_toolkit.log"
        self.log.start_session_file(platform_compat.app_root() / "logs" /
                                    f"rambreaker_{time.strftime('%Y%m%d_%H%M%S')}_{self.case.name}_ti.log")
        if self.s.get("animation", True):
            self.monitor.anim.show()
            self.monitor.anim.start()
        self.t0 = time.time()
        self.monitor.stage.setText("Starting threat intel...")
        self.log.append("event", f"Starting: {' '.join(args)}")
        self.runner.start(args, cwd=str(SRC), extra_env={"RAMBREAKER_VT_KEY": o["vt_key"]})
        self._tick.start()
        self._spin.start()
        self._set_status(f"Threat intel on {self.case.name}", "running")
        for dk in self._focus_hidden:
            dk.show()
        self._focus_hidden = []
        self._update_actions()
        self.d_mon.raise_()

    def stop_run(self):
        if QMessageBox.question(self, APP, "Stop the running analysis? Results written so far are kept.") \
                == QMessageBox.Yes:
            self.log.append("warn", "Stop requested by the user - terminating the analysis process tree")
            self.runner.stop()

    # ---------------------------------------------------------------- events
    def _clear_rows(self):
        self.monitor.plugins.clear()
        self.rows = {}
        self.row_info = {}

    def _new_row(self, plugin) -> QTreeWidgetItem:
        it = self.rows.get(plugin)
        if it is None:
            short = plugin.split(".", 1)[1] if plugin.count(".") >= 2 else plugin
            it = QTreeWidgetItem(self.monitor.plugins, [short, "queued", "", "", ""])
            it.setToolTip(0, plugin)
            it.setIcon(0, icons.icon("queued", self.c["faint"], 14))
            self.rows[plugin] = it
        return it

    def _row(self, plugin) -> QTreeWidgetItem:
        """Row of a plugin of the CURRENT run (counted in its progress)."""
        it = self._new_row(plugin)
        self.state.setdefault("plugins", {})[plugin] = it
        return it

    # ------------------------------------------------------------ retry
    _STATE_LOOK = {"done": ("ok", "ok"), "empty": ("ok", "ok"), "failed": ("err", "fail"),
                   "timeout": ("warn", "timeout"), "skipped": ("warn", "warn"),
                   "not run": ("faint", "queued")}

    def _paint_state(self, it: QTreeWidgetItem, state: str, label: str):
        col, ic = self._STATE_LOOK.get(state, ("text", "queued"))
        it.setText(1, label)
        it.setForeground(1, QColor(self.c[col]))
        it.setIcon(0, icons.icon(ic, self.c[col], 14))

    def _set_retry_button(self, plugin: str):
        """Retry button in column 4 for a plugin that needs one (or 'queued')."""
        it = self.rows.get(plugin)
        if it is None:
            return
        info = self.row_info.get(plugin, {})
        queued = any(q["plugin"] == plugin for q in self.retry_queue)
        if not queued and info.get("state") not in ("failed", "timeout", "skipped", "not run"):
            self.monitor.plugins.removeItemWidget(it, 4)
            return
        b = self.monitor.plugins.itemWidget(it, 4)
        if b is None:
            b = QToolButton()
            b.setObjectName("RetryBtn")
            b.setAutoRaise(True)
            b.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            b.setProperty("help_key", "prog.retry")
            b.clicked.connect(lambda _=False, p=plugin: self.retry_clicked(p))
            self.monitor.plugins.setItemWidget(it, 4, b)
        b.setIcon(icons.icon("clock" if queued else "refresh-cw", self.c["muted" if queued else "accent"], 14))
        b.setText("queued" if queued else "")
        b.setEnabled(not queued)
        b.setToolTip("Queued: runs when the current analysis finishes" if queued
                     else f"Retry {plugin} ({info.get('state')})")

    def _sync_rows_from_case(self):
        """Show the case's plugins as saved on disk (after a run, or Load results)."""
        if not (self.case and self.case.is_dir()):
            return
        try:
            from modules import plugin_retry as pr
            rows = pr.case_plugin_states(self.case)
        except Exception as e:
            self.log.append("warn", f"Could not read the plugin states of this case: {e}")
            return
        for r in rows:
            p = r["plugin"]
            it = self._new_row(p)
            if it.text(1) in ("running", "retrying"):
                continue
            self.row_info[p] = r
            self._paint_state(it, r["state"], r["label"])
            if r.get("last_limit_s") and not it.text(3):
                it.setText(3, f"{r['last_limit_s']} s")
            it.setToolTip(1, r.get("error") or r["label"])
            self._set_retry_button(p)

    def retry_clicked(self, plugin: str):
        if not (self.case and self.case.is_dir()):
            return
        if self.xview.runner.running():
            QMessageBox.information(self, APP, "An extraction is running. Retry the plugin when it has finished.")
            return
        from modules import plugin_retry as pr
        try:
            disk = pr.case_plugin_states(self.case)
        except Exception:
            disk = []
        row = dict(next((r for r in disk if r["plugin"] == plugin), {}))
        live = self.row_info.get(plugin, {})
        if live.get("state") and (self.runner.running() or not row):
            row.update({k: v for k, v in live.items() if v})
        row.setdefault("plugin", plugin)
        row.setdefault("state", "not run")
        queued_now = {q["plugin"] for q in self.retry_queue}
        deps = [d for d in pr.dependents(plugin, disk) if d not in queued_now]
        os_t = (pr.read_summary(self.case).get("os") or self.state.get("os_type") or "windows").lower()
        steps = pr.affected_steps([plugin] + deps, os_t) + ["HTML report (always)"]
        exp = cal = None
        try:
            from modules import case_index
            from modules import timeout_model as tm
            img = case_index.locate_image(self.case, self.setup.dump.text().strip().strip('"'))
            gb = tm.image_size_gb(img) if img else self.state.get("size_gb", 1.0)
            m = tm.get_model()
            exp = int(m.expected(plugin, pr.engine_of(plugin), os_t, gb))
            cal = int(m.timeout(plugin, pr.engine_of(plugin), os_t, gb))
        except Exception:
            pass
        d = RetryDialog(row, deps, steps, exp, cal, self.runner.running(), self.c, self)
        if not d.exec():
            return
        items = [{"plugin": plugin, "timeout": d.timeout_s()}] + [{"plugin": x, "timeout": None} for x in deps]
        if self.runner.running():
            self.retry_queue += [i for i in items if i["plugin"] not in queued_now]
            for i in items:
                self._new_row(i["plugin"])
                self._set_retry_button(i["plugin"])
            self.log.append("event", f"Retry queued: {', '.join(i['plugin'] for i in items)} "
                                     "(starts when the current analysis finishes)")
            return
        self.start_retry(items)

    def start_retry(self, items: List[Dict]):
        from modules import case_index
        from modules import plugin_retry as pr
        image = case_index.locate_image(self.case, self.setup.dump.text().strip().strip('"'))
        if not image:
            f, _ = QFileDialog.getOpenFileName(self, "Memory dump of this case", "",
                                               "Memory images (*.raw *.mem *.vmem *.lime *.dmp *.bin *.img);;All files (*)")
            if not f:
                for i in items:
                    self._set_retry_button(i["plugin"])
                return
            image = f
        args = ["retry", "-o", str(self.case), "-i", image, "--retry-plugins", pr.make_spec(items),
                "--no-telemetry"]
        self.state = {"plugins": {}, "total": len(items), "done": 0, "failed": 0, "timeouts": 0,
                      "jobs": 1, "expected": {}, "detect_done": True, "step": 0, "steps": 8,
                      "size_gb": Path(image).stat().st_size / 1024 ** 3 if Path(image).is_file() else 1.0,
                      "cmd": "retry", "batch_t": 0.0, "running_since": {}}
        for i in items:
            it = self._row(i["plugin"])
            self.row_info.pop(i["plugin"], None)
            self.monitor.plugins.removeItemWidget(it, 4)
            self._paint_state(it, "not run", "queued")
            it.setText(2, "")
        self.log.logfile = self.case / "crescent_toolkit.log"
        self.log.start_session_file(platform_compat.app_root() / "logs" /
                                    f"rambreaker_{time.strftime('%Y%m%d_%H%M%S')}_{self.case.name}_retry.log")
        if self.s.get("animation", True):
            self.monitor.anim.show()
            self.monitor.anim.start()
        self.t0 = time.time()
        self.monitor.bar.setValue(0)
        self.monitor.stage.setText("Starting retry...")
        self.log.append("event", f"Starting: {' '.join(args)}")
        self.runner.start(args, cwd=str(SRC))
        self._tick.start()
        self._spin.start()
        self._set_status(f"Retrying {len(items)} plugin(s) on {self.case.name}", "running")
        self._update_actions()
        self.d_mon.raise_()

    def _on_event(self, ev: dict):
        k = ev.get("ev")
        st = self.state
        if k == "stage":
            name, state = ev.get("name", ""), ev.get("state")
            if state == "start":
                self.monitor.stage.setText(name + "...")
                self.monitor.anim.set_stage(name)
                self._set_status(name, "running")
                if ev.get("detail"):
                    self.log.append("event", f"{name}: {ev['detail']}")
                if ev.get("index"):
                    st["step"] = int(ev["index"])
                    st["steps"] = int(ev.get("of", 8))
                if ev.get("ti_step"):
                    st["ti_step"] = int(ev["ti_step"])
                    st["ti_steps"] = int(ev.get("ti_steps", 7))
            elif name == "Detecting OS" and state in ("done", "fail"):
                st["detect_done"] = True
                osn = ev.get("os_type", "?")
                st["os_type"] = osn
                self.log.append("ok" if state == "done" else "warn",
                                f"Detected OS: {osn} / engine {ev.get('engine', '?')} "
                                f"{ev.get('profile', '')}".strip())
        elif k == "batch":
            st["total"] = len(ev.get("plugins", []))
            st["expected"].update(ev.get("expected", {}))
            st["jobs"] = int(ev.get("jobs", st["jobs"]))
            st["batch_t"] = time.time()
            for p in ev.get("plugins", []):
                it = self._row(p)
                exp = st["expected"].get(p)
                it.setText(3, f"~{int(exp)} s" if exp else "")
            self.log.append("event", f"Plugin batch: {st['total']} plugins, estimated "
                                     f"{int(ev.get('eta_s', 0))} s with {st['jobs']} parallel jobs")
        elif k == "plugin":
            p, state = ev.get("plugin"), ev.get("state")
            if p not in st["plugins"]:
                st["total"] += 1      # e.g. background Vol2 extras, not in the batch list
            it = self._row(p)
            if state in ("running", "retry"):
                st["running_since"][p] = time.time()
                it.setText(1, "running" if state == "running" else "retrying")
                it.setText(3, f"{ev.get('timeout_s', '')} s" if ev.get("timeout_s") else "")
                it.setForeground(1, QColor(self.c["accent" if state == "running" else "warn"]))
                self.row_info[p] = {"state": "running", "limit_s": ev.get("timeout_s")}
                self.monitor.plugins.removeItemWidget(it, 4)
            else:
                st["running_since"].pop(p, None)
                disk_state = {"done": "done", "cached": "done", "failed": "failed",
                              "timeout": "timeout", "skipped": "skipped"}.get(state, state)
                lbl = {"done": "done", "cached": "done (earlier run)", "failed": "failed",
                       "timeout": "timed out", "skipped": "skipped (dependency)"}.get(state, state)
                self._paint_state(it, disk_state, lbl)
                it.setText(2, "reused" if state == "cached" else
                           ("" if state == "skipped" else f"{ev.get('duration_s', 0)} s"))
                prev = self.row_info.get(p, {})
                self.row_info[p] = {"plugin": p, "state": disk_state,
                                    "error": str(ev.get("error", "")), "parent": ev.get("parent"),
                                    "last_limit_s": prev.get("limit_s") if state == "timeout" else None}
                if ev.get("error"):
                    it.setToolTip(1, str(ev["error"]))
                self._set_retry_button(p)
                if state == "timeout":
                    st["timeouts"] += 1
                elif state == "failed":
                    st["failed"] += 1
        elif k == "info":
            self.log.append("event", ev.get("msg", ""))
        self._progress()

    def _progress(self):
        st = self.state
        tot = max(1, st.get("total", 0))
        done = sum(1 for x in st.get("plugins", {}).values()
                   if x.text(1) in ("done", "done (earlier run)", "done (no rows)", "failed", "timed out",
                                    "skipped (dependency)"))
        st["done"] = done
        step, steps = st.get("step", 0), st.get("steps", 8)
        if st.get("cmd") == "extract":
            frac = 0.06 * st.get("detect_done", False) + 0.94 * done / tot
        else:
            post = max(0, step - 1) / max(1, steps - 1) if step >= 2 else 0.0
            frac = 0.05 * st.get("detect_done", False) + 0.55 * (done / tot if st.get("total") else
                                                              (1.0 if step >= 2 else 0.0)) + 0.40 * post
        if st.get("cmd") in ("ti", "dfir-ti"):
            tif = max(0, st.get("ti_step", 0) - 1) / max(1, st.get("ti_steps", 7))
            frac = tif if st["cmd"] == "ti" else 0.75 * frac + 0.25 * tif
            if st["cmd"] == "ti":
                self.monitor.counts.setText(f"Threat intel step {st.get('ti_step', 0)}/{st.get('ti_steps', 7)}")
        frac = min(0.995, frac)
        self.monitor.bar.setValue(int(frac * 1000))
        self.monitor.anim.set_progress(frac)
        if st.get("cmd") != "ti":
            self.monitor.counts.setText(f"Plugins: {done}/{st.get('total', 0)}   failed {st.get('failed', 0)}"
                                        f"   timed out {st.get('timeouts', 0)}")
        # ETA: remaining expected plugin work / jobs + remaining post-processing
        exp = st.get("expected", {})
        rem = 0.0
        now = time.time()
        for p, it in st.get("plugins", {}).items():
            if it.text(1) in ("queued", ""):
                rem += exp.get(p, 10)
            elif it.text(1) in ("running", "retrying"):
                rem += max(0.0, exp.get(p, 10) - (now - st["running_since"].get(p, now)))
        rem /= max(1, st.get("jobs", 4))
        if st.get("cmd") != "extract":
            post_left = 1.0 - (max(0, step - 1) / max(1, steps - 1) if step >= 2 else 0.0)
            rem += POST_S_PER_GB * st.get("size_gb", 1) * post_left
        st["eta"] = rem

    def _fmt(self, s):
        s = int(max(0, s))
        return f"{s // 3600}h{(s % 3600) // 60:02d}m{s % 60:02d}s" if s >= 3600 else f"{s // 60}m{s % 60:02d}s"

    def _heartbeat(self):
        if not self.runner.running():
            return
        now = time.time()
        el = now - self.t0
        idle = now - self.runner.last_activity
        self.monitor.elapsed.setText(f"Elapsed: {self._fmt(el)}")
        self.st_elapsed.setText(f"Elapsed {self._fmt(el)}")
        eta = self.state.get("eta")
        if eta is not None and self.state.get("total"):
            self.monitor.eta.setText(f"ETA: ~{self._fmt(eta)}")
            self.st_eta.setText(f"ETA ~{self._fmt(eta)}")
        else:
            self.monitor.eta.setText("ETA: calculating...")
        on = int(now * 2) % 2 == 0
        self.st_pulse.setPixmap(icons.pixmap("circle-dot", self.c["ok"] if on else self.c["accent_lo"], 12))
        run = self.state.get("running_since", {})
        longest = max(run.items(), key=lambda x: now - x[1]) if run else None
        if idle < 60:
            msg = f"Alive - last activity {int(idle)} s ago"
            col = self.c["muted"]
        elif longest:
            p, since = longest
            lim = self.state["plugins"][p].text(3)
            msg = (f"Still working... {p} has been running {int(now - since)} s (limit {lim}). "
                   "No output is normal for long scans.")
            col = self.c["muted"]
            if idle > 600:
                msg += " If it passes its limit RAMBreaker kills it and retries once with a longer limit."
                col = self.c["warn"]
        else:
            msg = f"Still working... no new output for {int(idle)} s"
            col = self.c["warn"] if idle > 900 else self.c["muted"]
        self.monitor.beat.setText(msg)
        self.monitor.beat.setStyleSheet(f"color:{col}")
        self._progress()

    def _spin_icons(self):
        self._spin_frame = (self._spin_frame + 1) % 8
        frames = self._spinner_frames()
        for p, it in self.state.get("plugins", {}).items():
            if it.text(1) in ("running", "retrying"):
                it.setIcon(0, frames[self._spin_frame])

    def _spinner_frames(self):
        """8 pre-rendered rotations of the loader icon (cheap live spinner)."""
        key = self.c["accent"]
        if getattr(self, "_frames_key", None) != key:
            from PySide6.QtGui import QIcon, QPixmap, QTransform
            base = icons.pixmap("spinner", key, 14)
            self._frames = []
            for k in range(8):
                pm = base.transformed(QTransform().rotate(45 * k), Qt.SmoothTransformation)
                self._frames.append(QIcon(pm))
            self._frames_key = key
        return self._frames

    def _on_log(self, level, text):
        self.log.append(level, text)
        t = text.strip()
        if "IOC check:" in t and "found" in t:
            self.monitor.anim.flash_hit(6)
        if "Sigma:" in t and "fired" in t and not t.startswith("[i]"):
            self.monitor.anim.flash_hit(4)

    def _on_finished(self, code, stopped):
        self._tick.stop()
        self._spin.stop()
        ok = code == 0 and not stopped
        self.monitor.anim.stop(done=ok)
        was_retry = self.state.get("cmd") == "retry"
        if ok:
            self.monitor.bar.setValue(1000)
            self.monitor.stage.setText("Retry finished - report rebuilt, results reloaded" if was_retry
                                       else "Finished - results loaded")
            self._set_status("Retry complete" if was_retry else "Analysis complete", "ok")
            self.log.append("ok", f"{'Retry' if was_retry else 'Analysis'} finished in "
                                  f"{self._fmt(time.time() - self.t0)}")
        elif stopped:
            self.monitor.stage.setText("Stopped by user - partial results loaded")
            self._set_status("Stopped", "warn")
        else:
            self.monitor.stage.setText(f"Analysis ended with an error (exit code {code}) - see the log")
            self._set_status(f"Failed (exit {code})", "error")
            self.log.append("error", f"Analysis process exited with code {code}")
        self.monitor.eta.setText("ETA: -")
        self.st_eta.setText("")
        if self.case and self.case.is_dir():
            self.results.load(self.case)
            self.xview.set_case(self.case)
        queue, self.retry_queue = self.retry_queue, []
        self._sync_rows_from_case()
        for q in queue:
            self._set_retry_button(q["plugin"])
        self._update_actions()
        if queue:
            if stopped:
                self.log.append("warn", "Stopped by the user: the queued retries were NOT started "
                                        f"({', '.join(q['plugin'] for q in queue)}). Press their retry buttons again.")
            else:
                self.log.append("event", f"Starting the queued retries: {', '.join(q['plugin'] for q in queue)}")
                QTimer.singleShot(300, lambda q=queue: self.start_retry(q))
        # v2.4 dump queue: note the result of the queue's dump, then start the next one
        if self.queue_active:
            if self._queue_cur is not None and not was_retry:
                self.queue_results.append({
                    "label": self._queue_cur["label"], "ok": ok, "case": str(self.case or ""),
                    "text": (f"completed in {self._fmt(time.time() - self.t0)}" if ok else
                             "stopped by the user" if stopped else f"FAILED (exit code {code})")})
                self._queue_cur = None
            if stopped:
                self.queue_active = False
                if self.run_queue:
                    self.log.append("warn", f"Queue stopped: {len(self.run_queue)} dump(s) were NOT started. They "
                                            "stay in the queue list - press 'Start queue' to continue.")
                self._update_actions()
            elif queue:
                pass                                   # the queued retries run first; this method is called again
            elif self.run_queue:
                self.log.append("event", f"Queue: starting the next dump ({len(self.run_queue)} left)")
                QTimer.singleShot(600, self._queue_next)
            else:
                self._queue_done()

    def _set_status(self, text, kind):
        col = {"ok": self.c["ok"], "warn": self.c["warn"], "error": self.c["err"],
               "running": self.c["accent"], "info": self.c["info"]}.get(kind, self.c["text"])
        ic = {"ok": "ok", "warn": "warn", "error": "fail", "running": "activity", "info": "info"}.get(kind, "info")
        self.st_icon.setPixmap(icons.pixmap(ic, col, 14))
        self.st_text.setText(text)

    # ------------------------------------------------------------------ tour
    def start_tour(self):
        steps = [
            (lambda: self.toolbar, "Toolbar",
             "Open a dump, start or stop the analysis, open the output folder or HTML report. "
             "On the right: Help mode, this tour, the glossary, theme and settings."),
            (lambda: self.setup.drop, "1. Load a memory dump",
             "Drag a RAM image onto this box or use Browse. The dump is only ever read, never changed."),
            (lambda: self.setup.preset, "2. Choose a preset",
             "Standard is right for most cases. Quick triage gives a process list in minutes. "
             "A preset fills in 'Plugin category' (what to look at) and 'Fast mode' (how much "
             "to run); click the ? next to any of them for an animated guide."),
            (lambda: self.setup.known, "Optional: you already know the OS",
             "Tick this to skip automatic detection and enter OS / profile / symbol file yourself."),
            (lambda: self.setup.ioc, "Optional: IOC list",
             "Load your threat-intel indicators; each one is searched in the whole dump and all results."),
            (lambda: self.setup.est, "Estimated time",
             "Predicted from the dump size and measured plugin costs, before you start."),
            (lambda: self.setup.start, "3. Start",
             "Starts the analysis. Everything runs in the background - the window stays responsive."),
            (lambda: self.monitor, "Run monitor",
             "Live progress: the memory map fills as work completes, with stage, ETA, heartbeat and "
             "every plugin's state."),
            (lambda: self.log, "Live log",
             "Plain-language log of every step, colour-coded. Pause, filter, search, copy."),
            (lambda: self.results, "Results",
             "After the run: navigate the case on the left (processes, network, findings, IOCs, "
             "e-mail, plugins); each opens as a sortable, filterable table."),
            (lambda: self.toolbar.widgetForAction(self.a_extract), "Extract files, processes, memory",
             "After a run: search the dump's file list and pull files out, dump process executables, "
             "DLLs or full memory, dump VAD memory regions (whole process or single regions), hunt "
             "strings and build an export pack. Every result gets a manifest with hashes."),
            (lambda: self.toolbar.widgetForAction(self.a_help), "Help everywhere",
             "Every control has a ? next to it. Help mode (F1) turns every click into an explanation."),
        ]
        TourOverlay(self, steps).start()

    def tour_finished(self):
        self.s["tour_done"] = True
        save_settings(self.s)

    def closeEvent(self, e):
        if self.xview.runner.running():
            if QMessageBox.question(self, APP, "An extraction is running. Stop it and quit?") != QMessageBox.Yes:
                e.ignore()
                return
            self.xview.runner.stop()
        if self.runner.running():
            if QMessageBox.question(self, APP, "An analysis is running. Stop it and quit?") != QMessageBox.Yes:
                e.ignore()
                return
            self.runner.stop()
        save_settings(self.s)
        super().closeEvent(e)
