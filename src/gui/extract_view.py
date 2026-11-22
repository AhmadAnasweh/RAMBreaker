"""Extraction workspace: search and pull files, processes, memory regions (VAD),
hunt strings and build export packs from a finished case - from the GUI.

Lists come from the case's own plugin JSON (modules/case_index.py, no
Volatility run needed to browse). Extraction runs as a child process
(`crescent_toolkit.py xjob --spec ...`, modules/extract_jobs.py) so the window
stays responsive; progress arrives as @@RB xjob/xitem events.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from PySide6.QtCore import (QAbstractTableModel, QModelIndex, Qt,
                            QThread, QTimer, Signal)
from PySide6.QtWidgets import (QAbstractItemView, QButtonGroup, QCheckBox,
                               QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QListWidget, QMessageBox, QPlainTextEdit,
                               QProgressBar, QPushButton, QRadioButton, QSplitter, QTableView,
                               QTabWidget, QVBoxLayout, QWidget)

from gui import icons
from gui.runner import AnalysisRunner
from gui.widgets import ComboBox, FastSortProxy, HelpButton, Spinner, THEME, helped

import sys  # noqa: E402

# The toolkit (modules\) is not frozen into the GUI exe: it is loaded from
# <exe dir>\app at runtime, so put that on the path before importing it.
_SRC = (Path(sys.executable).resolve().parent / "app" if getattr(sys, "frozen", False)
        else Path(__file__).resolve().parent.parent)
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
from modules import case_index as ci  # noqa: E402


# ------------------------------------------------------------------ helpers
class Loader(QThread):
    """Runs a function off the UI thread (big JSON files) and hands back the result."""
    done = Signal(object)

    def __init__(self, fn: Callable, parent=None):
        super().__init__(parent)
        self.fn = fn

    def run(self):
        try:
            r = self.fn()
        except Exception as e:           # surfaced in the UI, never crashes it
            r = e
        self.done.emit(r)


class CheckModel(QAbstractTableModel):
    """Rows of dicts with a leading checkbox column; checks survive filtering."""
    checks_changed = Signal()

    def __init__(self, cols: List[tuple], key: str):
        super().__init__()
        self.cols = cols                 # [(dict key, header)]
        self.key = key                   # unique row id field
        self.rows: List[Dict[str, Any]] = []
        self.checked: Set[str] = set()

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.checked = {c for c in self.checked if any(self.rid(r) == c for r in rows[:1])} if rows else set()
        self.checked.clear()
        self.endResetModel()
        self.checks_changed.emit()

    def rid(self, r) -> str:
        return str(r.get(self.key, id(r)))

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.cols) + 1

    def headerData(self, s, o, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and o == Qt.Horizontal:
            return "" if s == 0 else self.cols[s - 1][1]
        return None

    def flags(self, idx):
        f = Qt.ItemIsEnabled | Qt.ItemIsSelectable
        if idx.column() == 0:
            f |= Qt.ItemIsUserCheckable
        return f

    def data(self, idx, role=Qt.DisplayRole):
        if not idx.isValid():
            return None
        r = self.rows[idx.row()]
        c = idx.column()
        if c == 0:
            if role == Qt.CheckStateRole:
                return Qt.Checked if self.rid(r) in self.checked else Qt.Unchecked
            if role == Qt.UserRole:
                return 0 if self.rid(r) in self.checked else 1
            return None
        k = self.cols[c - 1][0]
        v = r.get(k)
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            if isinstance(v, list):
                v = "; ".join(map(str, v))
            if k == "size" and isinstance(v, int):
                v = ci.fmt_size(v) if v else ""
            s = "" if v is None else str(v)
            if role == Qt.ToolTipRole:
                return s if len(s) > 40 else None
            return s
        if role == Qt.UserRole:
            if isinstance(v, (int, float)):
                return v
            if k in ("pid", "ppid") and str(v).isdigit():
                return int(v)
            return "" if v is None else str(v).lower()
        if role == Qt.ForegroundRole and k in ("flags", "injection") and v:
            from PySide6.QtGui import QColor
            return QColor(THEME.get("warn", "#d29922"))
        return None

    def sort_key(self, r, column):
        """The same order the UserRole sort used, computed once per row."""
        if column == 0:
            return 0 if self.rid(r) in self.checked else 1
        k = self.cols[column - 1][0]
        v = r.get(k)
        if isinstance(v, (int, float)):
            return v
        if k in ("pid", "ppid") and str(v).isdigit():
            return int(v)
        return "" if v is None else str(v).lower()

    def setData(self, idx, value, role=Qt.EditRole):
        if idx.column() == 0 and role == Qt.CheckStateRole:
            rid = self.rid(self.rows[idx.row()])
            if Qt.CheckState(value) == Qt.Checked:
                self.checked.add(rid)
            else:
                self.checked.discard(rid)
            self.dataChanged.emit(idx, idx, [Qt.CheckStateRole])
            self.checks_changed.emit()
            return True
        return False

    def set_checked(self, rids, on=True):
        if on:
            self.checked |= set(rids)
        else:
            self.checked -= set(rids)
        if self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows) - 1, 0), [Qt.CheckStateRole])
        self.checks_changed.emit()

    def checked_rows(self):
        return [r for r in self.rows if self.rid(r) in self.checked]


class RowFilter(FastSortProxy):
    """Text over chosen fields + an optional predicate (extension, flags...)."""

    def __init__(self, fields: List[str], parent=None):
        super().__init__(parent)
        self.fields = fields
        self.text = ""
        self.pred: Optional[Callable[[dict], bool]] = None
        self.setSortRole(Qt.UserRole)

    def set_text(self, t):
        self.text = (t or "").strip().lower()
        self.invalidateFilter()

    def set_pred(self, p):
        self.pred = p
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        r = self.sourceModel().rows[row]
        if self.pred is not None and not self.pred(r):
            return False
        if not self.text:
            return True
        hay = " ".join(str(r.get(f, "")) for f in self.fields).lower()
        return all(t in hay for t in self.text.split())

    def visible_ids(self):
        m = self.sourceModel()
        return [m.rid(m.rows[self.mapToSource(self.index(i, 0)).row()]) for i in range(self.rowCount())]


def table(model, proxy, key) -> QTableView:
    v = QTableView()
    proxy.setSourceModel(model)
    # no live re-sort: with the default (checkbox column, descending) a row
    # jumped to the bottom the moment it was ticked; sort only on header click
    proxy.setDynamicSortFilter(False)
    v.setModel(proxy)
    v.setSortingEnabled(True)
    v.sortByColumn(1, Qt.AscendingOrder)
    v.setAlternatingRowColors(True)
    v.setSelectionBehavior(QAbstractItemView.SelectRows)
    v.setSelectionMode(QAbstractItemView.SingleSelection)
    v.verticalHeader().setDefaultSectionSize(22)
    v.verticalHeader().setVisible(False)
    h = v.horizontalHeader()
    h.setSectionResizeMode(QHeaderView.Interactive)
    h.setStretchLastSection(True)
    v.setColumnWidth(0, 28)
    v.setWordWrap(False)
    # header + 2 rows (+ scrollbar) stay visible, so growing the results pane
    # after a job can never squeeze a list to the bare header
    v.setMinimumHeight(h.sizeHint().height() + 2 * 22 + v.horizontalScrollBar().sizeHint().height() + 4)
    helped(v, key)
    return v


def btn(text, key, icon_name=None, primary=False) -> QPushButton:
    b = QPushButton(text)
    b.setProperty("icon_name", icon_name or "")
    b.setProperty("primary", primary)
    if primary:
        b.setObjectName("Primary")
    if icon_name:
        b.setIcon(icons.icon(icon_name, "#ffffff" if primary else THEME.get("text", "#ddd"), 14))
    helped(b, key)
    return b


def row(*ws, stretch_at: Optional[int] = None) -> QHBoxLayout:
    h = QHBoxLayout()
    h.setSpacing(6)
    for i, w in enumerate(ws):
        if w is None:
            h.addStretch(1)
        elif isinstance(w, str):
            h.addWidget(HelpButton(w))
        else:
            h.addWidget(w, 1 if i == stretch_at else 0)
    return h


def muted(text, wrap=True) -> QLabel:
    l = QLabel(text)
    l.setObjectName("Muted")
    l.setWordWrap(wrap)
    return l


# ------------------------------------------------------------- the view
class ExtractView(QWidget):
    job_finished = Signal(str)          # manifest path ("" if none)

    def __init__(self, log_sink: Callable[[str, str], None], parent=None):
        super().__init__(parent)
        self.log_sink = log_sink
        self.case: Optional[Path] = None
        self.info: Dict[str, str] = {}
        self.runner = AnalysisRunner(self)
        self.runner.event.connect(self._on_event)
        self.runner.log_line.connect(self._on_log)
        self.runner.finished.connect(self._on_done)
        self._loaders: List[Loader] = []
        self.analysis_running = False
        self.job: Dict[str, Any] = {}
        self.vad_checks: Dict[str, Set[str]] = {}     # pid -> region starts (per-region mode)
        self.vad_regions: Dict[str, List[dict]] = {}
        self.cur_pid: Optional[str] = None
        self._build()
        self._busy(False)

    # ================================================================ build
    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        lay.setSpacing(6)
        hdr = QLabel("Extraction")
        hdr.setObjectName("H2")
        self.case_lbl = muted("No case loaded", wrap=False)
        lay.addLayout(row(hdr, self.case_lbl, None, "x.overview"))
        grid = QGridLayout()
        grid.setHorizontalSpacing(6)
        grid.setVerticalSpacing(4)
        self.dump = QLineEdit()
        self.dump.setPlaceholderText("Memory dump of this case")
        helped(self.dump, "x.dump")
        self.dump_b = btn("Browse", "x.dumpbrowse", "open")
        self.dest = QLineEdit()
        self.dest.setPlaceholderText("Folder that receives the extracted data")
        helped(self.dest, "x.dest")
        self.dest_b = btn("Browse", "x.destbrowse", "open")
        self.dest_open = btn("Open", "x.destopen", "external-link")
        grid.addWidget(QLabel("Memory dump"), 0, 0)
        grid.addWidget(self.dump, 0, 1)
        grid.addWidget(self.dump_b, 0, 2)
        grid.addWidget(HelpButton("x.dump"), 0, 4)
        grid.addWidget(QLabel("Save to"), 1, 0)
        grid.addWidget(self.dest, 1, 1)
        grid.addWidget(self.dest_b, 1, 2)
        grid.addWidget(self.dest_open, 1, 3)
        grid.addWidget(HelpButton("x.dest"), 1, 4)
        # v2.5: a dumped file can be live malware - by default each one goes straight
        # into its own password-protected ZIP (modules/safe_zip.py)
        self.protect = QCheckBox("Protect extracted files: each one in its own password-protected ZIP (AES-256)")
        self.protect.setChecked(True)
        helped(self.protect, "x.protect")
        self.zippw = QLineEdit("infected")
        self.zippw.setMaximumWidth(140)
        helped(self.zippw, "x.zippw")
        prow = QHBoxLayout()
        prow.addWidget(self.protect)
        prow.addSpacing(8)
        prow.addWidget(QLabel("Password"))
        prow.addWidget(self.zippw)
        prow.addStretch(1)
        grid.addWidget(QLabel("Safety"), 2, 0)
        grid.addLayout(prow, 2, 1, 1, 3)
        grid.addWidget(HelpButton("x.protect"), 2, 4)
        grid.setColumnStretch(1, 1)
        lay.addLayout(grid)
        self.protect.toggled.connect(self.zippw.setEnabled)
        self.dump_b.clicked.connect(self._pick_dump)
        self.dest_b.clicked.connect(self._pick_dest)
        self.dest_open.clicked.connect(lambda: self._open_path(Path(self.dest.text().strip())))

        split = self.split = QSplitter(Qt.Vertical)
        self.tabs = QTabWidget()
        helped(self.tabs, "x.tabs")
        self.tabs.addTab(self._files_tab(), icons.icon("file-down", THEME.get("muted", "#999"), 14), "Files")
        self.tabs.addTab(self._procs_tab(), icons.icon("process", THEME.get("muted", "#999"), 14), "Processes")
        self.tabs.addTab(self._vad_tab(), icons.icon("layers", THEME.get("muted", "#999"), 14), "Memory regions (VAD)")
        self.tabs.addTab(self._hunt_tab(), icons.icon("scan-search", THEME.get("muted", "#999"), 14), "String hunt")
        self.tabs.addTab(self._export_tab(), icons.icon("package", THEME.get("muted", "#999"), 14), "Export pack")
        split.addWidget(self.tabs)
        split.addWidget(self._results_panel())
        split.setChildrenCollapsible(False)
        split.setSizes([640, 150])
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 1)
        lay.addWidget(split, 1)
        # job strip
        self.spin = Spinner(14)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(10)
        helped(self.bar, "x.progress")
        self.job_lbl = QLabel("Idle")
        self.elapsed = muted("", wrap=False)
        self.stop_b = btn("Stop", "x.stop", "stop")
        self.stop_b.setObjectName("Danger")
        self.stop_b.clicked.connect(self._stop)
        lay.addLayout(row(self.spin, self.job_lbl, self.bar, self.elapsed, self.stop_b, "x.progress",
                          stretch_at=2))
        self._tick = QTimer(self, interval=1000, timeout=self._heartbeat)

    # ---------------------------------------------------------------- files
    def _files_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 6, 4, 4)
        self.f_src = muted("", wrap=False)
        v.addWidget(self.f_src)
        self.f_search = QLineEdit()
        self.f_search.setPlaceholderText(r"Search name or path, e.g.  .evtx   \Users\   hosts   (all words must match)")
        self.f_search.setClearButtonEnabled(True)
        helped(self.f_search, "x.f.search")
        self.f_ext = ComboBox()
        self.f_ext.setMinimumWidth(130)
        helped(self.f_ext, "x.f.ext")
        self.f_rec = QCheckBox("Only recoverable")
        helped(self.f_rec, "x.f.rec")
        self.f_count = muted("", wrap=False)
        v.addLayout(row(self.f_search, "x.f.search", self.f_ext, "x.f.ext", self.f_rec, "x.f.rec",
                        self.f_count, stretch_at=0))
        self.f_model = CheckModel([("name", "Name"), ("path", "Path"), ("offset", "Offset"),
                                   ("cached_pages", "Cached pages"), ("size", "Size"),
                                   ("inode_addr", "Inode")], "path_key")
        self.f_proxy = RowFilter(["name", "path"])
        self.f_view = table(self.f_model, self.f_proxy, "x.f.table")
        self.f_view.setColumnWidth(1, 220)
        self.f_view.setColumnWidth(2, 520)
        v.addWidget(self.f_view, 1)
        self.f_empty = QWidget()
        ev = QHBoxLayout(self.f_empty)
        ev.setContentsMargins(0, 0, 0, 0)
        self.f_empty_lbl = muted("This case has no file list yet.")
        self.f_build = btn("Build file list", "x.f.build", "list-checks")
        self.f_build.clicked.connect(self._build_filelist)
        ev.addWidget(self.f_empty_lbl, 1)
        ev.addWidget(self.f_build)
        ev.addWidget(HelpButton("x.f.build"))
        v.addWidget(self.f_empty)
        self.f_all = btn("Check all shown", "x.f.checkall", "list-checks")
        self.f_none = btn("Uncheck all", "x.f.uncheck", "x")
        self.f_go = btn("Extract checked files", "x.f.extract", "download", primary=True)
        v.addLayout(row(self.f_all, self.f_none, None, self.f_go, "x.f.extract"))
        self.f_search.textChanged.connect(self._f_filter)
        self.f_ext.currentIndexChanged.connect(self._f_filter)
        self.f_rec.toggled.connect(self._f_filter)
        self.f_model.checks_changed.connect(self._f_count_upd)
        self.f_all.clicked.connect(lambda: self._check_shown(self.f_model, self.f_proxy))
        self.f_none.clicked.connect(lambda: self.f_model.set_checked(list(self.f_model.checked), False))
        self.f_go.clicked.connect(self._extract_files)
        return w

    # ------------------------------------------------------------ processes
    def _procs_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 6, 4, 4)
        self.p_search = QLineEdit()
        self.p_search.setPlaceholderText("Filter by PID, name, command line or flag")
        self.p_search.setClearButtonEnabled(True)
        helped(self.p_search, "x.p.search")
        self.p_flagged = QCheckBox("Only flagged")
        helped(self.p_flagged, "x.p.flagged")
        self.p_count = muted("", wrap=False)
        v.addLayout(row(self.p_search, "x.p.search", self.p_flagged, "x.p.flagged", self.p_count,
                        stretch_at=0))
        self.p_model = CheckModel([("pid", "PID"), ("ppid", "PPID"), ("name", "Name"),
                                   ("flags", "Flags"), ("cmdline", "Command line")], "pid")
        self.p_proxy = RowFilter(["pid", "name", "cmdline", "flags"])
        self.p_view = table(self.p_model, self.p_proxy, "x.p.table")
        for i, wd in ((1, 60), (2, 60), (3, 170), (4, 260)):
            self.p_view.setColumnWidth(i, wd)
        v.addWidget(self.p_view, 1)
        self.p_exe = QCheckBox("Executable image")
        self.p_exe.setChecked(True)
        helped(self.p_exe, "x.p.exe")
        self.p_dll = QCheckBox("Loaded DLLs")
        helped(self.p_dll, "x.p.dll")
        self.p_mem = QCheckBox("Full process memory")
        helped(self.p_mem, "x.p.mem")
        v.addLayout(row(QLabel("Extract:"), self.p_exe, "x.p.exe", self.p_dll, "x.p.dll",
                        self.p_mem, "x.p.mem", None))
        self.p_flag_b = btn("Check flagged", "x.p.checkflagged", "flag")
        self.p_none = btn("Uncheck all", "x.p.uncheck", "x")
        self.p_go = btn("Extract checked processes", "x.p.extract", "download", primary=True)
        v.addLayout(row(self.p_flag_b, self.p_none, None, self.p_go, "x.p.extract"))
        self.p_search.textChanged.connect(self.p_proxy.set_text)
        self.p_flagged.toggled.connect(lambda on: self.p_proxy.set_pred((lambda r: bool(r["flags"])) if on else None))
        self.p_proxy.layoutChanged.connect(self._p_count_upd)
        self.p_model.checks_changed.connect(self._p_count_upd)
        self.p_flag_b.clicked.connect(lambda: self.p_model.set_checked(
            [r["pid"] for r in self.p_model.rows if r["flags"]]))
        self.p_none.clicked.connect(lambda: self.p_model.set_checked(list(self.p_model.checked), False))
        self.p_go.clicked.connect(self._extract_procs)
        return w

    # ------------------------------------------------------------------ VAD
    def _vad_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 6, 4, 4)
        self.v_mode_proc = QRadioButton("Whole process - every memory region")
        self.v_mode_reg = QRadioButton("Selected regions only")
        self.v_mode_proc.setChecked(True)
        helped(self.v_mode_proc, "x.v.modeproc")
        helped(self.v_mode_reg, "x.v.modereg")
        grp = QButtonGroup(self)
        grp.addButton(self.v_mode_proc)
        grp.addButton(self.v_mode_reg)
        v.addLayout(row(QLabel("Mode:"), self.v_mode_proc, "x.v.modeproc", self.v_mode_reg, "x.v.modereg", None))
        self.v_explain = QLabel()
        self.v_explain.setWordWrap(True)
        self.v_explain.setObjectName("Panel")
        self.v_explain.setTextFormat(Qt.RichText)
        self.v_explain.setContentsMargins(8, 6, 8, 6)
        v.addWidget(self.v_explain)
        split = QSplitter(Qt.Horizontal)
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        self.v_psearch = QLineEdit()
        self.v_psearch.setPlaceholderText("Filter processes")
        self.v_psearch.setClearButtonEnabled(True)
        helped(self.v_psearch, "x.v.psearch")
        lv.addLayout(row(self.v_psearch, "x.v.psearch", stretch_at=0))
        self.v_pmodel = CheckModel([("pid", "PID"), ("name", "Name"), ("flags", "Flags")], "pid")
        self.v_pproxy = RowFilter(["pid", "name", "flags"])
        self.v_pview = table(self.v_pmodel, self.v_pproxy, "x.v.procs")
        self.v_pview.setColumnWidth(1, 60)
        self.v_pview.setColumnWidth(2, 150)
        lv.addWidget(self.v_pview, 1)
        split.addWidget(left)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        self.v_rtitle = muted("Select a process on the left to see its memory regions.", wrap=False)
        self.v_list_b = btn("List regions", "x.v.list", "list-tree")
        self.v_list_b.clicked.connect(self._list_regions)
        rv.addLayout(row(self.v_rtitle, None, self.v_list_b, "x.v.list"))
        self.v_rmodel = CheckModel([("start", "Start"), ("end", "End"), ("size", "Size"),
                                    ("protection", "Protection"), ("tag", "Tag / private"),
                                    ("injection", "Injection flag"), ("file", "Mapped file")], "start")
        self.v_rproxy = RowFilter(["start", "protection", "file", "injection", "tag"])
        self.v_rview = table(self.v_rmodel, self.v_rproxy, "x.v.regions")
        for i, wd in ((1, 120), (2, 120), (3, 70), (4, 175), (5, 100), (6, 230)):
            self.v_rview.setColumnWidth(i, wd)
        rv.addWidget(self.v_rview, 1)
        self.v_inj_b = btn("Check injection-flagged", "x.v.checkinj", "shield-ban")
        self.v_rnone = btn("Uncheck regions", "x.v.uncheck", "x")
        rv.addLayout(row(self.v_inj_b, self.v_rnone, None))
        split.addWidget(right)
        split.setSizes([330, 700])
        v.addWidget(split, 1)
        self.v_sel = muted("", wrap=False)
        self.v_go = btn("Extract", "x.v.extract", "download", primary=True)
        v.addLayout(row(self.v_sel, None, self.v_go, "x.v.extract"))
        self.v_mode_proc.toggled.connect(self._v_mode)
        self.v_psearch.textChanged.connect(self.v_pproxy.set_text)
        self.v_pview.selectionModel().currentRowChanged.connect(self._v_pick)
        self.v_pmodel.checks_changed.connect(self._v_sel_upd)
        self.v_rmodel.checks_changed.connect(self._v_rchecks)
        self.v_inj_b.clicked.connect(self._v_check_inj)
        self.v_rnone.clicked.connect(lambda: self.v_rmodel.set_checked(list(self.v_rmodel.checked), False))
        self.v_go.clicked.connect(self._extract_vad)
        self._v_mode()
        return w

    # ----------------------------------------------------------------- hunt
    def _hunt_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 6, 4, 4)
        v.addWidget(muted("Search the memory of every process (or the PIDs you list) for your own strings. "
                          "Hits show the process, address and surrounding bytes."))
        self.h_terms = QPlainTextEdit()
        self.h_terms.setPlaceholderText("One search term per line, e.g.\nevil-domain.com\npassword=\n10.13.37.5")
        self.h_terms.setFixedHeight(96)
        helped(self.h_terms, "x.h.terms")
        v.addLayout(row(self.h_terms, "x.h.terms", stretch_at=0))
        self.h_pids = QLineEdit()
        self.h_pids.setPlaceholderText("Optional: PIDs, comma-separated (empty = all processes)")
        helped(self.h_pids, "x.h.pids")
        self.h_case = QCheckBox("Case-sensitive")
        helped(self.h_case, "x.h.case")
        self.h_wide = QCheckBox("Also UTF-16 (wide)")
        self.h_wide.setChecked(True)
        helped(self.h_wide, "x.h.wide")
        self.h_go = btn("Run string hunt", "x.h.run", "scan-search", primary=True)
        v.addLayout(row(self.h_pids, "x.h.pids", self.h_case, "x.h.case", self.h_wide, "x.h.wide",
                        self.h_go, stretch_at=0))
        self.h_model = CheckModel([("search_term", "Term"), ("pid", "PID"), ("process", "Process"),
                                   ("offset", "Address"), ("decoded", "Match"), ("hex_bytes", "Bytes")], "_k")
        self.h_proxy = RowFilter(["search_term", "pid", "process", "context"])
        self.h_title = muted("No hunt run yet.", wrap=False)
        v.addWidget(self.h_title)
        self.h_view = table(self.h_model, self.h_proxy, "x.h.results")
        self.h_view.setColumnHidden(0, True)
        for i, wd in ((1, 160), (2, 60), (3, 130), (4, 150), (5, 220)):
            self.h_view.setColumnWidth(i, wd)
        v.addWidget(self.h_view, 1)
        self.h_go.clicked.connect(self._run_hunt)
        return w

    # --------------------------------------------------------------- export
    def _export_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 6, 4, 4)
        v.addWidget(muted("Packs the key results of this case (report, IOCs, Sigma, timeline, "
                          "processes, network, logs) into one zip with a manifest - ready to attach to a ticket."))
        self.e_list = QListWidget()
        helped(self.e_list, "x.e.list")
        v.addLayout(row(self.e_list, "x.e.list", stretch_at=0), 1)
        self.e_go = btn("Create export pack", "x.e.run", "package", primary=True)
        v.addLayout(row(None, self.e_go, "x.e.run"))
        self.e_go.clicked.connect(self._run_export)
        return w

    # -------------------------------------------------------------- results
    def _results_panel(self):
        w = QFrame()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 4, 0, 0)
        self.r_title = QLabel("Extraction results")
        self.r_title.setObjectName("H2")
        self.r_open = btn("Open folder", "x.r.open", "folder-open")
        self.r_man = btn("Open manifest", "x.r.manifest", "file-text")
        self.r_hist = ComboBox()
        self.r_hist.setMinimumWidth(260)
        helped(self.r_hist, "x.r.history")
        v.addLayout(row(self.r_title, None, self.r_hist, "x.r.history", self.r_open, self.r_man, "x.r.table"))
        self.r_model = CheckModel([("status", "Status"), ("item", "Item"), ("file", "Extracted file"),
                                   ("size", "Size"), ("type", "Type"), ("nonzero_pct", "Non-zero %"),
                                   ("sha256", "SHA-256"), ("note", "Notes")], "_k")
        self.r_proxy = RowFilter(["status", "item", "file", "type", "note", "sha256"])
        self.r_view = table(self.r_model, self.r_proxy, "x.r.table")
        self.r_view.setColumnHidden(0, True)
        for i, wd in ((1, 64), (2, 260), (3, 300), (4, 80), (5, 170), (6, 76), (7, 150)):
            self.r_view.setColumnWidth(i, wd)
        self.r_view.doubleClicked.connect(self._r_open_item)
        # header + 3 rows always visible: on a ~1000 px screen the 4:1 splitter
        # otherwise squeezed the results down to the bare header
        self.r_view.setMinimumHeight(self.r_view.horizontalHeader().sizeHint().height()
                                     + 3 * self.r_view.verticalHeader().defaultSectionSize() + 6)
        v.addWidget(self.r_view, 1)
        self.r_open.clicked.connect(lambda: self._open_path(self._r_dir()))
        self.r_man.clicked.connect(lambda: self._open_path(self._r_dir() / "manifest.txt"))
        self.r_hist.currentIndexChanged.connect(self._r_pick_hist)
        return w

    def bind_protection(self, settings: dict, saver: Callable[[dict], None]):
        """Show and remember the protected-output choice in the GUI settings
        (shared with the threat-intel dialog)."""
        self.protect.setChecked(bool(settings.get("protect_dumps", True)))
        self.zippw.setText(str(settings.get("zip_password") or "infected"))
        self.zippw.setEnabled(self.protect.isChecked())

        def store(*_):
            settings["protect_dumps"] = self.protect.isChecked()
            settings["zip_password"] = self.zippw.text().strip() or "infected"
            saver(settings)

        self.protect.toggled.connect(store)
        self.zippw.editingFinished.connect(store)

    # ============================================================ case load
    def set_case(self, case: Optional[Path]):
        self.case = Path(case) if case else None
        if not self.case or not self.case.is_dir():
            self.case_lbl.setText("No case loaded - run an analysis or use Load results")
            return
        self.info = ci.read_summary(self.case)
        self.case_lbl.setText(f"{self.case.name}   |   {self.info.get('os', '?')}   |   "
                              f"{self.info.get('engine', '?')}"
                              + (f" {self.info['profile']}" if self.info.get("profile") else ""))
        img = ci.locate_image(self.case)
        self.dump.setText(img or self.info.get("image", ""))
        if not img:
            self.dump.setStyleSheet(f"QLineEdit{{border:1px solid {THEME.get('warn', '#d29922')};}}")
            self.dump.setToolTip("The dump recorded for this case was not found - use Browse to locate it.")
        else:
            self.dump.setStyleSheet("")
        self.dest.setText(str(self.case / "extracted"))
        win = self.info.get("os") == "windows"
        self.p_dll.setEnabled(win)
        self.p_exe.setEnabled(self.info.get("os") != "mac")
        if self.info.get("os") == "mac":
            self.p_exe.setChecked(False)
            self.p_mem.setChecked(True)
        self.p_exe.setText("Executable image" if win else "Executable + libraries (ELF)")
        self.f_rec.setChecked(self.info.get("os") == "linux")
        self.f_rec.setEnabled(self.info.get("os") == "linux")
        for c, k in ((2, "windows"), (3, "linux"), (4, "linux"), (5, "linux")):
            self.f_view.setColumnHidden(c + 1, self.info.get("os") != k)
        self.f_view.setColumnHidden(3, self.info.get("os") == "linux")
        self.vad_checks.clear()
        self.vad_regions.clear()
        self.cur_pid = None
        self.v_rmodel.set_rows([])
        self._reload_lists()
        self._reload_export()
        self._reload_history()

    def _bg(self, fn, cb):
        ld = Loader(fn, self)
        ld.done.connect(cb)
        ld.done.connect(lambda _r, ld=ld: self._loaders.remove(ld) if ld in self._loaders else None)
        self._loaders.append(ld)
        ld.start()

    def _reload_lists(self):
        case = self.case
        self.f_src.setText("Loading file list...")
        self._bg(lambda: ci.file_list(case), self._files_loaded)
        self._bg(lambda: ci.process_list(case), self._procs_loaded)

    def _files_loaded(self, r):
        if isinstance(r, Exception):
            self.f_src.setText(f"Could not read the file list: {r}")
            return
        src, rows = r
        for x in rows:
            x["path_key"] = (x.get("offset") or x.get("inode_addr") or "") + "|" + x.get("path", "")
        self.f_model.set_rows(rows)
        has = bool(rows)
        self.f_view.setVisible(has)
        self.f_empty.setVisible(not has)
        how = {"windows": "windows.filescan", "linux": "linux.pagecache.Files (or Vol2 linux_find_file)",
               "mac": "mac.list_files"}.get(self.info.get("os"), "the file-listing plugin")
        self.f_empty_lbl.setText(f"This case has no file list yet. 'Build file list' runs {how} "
                                 "once (a few minutes) and stores it with the case.")
        self.f_src.setText(f"Source: {src}  -  {len(rows):,} files" if has else "")
        self.f_ext.blockSignals(True)
        self.f_ext.clear()
        self.f_ext.addItem("All types", "")
        for e, n in ci.extensions(rows):
            self.f_ext.addItem(f"{e}  ({n:,})", e)
        self.f_ext.blockSignals(False)
        self._f_filter()

    def _procs_loaded(self, r):
        rows = [] if isinstance(r, Exception) else r
        self.p_model.set_rows(rows)
        self.v_pmodel.set_rows(rows)
        self._p_count_upd()
        self._v_sel_upd()

    # ================================================================ files
    def _f_filter(self):
        self.f_proxy.text = (self.f_search.text() or "").strip().lower()
        ext = self.f_ext.currentData() or ""
        rec = self.f_rec.isChecked() and self.f_rec.isEnabled()

        def pred(r):
            if rec and not r.get("dumpable"):
                return False
            if ext:
                n = r.get("name", "").lower()
                e = ("." + n.rsplit(".", 1)[-1]) if "." in n.strip(".") else "(none)"
                if ext == "(other)":
                    return len(e) > 12
                return e == ext
            return True
        self.f_proxy.set_pred(pred if (ext or rec) else None)
        self._f_count_upd()

    def _f_count_upd(self):
        n = len(self.f_model.checked)
        self.f_count.setText(f"{self.f_proxy.rowCount():,} shown  |  {n:,} checked")
        self.f_go.setText(f"Extract {n} checked file{'s' if n != 1 else ''}" if n else "Extract checked files")
        self._busy(bool(self.job))

    def _check_shown(self, model, proxy):
        ids = proxy.visible_ids()
        if len(ids) > 500 and QMessageBox.question(
                self, "RAMBreaker", f"Check all {len(ids):,} shown rows? Extracting that many items "
                                    "can take a long time.") != QMessageBox.Yes:
            return
        model.set_checked(ids)

    def _extract_files(self):
        rows = self.f_model.checked_rows()
        if not rows:
            QMessageBox.information(self, "RAMBreaker", "Tick the files to extract first "
                                                        "(search, then use the checkbox column).")
            return
        items = [{k: r.get(k) for k in ("name", "path", "offset", "inode", "inode_addr", "size",
                                         "cached_pages")} for r in rows]
        self._start("files", {"items": items}, f"{len(items)} file(s)")

    def _build_filelist(self):
        self._start("filelist", {}, "file list", dest_is_case=True)

    # ============================================================ processes
    def _p_count_upd(self):
        n = len(self.p_model.checked)
        fl = sum(1 for r in self.p_model.rows if r["flags"])
        self.p_count.setText(f"{len(self.p_model.rows)} processes  |  {fl} flagged  |  {n} checked")
        self.p_go.setText(f"Extract {n} checked process{'es' if n != 1 else ''}" if n
                          else "Extract checked processes")
        self._busy(bool(self.job))

    def _extract_procs(self):
        rows = self.p_model.checked_rows()
        what = [k for k, cb in (("exe", self.p_exe), ("dlls", self.p_dll), ("memory", self.p_mem))
                if cb.isChecked() and cb.isEnabled()]
        if not rows or not what:
            QMessageBox.information(self, "RAMBreaker", "Tick at least one process and at least one "
                                                        "thing to extract (executable, DLLs or memory).")
            return
        if "memory" in what and len(rows) > 5 and QMessageBox.question(
                self, "RAMBreaker", f"Full memory of {len(rows)} processes can be several GB. Continue?") \
                != QMessageBox.Yes:
            return
        self._start("procs", {"items": [{"pid": r["pid"], "name": r["name"]} for r in rows], "what": what},
                    f"{len(rows)} process(es): {', '.join(what)}")

    # ================================================================== VAD
    EX_PROC = ("<b>Whole process</b> dumps <i>every</i> memory region (VAD) of each <b>ticked process</b> "
               "into its own folder: heaps, stacks, mapped DLLs, everything. Complete, but large."
               "<br><span style='color:{m}'>Example: tick <b>notepad.exe</b> -> about 120 files / ~60 MB "
               "in pid_2140_notepad.exe\\. Use it when you want to carve or YARA-scan the process "
               "offline.</span>")
    EX_REG = ("<b>Selected regions only</b> dumps just the regions you <b>tick in the right-hand table</b> "
              "(they can come from several processes). Small and fast."
              "<br><span style='color:{m}'>Example: malfind flagged notepad.exe -> select notepad, press "
              "<b>Check injection-flagged</b> -> one 4 KB file for the PAGE_EXECUTE_READWRITE region at "
              "0x2a0000 - exactly the injected shellcode.</span>")

    def _v_mode(self, *_):
        per_region = self.v_mode_reg.isChecked()
        self.v_explain.setText((self.EX_REG if per_region else self.EX_PROC).format(m=THEME.get("muted", "#999")))
        self.v_rview.setColumnHidden(0, not per_region)
        self.v_pview.setColumnHidden(0, per_region)
        self.v_inj_b.setEnabled(per_region)
        self.v_rnone.setEnabled(per_region)
        self._v_sel_upd()

    def _v_pick(self, cur, _prev):
        if not cur.isValid():
            return
        r = self.v_pmodel.rows[self.v_pproxy.mapToSource(cur).row()]
        self.cur_pid = r["pid"]
        self._v_show_regions(r)

    def _v_show_regions(self, prow):
        pid = prow["pid"]
        case = self.case
        self.v_rtitle.setText(f"PID {pid} {prow['name']}: loading regions...")

        def got(res, pid=pid, prow=prow):
            if pid != self.cur_pid:
                return
            known, rows = res if not isinstance(res, Exception) else (False, [])
            self.vad_regions[pid] = rows
            self.v_rmodel.blockSignals(True)
            self.v_rmodel.set_rows(rows)
            self.v_rmodel.checked = set(self.vad_checks.get(pid, set()))
            self.v_rmodel.blockSignals(False)
            self.v_rmodel.layoutChanged.emit()
            inj = sum(1 for r in rows if r["injection"])
            if known:
                self.v_rtitle.setText(f"PID {pid} {prow['name']}: {len(rows)} regions"
                                      + (f", {inj} injection-flagged" if inj else ""))
            else:
                self.v_rtitle.setText(f"PID {pid} {prow['name']}: no region list in this case yet - "
                                      "press 'List regions'")
            self.v_list_b.setVisible(not known)
            self._v_sel_upd()
        self._bg(lambda: ci.region_list(case, pid), got)

    def _v_check_inj(self):
        self.v_rmodel.set_checked([r["start"] for r in self.v_rmodel.rows if r["injection"]])
        self.v_rview.sortByColumn(0, Qt.AscendingOrder)     # ticked rows first
        self.v_rview.scrollToTop()

    def _v_rchecks(self):
        if self.cur_pid is not None:
            self.vad_checks[self.cur_pid] = set(self.v_rmodel.checked)
            if not self.vad_checks[self.cur_pid]:
                self.vad_checks.pop(self.cur_pid)
        self._v_sel_upd()

    def _v_sel_upd(self):
        if self.v_mode_reg.isChecked():
            n = sum(len(s) for s in self.vad_checks.values())
            self.v_sel.setText(f"{n} region(s) ticked in {len(self.vad_checks)} process(es)")
            self.v_go.setText(f"Extract {n} selected region{'s' if n != 1 else ''}" if n else "Extract selected regions")
        else:
            n = len(self.v_pmodel.checked)
            self.v_sel.setText(f"{n} process(es) ticked - every region of each will be dumped")
            self.v_go.setText(f"Extract all regions of {n} process{'es' if n != 1 else ''}" if n
                              else "Extract all regions of ticked processes")
        self._busy(bool(self.job))

    def _list_regions(self):
        if self.cur_pid:
            self._start("regions", {"items": [{"pid": self.cur_pid}]}, f"region list of PID {self.cur_pid}",
                        dest_is_case=True)

    def _extract_vad(self):
        names = {r["pid"]: r["name"] for r in self.v_pmodel.rows}
        if self.v_mode_reg.isChecked():
            items = []
            for pid, starts in self.vad_checks.items():
                regs = [r for r in self.vad_regions.get(pid, []) if r["start"] in starts]
                if regs:
                    items.append({"pid": pid, "name": names.get(pid, ""), "regions": regs})
            if not items:
                QMessageBox.information(self, "RAMBreaker", "Select a process, then tick the regions to dump "
                                                            "in the right-hand table.")
                return
            self._start("vad", {"items": items, "mode": "region"},
                        f"{sum(len(i['regions']) for i in items)} region(s)")
        else:
            rows = self.v_pmodel.checked_rows()
            if not rows:
                QMessageBox.information(self, "RAMBreaker", "Tick the processes whose regions you want "
                                                            "(checkbox column on the left).")
                return
            self._start("vad", {"items": [{"pid": r["pid"], "name": r["name"]} for r in rows],
                                "mode": "process"}, f"all regions of {len(rows)} process(es)")

    # ================================================================= hunt
    def _run_hunt(self):
        terms = [t.strip() for t in self.h_terms.toPlainText().splitlines() if t.strip()]
        if not terms:
            QMessageBox.information(self, "RAMBreaker", "Enter at least one search term (one per line).")
            return
        pids = [p.strip() for p in self.h_pids.text().replace(";", ",").split(",") if p.strip()]
        bad = [p for p in pids if not p.isdigit()]
        if bad:
            QMessageBox.warning(self, "RAMBreaker", f"Not a PID: {', '.join(bad)}")
            return
        self._start("hunt", {"terms": terms, "pids": pids, "case_sensitive": self.h_case.isChecked(),
                             "wide": self.h_wide.isChecked()}, f"{len(terms)} term(s)")

    def _show_hunt(self, dest: Path):
        d = ci.load_json(dest / "json" / "string_hunt.json") or {}
        hits = d.get("hits") or []
        for i, h in enumerate(hits):
            h["_k"] = str(i)
        self.h_model.set_rows(hits)
        self.h_title.setText(f"{len(hits)} hit(s) in process memory"
                             + "".join(f"  |  '{t}': {n} line(s) in the whole-dump strings"
                                       for t, n in (d.get("strings_hits") or {}).items()))

    # =============================================================== export
    def _reload_export(self):
        self.e_list.clear()
        if not self.case:
            return
        try:
            from modules.export_pack import ExportPack
            import logging
            for f in ExportPack(logging.getLogger("x")).list_available(self.case):
                self.e_list.addItem(str(f))
        except Exception as e:
            self.e_list.addItem(f"(could not list: {e})")

    def _run_export(self):
        self._start("export", {}, "export pack")

    # ============================================================== running
    def _dest_for(self, kind) -> Path:
        base = Path(self.dest.text().strip() or (self.case / "extracted"))
        return base / f"{kind}_{time.strftime('%Y%m%d_%H%M%S')}"

    def _start(self, kind, extra: Dict[str, Any], label: str, dest_is_case=False):
        if self.job or self.runner.running():
            return
        if not self.case:
            QMessageBox.warning(self, "RAMBreaker", "Load a case first (run an analysis or Load results).")
            return
        if self.analysis_running:
            QMessageBox.warning(self, "RAMBreaker", "An analysis is running. Wait for it to finish - "
                                                    "running both at once would compete for the disk and RAM.")
            return
        img = self.dump.text().strip().strip('"')
        if not img or not Path(img).is_file():
            QMessageBox.warning(self, "RAMBreaker", "The memory dump for this case was not found. "
                                                    "Use Browse next to 'Memory dump' to locate it.")
            return
        dest = self.case if dest_is_case else self._dest_for(kind)
        spec = {"kind": kind, "case": str(self.case), "image": img, "dest": str(dest),
                "protect": self.protect.isChecked(), "zip_password": self.zippw.text().strip() or "infected"}
        spec.update(extra)
        jd = self.case / "extracted" / "_jobs"
        jd.mkdir(parents=True, exist_ok=True)
        sp = jd / f"{kind}_{time.strftime('%Y%m%d_%H%M%S')}.json"
        sp.write_text(json.dumps(spec, indent=1, default=str), encoding="utf-8")
        self.job = {"kind": kind, "dest": dest, "label": label, "t0": time.time(), "n": 1, "done": 0,
                    "spec": sp}
        self.bar.setValue(0)
        self.job_lbl.setText(f"Extracting {label}...")
        self.log_sink("event", f"Extraction started: {kind} - {label} -> {dest}")
        self.spin.start()
        self._tick.start()
        self._busy(True)
        args = ["xjob", "--spec", str(sp)]
        from gui.main_window import SRC
        self.runner.start(args, cwd=str(SRC))

    def _stop(self):
        if self.runner.running() and QMessageBox.question(
                self, "RAMBreaker", "Stop this extraction? Files written so far are kept.") == QMessageBox.Yes:
            self.log_sink("warn", "Extraction stop requested by the user")
            self.runner.stop()

    def _on_log(self, level, text):
        if text.lstrip().startswith("[+] Command:"):
            level = "debug" if False else "info"
        self.log_sink(level, text)

    def _on_event(self, ev):
        k = ev.get("ev")
        if k == "xjob" and ev.get("state") == "start":
            self.job["n"] = max(1, int(ev.get("total") or 1))
        elif k == "xitem":
            n = max(1, int(ev.get("n") or self.job.get("n", 1)))
            st = ev.get("state")
            if st == "running":
                self.job_lbl.setText(f"[{ev.get('i')}/{n}] {ev.get('label', '')[:90]}")
            else:
                self.job["done"] = self.job.get("done", 0) + 1
                self.bar.setValue(int(1000 * self.job["done"] / n))
        elif k == "xjob" and ev.get("state") == "done":
            self.job["result"] = ev
        elif k == "plugin":
            pass

    def _heartbeat(self):
        if self.job:
            s = int(time.time() - self.job["t0"])
            idle = int(time.time() - self.runner.last_activity)
            self.elapsed.setText(f"{s // 60}:{s % 60:02d}" + (f"  (Volatility working, {idle}s since last output)"
                                                            if idle > 20 else ""))
            if self.job.get("done", 0) == 0:          # keep the bar moving before the first item ends
                self.bar.setValue(min(900, self.bar.value() + 2))

    def _on_done(self, code, stopped):
        job, self.job = self.job, {}
        self.spin.stop()
        self._tick.stop()
        res = job.get("result") or {}
        kind = job.get("kind", "")
        if stopped:
            self.job_lbl.setText("Stopped by user - partial results kept")
        elif res:
            self.bar.setValue(1000)
            self.job_lbl.setText(f"Done: {res.get('ok', 0)} ok, {res.get('empty', 0)} empty, "
                                 f"{res.get('failed', 0)} failed  ({res.get('duration_s', 0):.0f}s)")
        else:
            self.job_lbl.setText(f"Extraction failed (exit {code}) - see the live log")
        self.log_sink("ok" if code == 0 and not stopped else "warn",
                      f"Extraction {kind} finished: {self.job_lbl.text()}")
        self._busy(False)
        if kind in ("filelist", "regions"):
            if kind == "filelist":
                self._reload_lists()
            elif self.cur_pid:
                prow = next((r for r in self.v_pmodel.rows if r["pid"] == self.cur_pid), None)
                if prow:
                    self._v_show_regions(prow)
            return
        man = res.get("manifest") or ""
        dest = Path(job.get("dest", ""))
        if kind == "hunt":
            self._show_hunt(dest)
        self._reload_history(select=str(dest))
        try:
            self._reveal_results()
        finally:                                  # listeners (e2e chain) must always hear the end
            self.job_finished.emit(man)

    def _reveal_results(self):
        """After a job, make sure its result rows are on screen: grow the results
        pane just enough to show them (at most 6). The pane always shows 3, so a
        small job leaves the lists above untouched."""
        sizes = self.split.sizes()
        if len(sizes) == 2 and sum(sizes) > 0:
            n = min(6, self.r_model.rowCount())
            missing = n * self.r_view.verticalHeader().defaultSectionSize() - self.r_view.viewport().height()
            if missing > 0:
                grow = min(missing, max(0, sizes[0] - self.tabs.minimumSizeHint().height()))
                if grow > 0:
                    self.split.setSizes([sizes[0] - grow, sizes[1] + grow])

    def _busy(self, on):
        if not hasattr(self, "stop_b"):          # still building the pages
            return
        idle = not on
        for b in (self.f_go, self.p_go, self.v_go, self.h_go, self.e_go, self.f_build, self.v_list_b):
            b.setEnabled(idle and self.case is not None)
        self.stop_b.setEnabled(on)
        if idle:
            self.f_go.setEnabled(self.case is not None and bool(self.f_model.checked))
            self.p_go.setEnabled(self.case is not None and bool(self.p_model.checked))

    def set_analysis_running(self, on: bool):
        self.analysis_running = on

    def retheme(self):
        for b in self.findChildren(QPushButton):
            n = b.property("icon_name")
            if n:
                b.setIcon(icons.icon(n, "#ffffff" if b.property("primary") else THEME.get("text", "#ddd"), 14))
        for i, n in enumerate(("file-down", "process", "layers", "scan-search", "package")):
            self.tabs.setTabIcon(i, icons.icon(n, THEME.get("muted", "#999"), 14))
        self._v_mode()

    # ============================================================== results
    def _manifests(self) -> List[Path]:
        if not self.case:
            return []
        bases = {self.case / "extracted"}
        d = self.dest.text().strip()
        if d:
            bases.add(Path(d))
        out = []
        for b in bases:
            if b.is_dir():
                out += [p for p in b.glob("*/manifest.json")]
        return sorted(set(out), key=lambda p: p.stat().st_mtime, reverse=True)

    def _reload_history(self, select: str = ""):
        self.r_hist.blockSignals(True)
        self.r_hist.clear()
        for p in self._manifests():
            self.r_hist.addItem(p.parent.name, str(p.parent))
        self.r_hist.blockSignals(False)
        idx = self.r_hist.findData(select) if select else 0
        if self.r_hist.count():
            self.r_hist.setCurrentIndex(max(0, idx))
            self._r_pick_hist()
        else:
            self.r_model.set_rows([])
            self.r_title.setText("Extraction results  -  nothing extracted yet")

    def _r_dir(self) -> Path:
        d = self.r_hist.currentData()
        return Path(d) if d else Path(self.dest.text().strip() or ".")

    def _r_pick_hist(self, *_):
        d = self._r_dir()
        man = ci.load_json(d / "manifest.json") or {}
        rows = []
        for it in man.get("items", []):
            if not it.get("outputs"):
                rows.append({"_k": str(len(rows)), "status": it.get("status", "").upper(), "item": it.get("label"),
                             "file": "", "note": it.get("detail", "")})
            for o in it.get("outputs", []):
                rows.append({"_k": str(len(rows)), "status": it.get("status", "").upper(), "item": it.get("label"),
                             "file": o.get("file"), "size": o.get("size", 0), "type": o.get("type", ""),
                             "nonzero_pct": o.get("nonzero_pct", ""), "sha256": o.get("sha256", ""),
                             "note": "; ".join(x for x in (o.get("injection", ""), o.get("object", ""),
                                                           o.get("note", ""), it.get("detail", "")) if x)})
        self.r_model.set_rows(rows)
        prot = man.get("protection") or {}
        self.r_title.setText(f"Extraction results  -  {man.get('kind', '?')}: {man.get('ok', 0)} ok, "
                             f"{man.get('empty', 0)} empty, {man.get('failed', 0)} failed"
                             + (f"  -  in password-protected ZIPs (password: {prot.get('password', 'infected')})"
                                if prot else ""))

    def _r_open_item(self, idx):
        r = self.r_model.rows[self.r_proxy.mapToSource(idx).row()]
        if r.get("file"):
            p = self._r_dir() / r["file"]
            self._open_path(p.parent if p.exists() else self._r_dir())

    # ================================================================ misc
    def _pick_dump(self):
        f, _ = QFileDialog.getOpenFileName(self, "Locate the memory dump of this case",
                                           str(Path(self.dump.text()).parent) if self.dump.text() else "",
                                           "Memory dumps (*.raw *.mem *.vmem *.lime *.dmp *.bin *.img);;All files (*)")
        if f:
            self.dump.setText(f)
            self.dump.setStyleSheet("")

    def _pick_dest(self):
        d = QFileDialog.getExistingDirectory(self, "Save extracted data to", self.dest.text())
        if d:
            self.dest.setText(d)
            self._reload_history()

    @staticmethod
    def _open_path(p: Path):
        from modules import platform_compat
        if p and p.exists():
            platform_compat.open_path(p)
