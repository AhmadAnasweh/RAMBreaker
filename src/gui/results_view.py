"""Results viewer: case navigator tree + tabbed, sortable/filterable tables."""

import csv
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from PySide6.QtWidgets import (QAbstractItemView, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QPushButton, QSplitter,
                               QTabWidget, QTableView, QTextBrowser, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from gui import icons
from gui.widgets import FastSortProxy, HelpButton, StatTile, THEME, helped


def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _n(v) -> int:
    """run_health stores counts as ints in some versions, lists in others."""
    if isinstance(v, (list, tuple, dict, set)):
        return len(v)
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def flatten(obj) -> List[Dict[str, Any]]:
    out = []

    def walk(rows, depth=0):
        for r in rows or []:
            if isinstance(r, dict):
                kids = r.get("__children")
                out.append({k: v for k, v in r.items() if k != "__children"})
                if kids:
                    walk(kids, depth + 1)
            else:
                out.append({"value": r})
    if isinstance(obj, list):
        walk(obj)
    elif isinstance(obj, dict):
        for k in ("rows", "records", "results", "data", "events", "findings", "values", "hits"):
            if isinstance(obj.get(k), list):
                walk(obj[k])
                break
        else:
            out = [{"key": k, "value": v} for k, v in obj.items()]
    return out


class RowsModel(QAbstractTableModel):
    def __init__(self, rows: List[Dict[str, Any]], cols: Optional[List[str]] = None):
        super().__init__()
        self.rows = rows
        if cols is None:
            freq: Dict[str, int] = {}
            for r in rows[:500]:
                for k in r:
                    freq[k] = freq.get(k, 0) + 1
            cols = [k for k, _ in sorted(freq.items(), key=lambda x: -x[1])][:40]
        self.cols = cols

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.cols)

    def data(self, idx, role=Qt.DisplayRole):
        if not idx.isValid():
            return None
        v = self.rows[idx.row()].get(self.cols[idx.column()])
        if role == Qt.DisplayRole:
            if isinstance(v, (list, dict)):
                v = json.dumps(v, default=str)
            s = "" if v is None else str(v)
            return s if len(s) < 600 else s[:600] + " ..."
        if role == Qt.UserRole:            # sort key
            return v if isinstance(v, (int, float)) else ("" if v is None else str(v).lower())
        if role == Qt.ToolTipRole and v is not None:
            s = str(v)
            return s[:2000] if len(s) > 60 else None
        return None

    def headerData(self, s, o, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            return self.cols[s] if o == Qt.Horizontal else str(s + 1)
        return None

    def sort_key(self, r, column):
        return r.get(self.cols[column])

    def row_text(self, i) -> str:
        """Lower-case text of every shown column (what the filter matches), cached."""
        r = self.rows[i]
        cache = self.__dict__.setdefault("_txt", {})
        t = cache.get(id(r))
        if t is None:
            parts = []
            for c in self.cols:
                v = r.get(c)
                if v is None:
                    continue
                parts.append(json.dumps(v, default=str) if isinstance(v, (list, dict)) else str(v))
            t = cache[id(r)] = "\x1f".join(parts).lower()
        return t


class TextFilterProxy(FastSortProxy):
    """Fixed-string, case-insensitive filter over any column, on cached row text
    (setFilterFixedString called data() for every cell on every keystroke)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.needle = ""

    def set_needle(self, s):
        self.needle = (s or "").lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        return not self.needle or self.needle in self.sourceModel().row_text(row)


class TablePage(QWidget):
    def __init__(self, title: str, rows: List[Dict[str, Any]], cols=None, note: str = ""):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        top = QHBoxLayout()
        h = QLabel(f"{title}   <span style='color:{THEME.get('muted')}'>{len(rows)} rows</span>")
        h.setObjectName("H2")
        top.addWidget(h)
        top.addStretch(1)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter rows (any column)...")
        self.filter.setClearButtonEnabled(True)
        self.filter.setFixedWidth(300)
        helped(self.filter, "res.filter")
        top.addWidget(self.filter)
        top.addWidget(HelpButton("res.filter"))
        self.export = QPushButton("Export CSV")
        self.export.setIcon(icons.icon("download", THEME.get("text"), 14))
        helped(self.export, "res.export")
        top.addWidget(self.export)
        top.addWidget(HelpButton("res.export"))
        lay.addLayout(top)
        if note:
            n = QLabel(note)
            n.setObjectName("Muted")
            n.setWordWrap(True)
            lay.addWidget(n)
        self.model = RowsModel(rows, cols)
        self.proxy = TextFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.view = QTableView()
        self.view.setModel(self.proxy)
        # open in the plugin's own row order: no sort until a header is clicked
        self.view.horizontalHeader().setSortIndicator(-1, Qt.AscendingOrder)
        self.view.setSortingEnabled(True)
        self.view.setAlternatingRowColors(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.view.verticalHeader().setDefaultSectionSize(22)
        self.view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.setWordWrap(False)
        helped(self.view, "res.table")
        lay.addWidget(self.view, 1)
        for i, c in enumerate(self.model.cols):
            self.view.setColumnWidth(i, max(70, min(360, 9 * max(len(c), 8))))
        self._ftimer = QTimer(self, singleShot=True, interval=200)     # debounce typing
        self._ftimer.timeout.connect(lambda: self.proxy.set_needle(self.filter.text()))
        self.filter.textChanged.connect(lambda _t: self._ftimer.start())
        self.export.clicked.connect(self._export)

    def _export(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Export CSV", "table.csv", "CSV (*.csv)")
        if not fn:
            return
        with open(fn, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(self.model.cols)
            for r in range(self.proxy.rowCount()):
                w.writerow([self.proxy.index(r, c).data() for c in range(len(self.model.cols))])


class ResultsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.od: Optional[Path] = None
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(Qt.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        hdr = QHBoxLayout()
        t = QLabel("CASE NAVIGATOR")
        t.setObjectName("Muted")
        hdr.addWidget(t)
        hdr.addStretch(1)
        hdr.addWidget(HelpButton("res.nav"))
        ll.addLayout(hdr)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(14)
        left.setMinimumWidth(210)
        helped(self.tree, "res.nav")
        ll.addWidget(self.tree, 1)
        split.addWidget(left)
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setDocumentMode(False)
        helped(self.tabs, "res.tabs")
        self.tabs.tabCloseRequested.connect(self.tabs.removeTab)
        split.addWidget(self.tabs)
        split.setSizes([260, 900])
        split.setStretchFactor(1, 1)
        lay.addWidget(split)
        self.tree.itemClicked.connect(self._open_item)
        self._loaders: Dict[int, Callable] = {}
        self.extract_opener: Optional[Callable] = None     # set by the main window
        self._show_empty()

    def open_widget(self, w: QWidget, title: str):
        """Show a persistent page (the Extraction workspace) as a tab."""
        i = self.tabs.indexOf(w)
        if i < 0:
            i = self.tabs.addTab(w, icons.icon("file-down", THEME.get("muted", "#999"), 14), title)
        self.tabs.setCurrentIndex(i)

    def _show_empty(self):
        self.tree.clear()
        self.tabs.clear()
        w = QLabel("No results loaded yet.\n\nRun an analysis or use 'Load results' in the toolbar.")
        w.setAlignment(Qt.AlignCenter)
        w.setObjectName("Muted")
        self.tabs.addTab(w, "Results")
        from PySide6.QtWidgets import QTabBar
        self.tabs.tabBar().setTabButton(0, QTabBar.RightSide, None)

    # ---------------------------------------------------------------- loading
    def load(self, od: Path):
        od = Path(od)
        if not od.is_dir():
            return
        self.od = od
        self.tree.clear()
        self.tabs.clear()
        self._loaders.clear()
        c = THEME
        mk = lambda parent, text, ic, loader=None: self._node(parent, text, ic, loader)
        root = mk(self.tree, f"Case: {od.name}", "case")
        mk(root, "Summary", "gauge", lambda: self._summary_page())
        jd = od / "json"
        plugs = sorted(jd.glob("*.json")) if jd.is_dir() else []
        pick = lambda *keys: next((p for p in plugs if any(k in p.stem.lower() for k in keys)), None)
        proc = pick("pstree", "pslist", "psaux")
        if proc:
            mk(root, "Processes", "process", lambda p=proc: self._table("Processes", flatten(_load(p))))
        net = pick("netscan", "netstat", "sockstat")
        if net:
            mk(root, "Network", "network", lambda p=net: self._table("Network", flatten(_load(p))))
        fnd = mk(root, "Findings", "finding")
        sig = od / "sigma" / "sigma_results.json"
        if sig.is_file():
            mk(fnd, "Sigma rule hits", "sigma", self._sigma_page)
        inj = jd / "injection_correlation.json"
        if inj.is_file():
            mk(fnd, "Fileless injection", "shield-ban",
               lambda: self._table("Fileless injection", flatten(_load(inj))))
        corr = jd / "correlation_report.json"
        if corr.is_file():
            mk(fnd, "Correlation", "workflow", lambda: self._json_page("Correlation", corr))
        tl = jd / "timeline.json"
        if tl.is_file():
            mk(fnd, "Timeline", "timeline", lambda: self._table("Timeline", flatten(_load(tl))))
        iocn = mk(root, "IOCs", "ioc")
        ir = _load(od / "iocs" / "ioc_results.json") or {}
        for name, v in sorted((ir.get("results") or {}).items()):
            if name in ("base64_long", "hex_blob"):
                continue
            mk(iocn, f"{name} ({v.get('count', 0)})", "hash",
               lambda n=name, v=v: self._table(f"IOC: {n}", [{"value": x} for x in v.get("values", [])],
                                               note=v.get("description", "")))
        em = od / "iocs" / "json" / "email_artifacts.json"
        if em.is_file():
            mk(root, "E-mail artefacts", "email", lambda: self._email_page(em))
        ic = od / "ioc_check" / "ioc_check.json"
        if ic.is_file():
            mk(root, "IOC check", "crosshair", lambda: self._ioccheck_page(ic))
        bh = od / "iocs" / "json" / "browser_history.json"
        if bh.is_file():
            mk(root, "Browser history", "globe", lambda: self._json_page("Browser history", bh))
        if self.extract_opener is not None:
            xn = mk(root, "Extraction (files, processes, memory)", "file-down")
            self._loaders[id(xn)] = (lambda: self.extract_opener(), "Extraction")
            mans = sorted((od / "extracted").glob("*/manifest.json"),
                          key=lambda p: p.stat().st_mtime, reverse=True) if (od / "extracted").is_dir() else []
            for m in mans[:50]:
                mk(xn, m.parent.name, "table", lambda m=m: self._manifest_page(m))
        pl = mk(root, f"Plugins ({len(plugs)})", "plugin")
        for p in plugs:
            if p.stem.startswith("_"):
                continue
            mk(pl, p.stem, "table", lambda p=p: self._table(p.stem, flatten(_load(p))))
        root.setExpanded(True)
        fnd.setExpanded(True)
        self._open(self._summary_page, "Summary")

    def _node(self, parent, text, ic, loader):
        it = QTreeWidgetItem(parent, [text])
        it.setIcon(0, icons.icon(ic, THEME.get("muted", "#999"), 14))
        if loader:
            self._loaders[id(it)] = (loader, text)
        return it

    def _open_item(self, it, _col):
        e = self._loaders.get(id(it))
        if e:
            self._open(*e)

    def _open(self, loader, title):
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == title:
                self.tabs.setCurrentIndex(i)
                return
        try:
            w = loader()
        except Exception as ex:
            w = QLabel(f"Could not load {title}: {ex}")
        if self.tabs.indexOf(w) < 0:
            self.tabs.addTab(w, title)
        self.tabs.setCurrentWidget(w)

    # ------------------------------------------------------------------ pages
    def _table(self, title, rows, cols=None, note=""):
        return TablePage(title, rows, cols, note)

    def _manifest_page(self, m: Path):
        man = _load(m) or {}
        rows = []
        for it in man.get("items", []):
            for o in it.get("outputs") or [{}]:
                rows.append({"status": it.get("status", "").upper(), "item": it.get("label"),
                             "file": o.get("file", ""), "size": o.get("size", ""), "type": o.get("type", ""),
                             "nonzero %": o.get("nonzero_pct", ""), "sha256": o.get("sha256", ""),
                             "md5": o.get("md5", ""), "notes": "; ".join(
                                 x for x in (o.get("injection", ""), o.get("object", ""), o.get("note", ""),
                                             it.get("detail", "")) if x)})
        return TablePage(f"Extraction {m.parent.name}", rows,
                         note=f"{man.get('kind', '?')} - {man.get('ok', 0)} ok, {man.get('empty', 0)} empty, "
                              f"{man.get('failed', 0)} failed - folder: {m.parent}")

    def _json_page(self, title, p):
        data = _load(p)
        rows = flatten(data)
        return TablePage(title, rows)

    def _sigma_page(self):
        d = _load(self.od / "sigma" / "sigma_results.json") or {}
        rows = []
        for h in d.get("hits", []):
            for m in h.get("matches", []):
                rows.append({"level": h.get("level"), "confidence": h.get("confidence", ""),
                             "rule": h.get("title"), "pid": m.get("_pid"),
                             "image": m.get("Image") or m.get("TargetObject"),
                             "command_line": m.get("CommandLine") or m.get("Details") or m.get("DestinationIp"),
                             "parent": m.get("ParentImage"), "source": m.get("_source"),
                             "tags": " ".join(h.get("tags", [])), "rule_file": h.get("file")})
        note = (f"{d.get('rules_fired', 0)} rule(s) fired - {d.get('rules_loaded', 0)} loaded, "
                f"{d.get('rules_applicable', 0)} applicable to the {d.get('events', 0)} events rebuilt "
                f"from memory. Memory is a snapshot: treat hits as leads and verify them.")
        return TablePage("Sigma rule hits", rows, note=note)

    def _email_page(self, p):
        d = _load(p) or {}
        s = d.get("summary", {})
        note = (f"{s.get('messages', 0)} message(s) {s.get('by_confidence', {})}, "
                f"{s.get('mailto', 0)} mailto link(s), {s.get('protocol_traces', 0)} SMTP/IMAP/POP traces, "
                f"{s.get('outlook_artifacts', 0)} Outlook/mail-store artefacts. Memory fragments are "
                "often partial - confidence says how complete each item is.")
        rows = list(d.get("records", []))
        rows += [{"confidence": "trace", "kind": x["type"], "subject": x["value"], "seen": x["seen"]}
                 for x in d.get("protocol", []) + d.get("outlook", [])]
        return TablePage("E-mail artefacts", rows,
                         ["confidence", "kind", "date", "from", "to", "cc", "subject",
                          "attachments", "body_preview", "seen", "message_id"], note)

    def _ioccheck_page(self, p):
        d = _load(p) or {}
        s = d.get("summary", {})
        rows = []
        for r in d.get("results", []):
            rows.append({"found": "YES" if r.get("found") else "no", "ioc": r.get("value"),
                         "type": r.get("type"), "raw_ascii": r.get("raw_hits_ascii"),
                         "raw_utf16": r.get("raw_hits_utf16le"),
                         "first_offsets": " ".join((r.get("raw_offsets_ascii", []) +
                                                    r.get("raw_offsets_utf16le", []))[:4]),
                         "plugins": " ".join(sorted({l.get("plugin") or l.get("source", "")
                                                     for l in r.get("locations", [])})),
                         "processes": " ".join(r.get("processes", [])[:8]),
                         "comment": r.get("comment", "")})
        note = (f"{s.get('found', 0)} of {s.get('iocs', 0)} IOCs found in {s.get('duration_s', '?')} s. "
                "Offsets are physical offsets in the dump file.")
        if s.get("attribution") and s["attribution"] != "done":
            note += f" Process attribution: {s['attribution']}."
        return TablePage("IOC check", rows, note=note)

    def _summary_page(self):
        od = self.od
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        title = QLabel(f"Case summary - {od.name}")
        title.setObjectName("H1")
        lay.addWidget(title)
        grid = QGridLayout()
        jd = od / "json"
        cnt = lambda pat: sum(len(flatten(_load(p))) for p in list(jd.glob(pat))[:1])
        sig = _load(od / "sigma" / "sigma_results.json") or {}
        ir = _load(od / "iocs" / "ioc_results.json") or {}
        em = (_load(od / "iocs" / "json" / "email_artifacts.json") or {}).get("summary", {})
        ic = (_load(od / "ioc_check" / "ioc_check.json") or {}).get("summary", {})
        rh = _load(od / "run_health.json") or {}
        to = _load(jd / "_timeouts.json") or []
        tiles = [("Processes", cnt("*pstree*.json") or cnt("*pslist*.json") or cnt("*psaux*.json")),
                 ("Network rows", cnt("*netscan*.json") or cnt("*sockstat*.json")),
                 ("IOC values", sum((v or {}).get("count", 0) for k, v in (ir.get("results") or {}).items()
                                    if k not in ("base64_long", "hex_blob"))),
                 ("E-mail items", em.get("messages", 0)),
                 ("Sigma rules fired", sig.get("rules_fired", 0)),
                 ("IOC check hits", f"{ic.get('found', 0)}/{ic.get('iocs', 0)}" if ic else "-"),
                 ("Plugins OK", _n(rh.get("plugins_ok"))),
                 ("Failed / timed out", f"{_n(rh.get('plugins_failed'))} / {len(to)}")]
        for i, (k, v) in enumerate(tiles):
            grid.addWidget(StatTile(k, v), i // 4, i % 4)
        lay.addLayout(grid)
        info = QTextBrowser()
        helped(info, "res.summarytext")
        txt = ""
        sp = od / "SUMMARY.txt"
        if sp.is_file():
            txt = sp.read_text(encoding="utf-8", errors="replace")[:20000]
        st = rh.get("status", "?")
        ban = rh.get("banner", "")
        if isinstance(ban, (list, tuple)):
            ban = "\n".join(str(x) for x in ban if str(x).strip())
        info.setPlainText(f"Run health: {st}\nOS: {rh.get('os_type', '?')}   mode: {rh.get('mode', '?')}\n"
                          f"{ban}\n\n{txt}")
        lay.addWidget(info, 1)
        return w
