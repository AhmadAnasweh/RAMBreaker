"""GUI for the "DFIR + Threat Intel" mode (RAMBreaker v2.2).

ThreatIntelDialog   asked before a threat-intel run: VirusTotal key (stored encrypted
                    for this Windows user only if the user ticks it), pace, YARA rule set,
                    custom-rule folder, and the threat-intel databases with their age.
DatabasesWidget     the database table + an Update button (the user's choice, never
                    automatic); also opened from Settings.

The results themselves are NOT shown here: they go to report.html (tab "Threat
Intelligence") and <case>/threat_intelligence/.
"""

from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog, QDoubleSpinBox,
                               QFileDialog, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from gui.widgets import helped, with_help
from modules import platform_compat, secret_store
from modules import ti_sources as ts


class _UpdateThread(QThread):
    step = Signal(str)
    done = Signal(list)

    def __init__(self, ids: List[str], keys: Dict[str, str]):
        super().__init__()
        self.ids, self.keys = ids, keys

    def run(self):
        try:
            res = ts.update(self.ids, self.keys, progress=self.step.emit)
        except Exception as e:                       # never crash the GUI on a network error
            res = [{"id": "-", "name": "update", "ok": False, "detail": str(e)}]
        self.done.emit(res)


class DatabasesWidget(QWidget):
    """Which threat-intel databases exist, how old they are, and an optional update."""
    updated = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        intro = QLabel(
            "RAMBreaker checks every dumped file, hash, IP and domain against these databases <b>on this PC</b>. "
            "Threat intelligence goes out of date quickly: new malware and new attacker servers appear every day, "
            "so an old database misses recent threats. Updating downloads the newest lists from their publishers "
            "(nothing about your case is sent). It is your choice: without an update the copies below are used, "
            "and the report says how old they are.")
        intro.setWordWrap(True)
        lay.addWidget(intro)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Update", "Database", "Contains", "Copy", "Age", "Entries"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        for c in (0, 2, 3, 4, 5):
            hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.table.setMinimumHeight(260)
        lay.addWidget(with_help(self.table, "ti.db.table"))
        self.abuse = QLineEdit(secret_store.get("abusech"))
        self.abuse.setEchoMode(QLineEdit.Password)
        self.abuse.setPlaceholderText("optional - free key from https://auth.abuse.ch/ (ThreatFox, URLhaus, MalwareBazaar)")
        lay.addWidget(with_help(self.abuse, "ti.db.abusekey", "abuse.ch key"))
        r = QHBoxLayout()
        self.stale_btn = QPushButton("Tick out-of-date")
        helped(self.stale_btn, "ti.db.tickstale")
        self.upd = QPushButton("Update ticked databases now")
        self.upd.setObjectName("Primary")
        helped(self.upd, "ti.db.update")
        self.state = QLabel("")
        self.state.setWordWrap(True)
        r.addWidget(self.stale_btn)
        r.addWidget(self.upd)
        r.addWidget(self.state, 1)
        lay.addLayout(r)
        self.stale_btn.clicked.connect(self._tick_stale)
        self.upd.clicked.connect(self._update)
        self._thread: Optional[_UpdateThread] = None
        self.refresh()

    def refresh(self):
        rows = ts.status()
        self.table.setRowCount(len(rows))
        self._rows = rows
        for i, r in enumerate(rows):
            cb = QTableWidgetItem("")
            cb.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            # an optional database (large download) is never ticked for the user
            cb.setCheckState(Qt.Checked if (r["stale"] or not r["present"]) and not r["needs_key"]
                             and not (r.get("optional") and not r["present"]) else Qt.Unchecked)
            self.table.setItem(i, 0, cb)
            name = QTableWidgetItem(r["name"])
            name.setToolTip(f"{r['why']}\n\n" + (f"Size: {r['size']}\n" if r.get("size") else "")
                            + f"Licence: {r['licence']}\n{r['homepage']}")
            self.table.setItem(i, 1, name)
            self.table.setItem(i, 2, QTableWidgetItem(r["what"]))
            copy = r["where"] if r["present"] else (
                "file removed after download (antivirus?)" if r.get("removed") else
                ("optional - not installed (" + (r.get("size") or "large download") + ")") if r.get("optional") else
                "needs abuse.ch key" if r["needs_key"] else "not downloaded")
            self.table.setItem(i, 3, QTableWidgetItem(copy))
            age = "" if r["age_days"] is None else (f"{r['age_days']:g} days" + ("  (out of date)" if r["stale"] else ""))
            self.table.setItem(i, 4, QTableWidgetItem(age))
            self.table.setItem(i, 5, QTableWidgetItem("" if r["entries"] is None else f"{r['entries']:,}"))
        n_stale = sum(1 for r in rows if r["stale"])
        n_missing = sum(1 for r in rows if not r["present"] and not r["needs_key"] and not r.get("optional"))
        self.state.setText(("All databases are up to date." if not (n_stale or n_missing) else
                            f"{n_stale} out of date, {n_missing} not downloaded yet."))

    def summary(self) -> str:
        rows = ts.status()
        old = [r for r in rows if r["stale"]]
        miss = [r for r in rows if not r["present"] and not r["needs_key"]]
        return f"{len(old)} out of date, {len(miss)} not downloaded"

    def _tick_stale(self):
        for i, r in enumerate(self._rows):
            on = (r["stale"] or not r["present"]) and (not r["needs_key"] or bool(self.abuse.text().strip())) \
                and not (r.get("optional") and not r["present"])
            self.table.item(i, 0).setCheckState(Qt.Checked if on else Qt.Unchecked)

    def selected(self) -> List[str]:
        return [self._rows[i]["id"] for i in range(self.table.rowCount())
                if self.table.item(i, 0).checkState() == Qt.Checked]

    def _update(self):
        ids = self.selected()
        if not ids:
            QMessageBox.information(self, "RAMBreaker", "Tick the databases to update first.")
            return
        k = self.abuse.text().strip()
        if k:
            secret_store.put("abusech", k)
        self.upd.setEnabled(False)
        self.state.setText("Downloading...")
        self._thread = _UpdateThread(ids, {"abusech": k})
        self._thread.step.connect(lambda n: self.state.setText(f"Downloading {n} ..."))
        self._thread.done.connect(self._updated)
        self._thread.start()

    def _updated(self, res):
        self.upd.setEnabled(True)
        ok = [r for r in res if r["ok"]]
        bad = [r for r in res if not r["ok"]]
        self.refresh()
        msg = f"Updated {len(ok)} of {len(res)}."
        if bad:
            msg += "  Not updated: " + "; ".join(f"{r['name']}: {r['detail']}" for r in bad)[:600]
        self.state.setText(msg)
        self.updated.emit()

    def busy(self) -> bool:
        return self._thread is not None and self._thread.isRunning()


class DatabasesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Threat-intel databases")
        lay = QVBoxLayout(self)
        self.db = DatabasesWidget(self)
        lay.addWidget(self.db)
        r = QHBoxLayout()
        r.addStretch(1)
        close = QPushButton("Close")
        helped(close, "ti.close")
        close.clicked.connect(self.accept)
        r.addWidget(close)
        lay.addLayout(r)
        self.resize(900, 560)

    def reject(self):
        if not self.db.busy():
            super().reject()

    def accept(self):
        if self.db.busy():
            QMessageBox.information(self, "RAMBreaker", "Please wait for the download to finish.")
            return
        super().accept()


class ThreatIntelDialog(QDialog):
    """Options for one threat-intel run. result_opts() -> dict (vt_key is NOT saved
    anywhere unless 'remember' is ticked, and then only DPAPI-encrypted)."""

    def __init__(self, s: dict, case_label: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("DFIR + Threat Intel")
        self.s = s
        lay = QVBoxLayout(self)
        head = QLabel(
            f"<b>{case_label or 'This run'}</b>: every file and every process executable in the memory image is "
            "dumped and hashed, the injection-flagged memory regions are dumped, and everything is checked with YARA "
            "and offline threat feeds on this PC. Then only a short list of suspicious items is looked up on "
            "VirusTotal (hashes, public IPs and domains - files are never uploaded). The results go to "
            "<b>report.html, tab 'Threat Intelligence'</b>.")
        head.setWordWrap(True)
        lay.addWidget(head)

        g = QGroupBox("VirusTotal")
        gl = QVBoxLayout(g)
        saved = secret_store.get("virustotal")
        self.key = QLineEdit(saved)
        self.key.setEchoMode(QLineEdit.Password)
        self.key.setPlaceholderText("your VirusTotal API key (virustotal.com > profile > API key)")
        gl.addWidget(with_help(self.key, "ti.vtkey", "API key"))
        r = QHBoxLayout()
        self.remember = QCheckBox("Remember the key (encrypted for this Windows user)")
        self.remember.setChecked(bool(saved))
        self.remember.setEnabled(secret_store.available())
        helped(self.remember, "ti.remember")
        self.novt = QCheckBox("Local checks only (no VirusTotal)")
        helped(self.novt, "ti.novt")
        r.addWidget(self.remember)
        r.addWidget(self.novt)
        r.addStretch(1)
        gl.addLayout(r)
        r = QHBoxLayout()
        self.rate = QDoubleSpinBox()
        self.rate.setRange(0.5, 1000)
        self.rate.setDecimals(1)
        self.rate.setValue(float(s.get("vt_rate", 4)))
        self.max = QSpinBox()
        self.max.setRange(1, 100000)
        self.max.setValue(int(s.get("vt_max", 100)))
        r.addWidget(with_help(self.rate, "ti.rate", "Lookups / minute"))
        r.addWidget(with_help(self.max, "ti.max", "Max new lookups"))
        gl.addLayout(r)
        self.eta = QLabel("")
        self.eta.setWordWrap(True)
        gl.addWidget(self.eta)
        lay.addWidget(g)

        g = QGroupBox("YARA rules")
        gl = QVBoxLayout(g)
        self.yset = QComboBox()
        self.yset.addItem("core - fewer false positives (recommended)", "core")
        self.yset.addItem("extended - about twice the rules, more false positives", "extended")
        self.yset.setCurrentIndex(max(0, self.yset.findData(s.get("yara_set", "core"))))
        gl.addWidget(with_help(self.yset, "ti.yaraset", "Rule set"))
        r = QHBoxLayout()
        self.custom = QLineEdit(s.get("yara_custom_dir", ""))
        self.custom.setPlaceholderText("optional extra folder (yara_rules" + chr(92) + "custom is always used)")
        br = QPushButton("Browse...")         # a fixed 34 px "..." button rendered as "." with the app style
        helped(br, "ti.browsecustom")
        op = QPushButton("Open custom rules folder")
        helped(op, "ti.opencustom")
        r.addWidget(with_help(self.custom, "ti.customdir", "Extra rules folder"), 1)
        r.addWidget(br)
        r.addWidget(op)
        gl.addLayout(r)
        self.ncustom = QLabel("")
        gl.addWidget(self.ncustom)
        lay.addWidget(g)

        g = QGroupBox("Dumped files")
        gl = QHBoxLayout(g)
        self.protect = QCheckBox("Put every dumped file into its own password-protected ZIP (AES-256)")
        self.protect.setChecked(bool(s.get("protect_dumps", True)))
        helped(self.protect, "ti.protect")
        self.zippw = QLineEdit(str(s.get("zip_password") or "infected"))
        self.zippw.setMaximumWidth(160)
        gl.addWidget(self.protect)
        gl.addWidget(with_help(self.zippw, "ti.zippw", "Password"))
        gl.addStretch(1)
        self.protect.toggled.connect(self.zippw.setEnabled)
        self.zippw.setEnabled(self.protect.isChecked())
        lay.addWidget(g)

        g = QGroupBox("Threat-intel databases")
        gl = QVBoxLayout(g)
        self.db = DatabasesWidget(self)
        gl.addWidget(self.db)
        lay.addWidget(g, 1)

        r = QHBoxLayout()
        r.addStretch(1)
        self.go = QPushButton("Start")
        self.go.setObjectName("Primary")
        helped(self.go, "ti.start")
        ca = QPushButton("Cancel")
        helped(ca, "ti.cancel")
        r.addWidget(self.go)
        r.addWidget(ca)
        lay.addLayout(r)

        br.clicked.connect(self._browse)
        op.clicked.connect(self._open_custom)
        self.novt.toggled.connect(self._vt_toggle)
        self.rate.valueChanged.connect(self._eta)
        self.max.valueChanged.connect(self._eta)
        self.custom.textChanged.connect(self._count)
        self.go.clicked.connect(self._accept)
        ca.clicked.connect(self.reject)
        self._vt_toggle(False)
        self._count()
        self.resize(940, 820)

    def _vt_toggle(self, off: bool):
        for w in (self.key, self.remember, self.rate, self.max):
            w.setEnabled(not off and (w is not self.remember or secret_store.available()))
        self._eta()

    def _eta(self, *_):
        if self.novt.isChecked():
            self.eta.setText("VirusTotal off: only YARA and the offline feeds are used.")
            return
        mins = self.max.value() / max(0.1, self.rate.value())
        self.eta.setText(f"At most {self.max.value()} new lookups at {self.rate.value():g} per minute = up to "
                         f"{mins:.0f} min for the VirusTotal step (answers cached from earlier cases are free). "
                         "A free key allows 4 per minute and 500 per day; if the quota runs out, the rest is "
                         "marked 'not checked' and 'Continue VirusTotal lookups' finishes it later.")

    def _count(self, *_):
        files = ts.custom_rule_files([self.custom.text().strip()] if self.custom.text().strip() else [])
        self.ncustom.setText(f"{len(files)} custom rule file(s) will be used"
                             + (": " + ", ".join(f.name for f in files[:6]) + (" ..." if len(files) > 6 else "")
                                if files else " - drop .yar / .yara files into the custom folder to add your own."))

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Folder with your own YARA rules", self.custom.text())
        if d:
            self.custom.setText(d)

    def _open_custom(self):
        p = ts.rules_root() / "custom"
        p.mkdir(parents=True, exist_ok=True)
        platform_compat.open_path(p)

    def _accept(self):
        if self.db.busy():
            QMessageBox.information(self, "RAMBreaker", "Please wait for the database download to finish.")
            return
        if not self.novt.isChecked() and not self.key.text().strip():
            if QMessageBox.question(self, "RAMBreaker", "No VirusTotal key entered. Run with local checks only "
                                    "(YARA + offline feeds)?") != QMessageBox.Yes:
                return
            self.novt.setChecked(True)
        if secret_store.available():
            if self.remember.isChecked() and self.key.text().strip():
                secret_store.put("virustotal", self.key.text().strip())
            elif not self.remember.isChecked():
                secret_store.put("virustotal", None)       # user un-ticked: forget it
        self.accept()

    def result_opts(self) -> dict:
        return {"vt_key": "" if self.novt.isChecked() else self.key.text().strip(),
                "vt_rate": self.rate.value(), "vt_max": self.max.value(),
                "yara_set": self.yset.currentData() or "core",
                "yara_custom_dir": self.custom.text().strip(),
                "protect_dumps": self.protect.isChecked(),
                "zip_password": self.zippw.text().strip() or "infected"}

    def cli_args(self) -> List[str]:
        o = self.result_opts()
        a = ["--vt-rate", f"{o['vt_rate']:g}", "--vt-max", str(o["vt_max"]), "--yara-set", o["yara_set"]]
        if o["yara_custom_dir"]:
            a += ["--yara-dir", o["yara_custom_dir"]]
        if not o["vt_key"]:
            a.append("--no-vt")
        if o["protect_dumps"]:
            a += ["--zip-password", o["zip_password"]]
        else:
            a.append("--no-protect")
        return a
