"""GUI for the "DFIR + Threat Intel" mode (RAMBreaker v2.2).

ThreatIntelDialog   asked before a threat-intel run: VirusTotal key (stored encrypted
                    for this Windows user only if the user ticks it), pace, YARA rule set,
                    custom-rule folder, and the threat-intel databases with their age.
DatabasesWidget     the database table + an Update button (the user's choice, never
                    automatic); also opened from Settings. v2.6: live progress (size
                    left, speed, time left), Pause / Resume / Cancel, Delete of
                    downloaded copies, a Size column and the free disk space.

The results themselves are NOT shown here: they go to report.html (tab "Threat
Intelligence") and <case>/threat_intelligence/.
"""

import re
import time
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QThread, QTimer, Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QDialog, QFileDialog, QFrame,
                               QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
                               QMessageBox, QProgressBar, QPushButton, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from gui.widgets import ComboBox, DoubleSpinBox, SpinBox, helped, with_help
from modules import platform_compat, secret_store
from modules import ti_sources as ts


# ------------------------------------------------------------------ progress text (v2.6)
def fmt_size(n) -> str:
    """1536 -> '1.5 KB' (Windows-style units of 1024)."""
    if n is None:
        return "?"
    n = float(n)
    if abs(n) < 1024:
        return f"{int(n)} bytes"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}"
    return f"{n:,.1f} TB"


def fmt_eta(seconds: float) -> str:
    s = max(0, int(round(seconds)))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s"
    return f"{s // 3600} h {s % 3600 // 60:02d} min"


class RateMeter:
    """Download speed over the last few seconds from (time, bytes received) samples.
    No value until at least `min_span` seconds are measured: the first second of a
    download (connection start-up) gave wild time-left guesses ('about 42 min')."""

    def __init__(self, window: float = 5.0, min_span: float = 1.0):
        self.window = window
        self.min_span = min_span
        self.samples = deque()

    def reset(self) -> None:
        self.samples.clear()

    def add(self, t: float, received: int) -> Optional[float]:
        self.samples.append((t, received))
        while len(self.samples) > 2 and t - self.samples[0][0] > self.window:
            self.samples.popleft()
        (t0, b0), (t1, b1) = self.samples[0], self.samples[-1]
        return (b1 - b0) / (t1 - t0) if t1 - t0 >= self.min_span else None


def progress_title(c: "ts.Transfer") -> str:
    return f"Database {c.index} of {c.count}: {c.source}" if c.source else "Starting the update ..."


def progress_permille(c: "ts.Transfer") -> Optional[int]:
    """Bar position 0..1000, or None for a moving bar (size unknown / building a database)."""
    if c.phase == "downloading" and c.total and not c.multi:
        return max(0, min(1000, int(1000 * c.done / c.total)))
    return None


def progress_line(c: "ts.Transfer", speed: Optional[float], cancelling: bool = False) -> str:
    """'120.5 MB of 231.0 MB  ·  110.5 MB left  ·  4.2 MB/s  ·  about 26 s left'"""
    parts = []
    connecting = c.phase == "downloading" and not c.done and c.total is None and not (c.multi and c.source_bytes)
    if connecting:
        parts.append("Connecting ...")
    elif c.phase == "downloading":
        if c.multi:
            parts.append(f"{fmt_size(c.source_bytes)} downloaded" + (f" ({c.detail})" if c.detail else ""))
        elif c.total:
            parts += [f"{fmt_size(c.done)} of {fmt_size(c.total)}", f"{fmt_size(max(0, c.total - c.done))} left"]
        else:
            parts.append(f"{fmt_size(c.done)} downloaded (the server did not say the size)")
    else:
        word = {"unpacking": "Unpacking the download", "building": "Building the local database"}.get(
            c.phase, "Working")
        parts.append(word + (f": {c.detail}" if c.detail else ""))
    if cancelling:
        parts.append("Cancelling ...")
    elif c.paused:
        parts.append("Paused")
    elif c.phase == "downloading" and speed is not None and not connecting:
        parts.append(f"{fmt_size(speed)}/s")
        if c.total and not c.multi and speed > 1:
            parts.append(f"about {fmt_eta((c.total - c.done) / speed)} left")
    return "  ·  ".join(parts)


class _UpdateThread(QThread):
    done = Signal(list)

    def __init__(self, ids: List[str], keys: Dict[str, str], ctl: "ts.Transfer"):
        super().__init__()
        self.ids, self.keys, self.ctl = ids, keys, ctl

    def run(self):
        try:
            res = ts.update(self.ids, self.keys, ctl=self.ctl)
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
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Update", "Database", "Contains", "Copy", "Size", "Age", "Entries"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        for c in (0, 4, 5, 6):
            hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        # v2.6: Contains / Copy have a set width (long text is cut with "...", full text on
        # hover). Sized to their longest text, the Copy column of the optional databases
        # ("about 19 GB download and well over 100 GB ...") pushed Size, Age and Entries
        # out of the window and centred its own header out of sight.
        for c, width in ((2, 190), (3, 210)):
            hh.setSectionResizeMode(c, QHeaderView.Interactive)
            self.table.setColumnWidth(c, width)
        self.table.setWordWrap(False)
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
        self.delb = QPushButton("Delete ticked downloads")
        helped(self.delb, "ti.db.delete")
        r.addWidget(self.stale_btn)
        r.addWidget(self.upd)
        r.addWidget(self.delb)
        r.addStretch(1)
        lay.addLayout(r)
        # v2.6: live progress of an update, with Pause / Resume and Cancel
        self.prog = QFrame()
        self.prog.setObjectName("Panel")
        pl = QVBoxLayout(self.prog)
        pl.setContentsMargins(8, 6, 8, 6)
        self.p_title = QLabel("")
        self.p_title.setWordWrap(True)
        self.p_bar = QProgressBar()
        self.p_bar.setRange(0, 1000)
        helped(self.p_bar, "ti.db.progress")
        pr = QHBoxLayout()
        self.p_text = QLabel("")
        self.p_text.setWordWrap(True)
        helped(self.p_text, "ti.db.progress")
        self.pause_btn = QPushButton("Pause")
        helped(self.pause_btn, "ti.db.pause")
        self.cancel_btn = QPushButton("Cancel")
        helped(self.cancel_btn, "ti.db.cancel")
        pr.addWidget(self.p_text, 1)
        pr.addWidget(self.pause_btn)
        pr.addWidget(self.cancel_btn)
        pl.addWidget(self.p_title)
        pl.addWidget(self.p_bar)
        pl.addLayout(pr)
        self.prog.setVisible(False)
        lay.addWidget(self.prog)
        self.state = QLabel("")
        self.state.setWordWrap(True)
        lay.addWidget(self.state)
        self.disk = QLabel("")
        self.disk.setObjectName("Muted")
        helped(self.disk, "ti.db.disk")
        lay.addWidget(self.disk)
        self.stale_btn.clicked.connect(self._tick_stale)
        self.upd.clicked.connect(self._update)
        self.delb.clicked.connect(self._delete)
        self.pause_btn.clicked.connect(self._pause)
        self.cancel_btn.clicked.connect(self.cancel)
        self.table.itemChanged.connect(self._sync_buttons)
        self._thread: Optional[_UpdateThread] = None
        self._running = False
        self._ctl: Optional[ts.Transfer] = None
        self._cancelling = False
        self._was_paused = False
        self._ticks = 0
        self._when_idle = None
        self._meter = RateMeter()
        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._tick)
        self._rows: List[dict] = []
        self.refresh()

    def refresh(self):
        rows = ts.status()
        self.table.blockSignals(True)              # setItem would fire itemChanged per cell
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
            what = QTableWidgetItem(r["what"])
            what.setToolTip(r["what"])
            self.table.setItem(i, 2, what)
            short_size = re.split(r"[,;]| and ", r.get("size") or "")[0].strip() or "large download"
            copy = (r["where"] + ("  (incomplete - Update continues it)" if r.get("partial") else "")) \
                if r["present"] else (
                "file removed after download (antivirus?)" if r.get("removed") else
                f"optional - not installed ({short_size})" if r.get("optional") else
                "needs abuse.ch key" if r["needs_key"] else "not downloaded")
            ci = QTableWidgetItem(copy)
            ci.setToolTip(copy + (f"\n\nSize: {r['size']}" if r.get("size") else ""))
            self.table.setItem(i, 3, ci)
            size = QTableWidgetItem(fmt_size(r["disk_bytes"]) if r["present"] else "")
            size.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(i, 4, size)
            age = "" if r["age_days"] is None else (f"{r['age_days']:g} days" + ("  (out of date)" if r["stale"] else ""))
            self.table.setItem(i, 5, QTableWidgetItem(age))
            self.table.setItem(i, 6, QTableWidgetItem("" if r["entries"] is None else f"{r['entries']:,}"))
        self.table.blockSignals(False)
        n_stale = sum(1 for r in rows if r["stale"])
        n_missing = sum(1 for r in rows if not r["present"] and not r["needs_key"] and not r.get("optional"))
        self.state.setText(("All databases are up to date." if not (n_stale or n_missing) else
                            f"{n_stale} out of date, {n_missing} not downloaded yet."))
        self._show_disk()
        self._sync_buttons()

    def _show_disk(self):
        free, drive = ts.disk_free()
        where = f"Free disk space ({drive}): {fmt_size(free)}" if free >= 0 else "Free disk space: unknown"
        self.disk.setText(f"{where}   ·   threat-intel databases use {fmt_size(ts.space_used(self._rows))}")

    def _ticked(self) -> List[int]:
        return [i for i in range(self.table.rowCount())
                if self.table.item(i, 0) is not None and self.table.item(i, 0).checkState() == Qt.Checked]

    def _sync_buttons(self, *_):
        busy = self.busy()
        self.upd.setEnabled(not busy)
        self.stale_btn.setEnabled(not busy)
        self.delb.setEnabled(not busy and any(self._rows[i]["downloaded"] for i in self._ticked()
                                              if i < len(self._rows)))

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
        return [self._rows[i]["id"] for i in self._ticked()]

    # ---------------------------------------------------------------- update
    def _update(self):
        ids = self.selected()
        if not ids:
            QMessageBox.information(self, "RAMBreaker", "Tick the databases to update first.")
            return
        need = sum(r["need_free"] for r in self._rows if r["id"] in ids)
        free, drive = ts.disk_free()
        if need and 0 <= free < need:
            if QMessageBox.question(
                    self, "RAMBreaker",
                    f"The ticked databases need about {fmt_size(need)} of free disk space while they are "
                    f"downloaded and built, but {drive} has only {fmt_size(free)} free.\n\nStart anyway?") \
                    != QMessageBox.Yes:
                return
        k = self.abuse.text().strip()
        if k:
            secret_store.put("abusech", k)
        self._ctl = ts.Transfer()
        self._cancelling, self._was_paused, self._ticks = False, False, 0
        self._meter.reset()
        self.pause_btn.setText("Pause")
        self.pause_btn.setEnabled(True)
        self.cancel_btn.setEnabled(True)
        self.p_bar.setRange(0, 1000)
        self.p_bar.setValue(0)
        self.state.setText("")
        self.prog.setVisible(True)
        self._running = True
        self._thread = _UpdateThread(ids, {"abusech": k}, self._ctl)
        self._thread.done.connect(self._updated)
        self._thread.start()
        self._sync_buttons()
        self._tick()
        self._timer.start()

    def _tick(self):
        """Every 0.5 s while an update runs: title, bar, size left, speed, time left, disk."""
        c = self._ctl
        if c is None:
            return
        paused = c.paused
        if paused != self._was_paused:                 # speed restarts after a pause
            self._meter.reset()
            self._was_paused = paused
        speed = None if paused else self._meter.add(time.monotonic(), c.received)
        self.p_title.setText(progress_title(c))
        pm = progress_permille(c)
        if pm is None:
            if self.p_bar.maximum() != 0 and not paused:
                self.p_bar.setRange(0, 0)              # moving bar: size of this step not known
        else:
            if self.p_bar.maximum() != 1000:
                self.p_bar.setRange(0, 1000)
            self.p_bar.setValue(pm)
        self.p_text.setText(progress_line(c, speed, self._cancelling))
        self._ticks += 1
        if self._ticks % 4 == 1:
            self._show_disk()

    def _pause(self):
        c = self._ctl
        if c is None or not self._running:
            return
        if c.paused:
            c.resume()
            self.pause_btn.setText("Pause")
        else:
            c.pause()
            self.pause_btn.setText("Resume")
        self._tick()

    def cancel(self):
        """Stop the running update (the database being fetched keeps its old copy)."""
        if self._ctl is not None and self._running:
            self._cancelling = True
            self._ctl.cancel()
            self.pause_btn.setEnabled(False)
            self.cancel_btn.setEnabled(False)
            self._tick()

    def _updated(self, res):
        if self._thread is not None:
            self._thread.wait()                        # run() emits just before it returns
        self._timer.stop()
        self._running = False
        self.prog.setVisible(False)
        ok = [r for r in res if r["ok"]]
        cancelled = [r for r in res if r.get("cancelled")]
        bad = [r for r in res if not r["ok"] and not r.get("cancelled")]
        self.refresh()
        msg = f"Updated {len(ok)} of {len(res)}."
        if cancelled:
            msg += "  Cancelled: " + "; ".join(f"{r['name']} ({r['detail']})" for r in cancelled
                                               if "not started" not in r["detail"])
            skipped = sum(1 for r in cancelled if "not started" in r["detail"])
            if skipped:
                msg += f"; {skipped} not started"
        if bad:
            msg += "  Not updated: " + "; ".join(f"{r['name']}: {r['detail']}" for r in bad)[:600]
        self.state.setText(msg)
        self.updated.emit()
        cb, self._when_idle = self._when_idle, None
        if cb is not None:
            cb()

    def busy(self) -> bool:
        return self._running

    def close_when_idle(self, parent: QWidget, close_fn) -> bool:
        """For a window that holds this widget: True = it may close now. While an update
        runs, ask whether to cancel it; on Yes the window closes (close_fn) as soon as the
        download thread has stopped, never while it still runs."""
        if not self.busy():
            return True
        if QMessageBox.question(parent, "RAMBreaker",
                                "A database update is running. Cancel it and close this window?\n\n"
                                "The database being downloaded keeps its previous copy.") == QMessageBox.Yes:
            self._when_idle = close_fn
            self.cancel()
        return False

    # ---------------------------------------------------------------- delete
    def _delete(self):
        rows = [self._rows[i] for i in self._ticked() if self._rows[i]["downloaded"]]
        if not rows:
            QMessageBox.information(self, "RAMBreaker",
                                    "None of the ticked databases has a downloaded copy on this PC. Copies that "
                                    "ship with RAMBreaker are part of the program and are not deleted.")
            return
        total = sum(r["downloaded_bytes"] for r in rows)
        lines = "\n".join(f"   {r['name']}  ({fmt_size(r['downloaded_bytes'])})" for r in rows)
        notes = []
        if any(r["bundled"] for r in rows):
            notes.append("Databases that also ship with RAMBreaker go back to that copy.")
        if any(r["id"].startswith("nsrl_") for r in rows):
            notes.append("The two NSRL rows share one database: deleting either removes it.")
        if QMessageBox.question(
                self, "RAMBreaker",
                f"Delete the downloaded copies of:\n\n{lines}\n\nThis frees about {fmt_size(total)}. "
                + " ".join(notes) + "\nYou can download them again with Update.") != QMessageBox.Yes:
            return
        res = ts.delete([r["id"] for r in rows])
        freed = sum(r["freed"] for r in res)
        bad = [r for r in res if not r["ok"]]
        self.refresh()
        msg = f"Deleted {len(res) - len(bad)} of {len(res)}, {fmt_size(freed)} freed."
        if bad:
            msg += "  Not deleted: " + "; ".join(f"{r['name']}: {r['detail']}" for r in bad)[:600]
        self.state.setText(msg)
        self.updated.emit()


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
        self.resize(1060, 660)

    def reject(self):
        if self.db.close_when_idle(self, super().reject):
            super().reject()

    def accept(self):
        if self.db.close_when_idle(self, super().accept):
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
        self.rate = DoubleSpinBox()
        self.rate.setRange(0.5, 1000)
        self.rate.setDecimals(1)
        self.rate.setValue(float(s.get("vt_rate", 4)))
        self.max = SpinBox()
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
        self.yset = ComboBox()
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

    def reject(self):
        if self.db.close_when_idle(self, super().reject):
            super().reject()

    def _accept(self):
        if self.db.busy():
            QMessageBox.information(self, "RAMBreaker", "A database update is running: wait for it to finish, "
                                    "or press Cancel next to its progress bar.")
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
