"""Docked live log console."""

import html
import time
from collections import deque

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QLineEdit, QPlainTextEdit,
                               QTextEdit, QToolButton, QVBoxLayout, QWidget)

from gui import icons
from gui.widgets import ComboBox, HelpButton, THEME, helped

MAX_LINES = 20000


class LogConsole(QWidget):
    LEVELS = ["All", "Warnings + errors", "Errors only", "Success only"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.lines = deque(maxlen=MAX_LINES)     # (ts, level, text)
        self.logfile = None
        self._pending = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)
        bar = QHBoxLayout()
        bar.setSpacing(4)
        self.pause = QToolButton()
        self.pause.setCheckable(True)
        self.pause.setText("Pause")
        self.pause.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        helped(self.pause, "log.pause")
        self.level = ComboBox()
        self.level.addItems(self.LEVELS)
        helped(self.level, "log.level")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search log...")
        self.search.setClearButtonEnabled(True)
        helped(self.search, "log.search")
        self.copy = QToolButton()
        self.copy.setText("Copy")
        self.copy.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        helped(self.copy, "log.copy")
        self.openf = QToolButton()
        self.openf.setText("Open log file")
        self.openf.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        helped(self.openf, "log.openfile")
        self.clear = QToolButton()
        self.clear.setText("Clear")
        self.clear.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        helped(self.clear, "log.clear")
        for w in (self.pause, HelpButton("log.pause"), self.level, HelpButton("log.level")):
            bar.addWidget(w)
        bar.addWidget(self.search, 1)
        bar.addWidget(HelpButton("log.search"))
        for w in (self.copy, self.openf, self.clear, HelpButton("log.openfile")):
            bar.addWidget(w)
        lay.addLayout(bar)
        self.view = QTextEdit()
        self.view.setReadOnly(True)
        self.view.setLineWrapMode(QTextEdit.NoWrap)
        f = QFont("Cascadia Mono")
        f.setStyleHint(QFont.Monospace)
        f.setPointSizeF(9)
        self.view.setFont(f)
        self.view.document().setMaximumBlockCount(MAX_LINES)
        helped(self.view, "log.view")
        lay.addWidget(self.view, 1)
        self.level.currentIndexChanged.connect(self.rebuild)
        self.search.textChanged.connect(lambda _: self._debounce.start(200))
        self.copy.clicked.connect(self._copy)
        self.clear.clicked.connect(self._clear)
        self.pause.toggled.connect(lambda on: (not on) and self._scroll_end())
        self._debounce = QTimer(self, singleShot=True, timeout=self.rebuild)
        self._flush = QTimer(self, interval=150, timeout=self._flush_pending)
        self._flush.start()
        self.retheme()

    def retheme(self):
        c = THEME
        for b, ic in ((self.pause, "pause"), (self.copy, "copy"),
                      (self.openf, "external-link"), (self.clear, "x")):
            b.setIcon(icons.icon(ic, c.get("text", "#ddd"), 14))
        self.rebuild()

    def _color(self, level):
        c = THEME
        return {"error": c.get("err"), "warn": c.get("warn"), "ok": c.get("ok"),
                "info": c.get("text"), "event": c.get("muted")}.get(level, c.get("text"))

    def _visible(self, level, text):
        i = self.level.currentIndex()
        if i == 1 and level not in ("warn", "error"):
            return False
        if i == 2 and level != "error":
            return False
        if i == 3 and level != "ok":
            return False
        q = self.search.text().strip().lower()
        return not q or q in text.lower()

    def _fmt(self, ts, level, text):
        t = time.strftime("%H:%M:%S", time.localtime(ts))
        return (f"<span style='color:{THEME.get('faint')}'>{t}</span> "
                f"<span style='color:{self._color(level)}'>{html.escape(text)}</span>")

    def start_session_file(self, path):
        """Mirror every line to logs/<session>.log beside the program."""
        try:
            if getattr(self, "_sess", None):
                self._sess.close()
            path.parent.mkdir(parents=True, exist_ok=True)
            self._sess = open(path, "a", encoding="utf-8", buffering=1)
            self.session_path = path
        except OSError:
            self._sess = None

    def append(self, level: str, text: str):
        rec = (time.time(), level, text)
        self.lines.append(rec)
        s = getattr(self, "_sess", None)
        if s:
            try:
                s.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{level.upper():5s}] {text}\n")
            except OSError:
                pass
        if self._visible(level, text):
            self._pending.append(rec)

    def _flush_pending(self):
        if not self._pending:
            return
        chunk = "<br>".join(self._fmt(*r) for r in self._pending)
        self._pending.clear()
        cur = QTextCursor(self.view.document())
        cur.movePosition(QTextCursor.End)
        if not self.view.document().isEmpty():
            cur.insertBlock()
        cur.insertHtml(chunk)
        if not self.pause.isChecked():
            self._scroll_end()

    def _scroll_end(self):
        sb = self.view.verticalScrollBar()
        sb.setValue(sb.maximum())

    def rebuild(self):
        self._pending.clear()
        self.view.clear()
        vis = [r for r in self.lines if self._visible(r[1], r[2])][-5000:]
        if vis:
            self.view.setHtml("<br>".join(self._fmt(*r) for r in vis))
        self._scroll_end()

    def _copy(self):
        vis = [r for r in self.lines if self._visible(r[1], r[2])]
        QApplication.clipboard().setText("\n".join(
            f"{time.strftime('%H:%M:%S', time.localtime(t))} {x}" for t, _l, x in vis))

    def _clear(self):
        self.lines.clear()
        self._pending.clear()
        self.view.clear()
