"""Signature RAM-module animation, tied to real progress.

A stylised DIMM (PCB outline, chips, gold edge contacts) made of a grid of
memory cells. Cells are assigned to analysis stages in order; a cell lights
up (in its stage colour) when the work it represents is done. Between real
progress events a soft shimmer sweeps the next cells so the view never looks
stuck. IOC hits flash red cells. Cheap: QTimer capped at 24 fps, static
layer cached in a pixmap, animation paused while hidden/minimised.
"""

import math
import random
import time

from PySide6.QtCore import QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QSizePolicy, QWidget

STAGE_KIND = {
    "Detecting OS": "scan", "Resolving symbols": "symbols",
    "Running Volatility plugins": "scan", "Extracting strings": "extract",
    "Building process tree": "extract", "Analyzing processes": "extract",
    "Correlating findings": "extract", "Analyzing registry data": "extract",
    "Building evidence timeline": "extract", "Sigma": "hit",
    "IOC check": "hit", "Generating HTML report": "report",
}


class RamAnimation(QWidget):
    COLS, ROWS = 48, 9            # cells per chip-row block

    def __init__(self, theme: dict, parent=None):
        super().__init__(parent)
        self.c = theme
        self.setMinimumSize(420, 150)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(170)
        self.n = self.COLS * self.ROWS
        self.fill = [None] * self.n          # stage kind per lit cell
        self.progress = 0.0                  # 0..1 real progress
        self.kind = "scan"
        self.hits = []                       # (cell, t0)
        self.phase = 0.0
        self.running = False
        self._static = None
        self._t = QTimer(self)
        self._t.timeout.connect(self._tick)
        self._last = time.time()
        rnd = random.Random(7)
        self._order = list(range(self.n))
        # fill column-major in small blocks: reads like data being swept
        self._order.sort(key=lambda i: ((i % self.COLS) // 3, i // self.COLS, rnd.random()))

    # ---------------------------------------------------------------- control
    def set_theme(self, theme: dict):
        self.c = theme
        self._static = None
        self.update()

    def start(self):
        self.running = True
        self.fill = [None] * self.n
        self.progress = 0.0
        self.hits.clear()
        if self.isVisible():
            self._t.start(1000 // 24)

    def stop(self, done: bool = True):
        self.running = False
        self._t.stop()
        if done:
            self.set_progress(1.0)
        self.update()

    def set_stage(self, name: str):
        for k, v in STAGE_KIND.items():
            if k.lower() in (name or "").lower():
                self.kind = v
                return

    def set_progress(self, frac: float):
        frac = max(0.0, min(1.0, frac))
        target = int(frac * self.n)
        lit = sum(1 for f in self.fill if f)
        for j in range(lit, target):
            self.fill[self._order[j]] = self.kind
        self.progress = frac
        self.update()

    def flash_hit(self, count: int = 3):
        lit = [i for i, f in enumerate(self.fill) if f]
        if not lit:
            return
        now = time.time()
        for i in random.sample(lit, min(count, len(lit))):
            self.fill[i] = "hit"
            self.hits.append((i, now))

    # ----------------------------------------------------------- visibility
    def showEvent(self, e):
        if self.running:
            self._t.start(1000 // 24)
        super().showEvent(e)

    def hideEvent(self, e):
        self._t.stop()           # minimised / hidden: zero CPU
        super().hideEvent(e)

    def resizeEvent(self, e):
        self._static = None
        super().resizeEvent(e)

    def _tick(self):
        if not self.isVisible() or (self.window() and self.window().isMinimized()):
            return
        now = time.time()
        self.phase = (self.phase + (now - self._last) * 1.6) % 1000
        self._last = now
        self.hits = [(i, t) for i, t in self.hits if now - t < 1.2]
        self.update()

    # ----------------------------------------------------------------- paint
    def _geometry(self):
        w, h = self.width(), self.height()
        pcb = QRectF(10, 24, w - 20, h - 50)
        cells = pcb.adjusted(16, 16, -16, -16)
        return pcb, cells

    def _paint_static(self):
        pm = QPixmap(self.size() * self.devicePixelRatioF())
        pm.setDevicePixelRatio(self.devicePixelRatioF())
        pm.fill(QColor(self.c["panel"]))
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing, False)
        pcb, cells = self._geometry()
        p.setPen(QPen(QColor(self.c["border_hi"]), 1))
        p.setBrush(QColor(self.c["panel2"]))
        p.drawRect(pcb)
        # notch + gold edge contacts
        notch_x = pcb.left() + pcb.width() * 0.42
        p.setBrush(QColor(self.c["panel"]))
        p.setPen(Qt.NoPen)
        p.drawRect(QRectF(notch_x, pcb.bottom() - 1, 10, 24))
        gold = QColor("#b08d3c") if self.c["bg"].lower() < "#5" else QColor("#c9a24a")
        x = pcb.left() + 8
        while x < pcb.right() - 10:
            if not (notch_x - 3 < x < notch_x + 12):
                p.fillRect(QRectF(x, pcb.bottom() + 3, 5, 14), gold)
            x += 8
        # chip outlines (cells are drawn on top of them)
        chips = 8
        cw = cells.width() / chips
        p.setPen(QPen(QColor(self.c["border"]), 1))
        p.setBrush(Qt.NoBrush)
        for k in range(chips):
            p.drawRect(QRectF(cells.left() + k * cw + 2, cells.top() - 6, cw - 4, cells.height() + 12))
        p.end()
        self._static = pm

    def paintEvent(self, _):
        if self._static is None or self._static.size() != self.size() * self.devicePixelRatioF():
            self._paint_static()
        p = QPainter(self)
        p.drawPixmap(0, 0, self._static)
        _, cells = self._geometry()
        cw = cells.width() / self.COLS
        ch = cells.height() / self.ROWS
        idle = QColor(self.c["cell_idle"])
        lit = sum(1 for f in self.fill if f)
        front = [self._order[j] for j in range(lit, min(self.n, lit + 24))] if self.running else []
        hot = {i for i, _ in self.hits}
        for i in range(self.n):
            col, row = i % self.COLS, i // self.COLS
            r = QRectF(cells.left() + col * cw + 1, cells.top() + row * ch + 1, cw - 2, ch - 2)
            f = self.fill[i]
            if f:
                base = QColor(self.c.get(f, self.c["scan"]))
                if i not in hot:
                    base = base.darker(135) if f != "hit" else base
                p.fillRect(r, base)
            else:
                p.fillRect(r, idle)
        # shimmer at the progress front: proves liveness between events
        if front:
            sc = QColor(self.c.get(self.kind, self.c["scan"]))
            for k, i in enumerate(front):
                a = 0.5 + 0.5 * math.sin(self.phase * 4 - k * 0.45)
                col, row = i % self.COLS, i // self.COLS
                r = QRectF(cells.left() + col * cw + 1, cells.top() + row * ch + 1, cw - 2, ch - 2)
                c = QColor(sc)
                c.setAlphaF(0.15 + 0.55 * a)
                p.fillRect(r, c)
        # caption
        p.setPen(QColor(self.c["muted"]))
        p.drawText(QRectF(10, 2, self.width() - 20, 20), Qt.AlignRight | Qt.AlignVCenter,
                   f"{int(self.progress * 100)} %  of the analysis complete")
        p.drawText(QRectF(10, 2, self.width() - 20, 20), Qt.AlignLeft | Qt.AlignVCenter,
                   "MEMORY MAP")
        p.end()
