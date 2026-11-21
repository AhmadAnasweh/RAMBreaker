"""In-depth help guides: annotated animations of the real window + long-form text.

Opened by the "?" of controls that have an entry in help_registry.GUIDES
(presets, plugin category, fast mode, RAM / jobs mode). The window is
non-modal (show(), never exec()), so the main window stays usable.

Media: gui/help_media/<name>_<theme>.gif, generated from the real GUI by
build_tools/make_help_media.py. The other theme's file is used when one is
missing, and a missing animation only hides the picture.
"""

import re
import sys
from pathlib import Path
from typing import Dict, Optional

from PySide6.QtCore import QPoint, QSize, Qt
from PySide6.QtGui import QImageReader, QMovie
from PySide6.QtWidgets import (QApplication, QDialog, QHBoxLayout, QLabel, QListWidget,
                               QPushButton, QTextBrowser, QToolButton, QVBoxLayout, QWidget)

from gui import help_registry, icons
from gui.widgets import THEME, helped

OS_LABEL = {"windows": "Windows", "linux": "Linux", "mac": "macOS"}


def media_dir() -> Path:
    base = Path(getattr(sys, "_MEIPASS", "")) / "gui" / "help_media"
    if base.is_dir():
        return base
    return Path(__file__).resolve().parent / "help_media"


def theme_name() -> str:
    app = QApplication.instance()
    return (app.property("rb_theme") if app else None) or "dark"


def media_path(name: str, theme: Optional[str] = None) -> Optional[Path]:
    if not name:
        return None
    t = theme or theme_name()
    for cand in (t, "light" if t == "dark" else "dark"):
        p = media_dir() / f"{name}_{cand}.gif"
        if p.is_file():
            return p
    return None


# ── live facts for the text (real plugin lists, real timing model) ──────────
_cache: Dict[str, str] = {}


def _short(plugin: str) -> str:
    """windows.registry.hivelist.HiveList -> registry.hivelist; linux_pslist stays."""
    parts = plugin.split(".")
    return ".".join(parts[1:-1]) if len(parts) >= 3 else plugin


def plugins_html(mode: str) -> str:
    key = "p:" + mode
    if key in _cache:
        return _cache[key]
    try:
        from gui.main_window import plugin_list
        out = []
        for os_t in ("windows", "linux", "mac"):
            pl = plugin_list(os_t, "vol3", mode)
            if not pl:
                continue
            full = plugin_list(os_t, "vol3", "full")
            note = ""
            if mode not in ("full", "fast") and pl == full:
                note = " - no separate set for this OS, the complete set runs"
            out.append(f"<p style='margin:4px 0 0 0'><b>{OS_LABEL[os_t]}</b> "
                       f"<span style='color:[[muted]]'>(Volatility 3, {len(pl)} plugins{note})</span><br>"
                       f"<span style='font-family:Consolas,monospace;font-size:8.5pt'>"
                       f"{', '.join(_short(p) for p in pl)}</span></p>")
        html = "".join(out) or "<p>(plugin list unavailable)</p>"
    except Exception as e:                      # never break the help window
        html = f"<p>(plugin list unavailable: {e})</p>"
    _cache[key] = html
    return html


def eta_html(cmd: str, mode: str) -> str:
    key = f"e:{cmd}:{mode}"
    if key in _cache:
        return _cache[key]
    fallback = "The setup panel shows the estimate for your dump before you start."
    try:
        from gui.main_window import POST_S_PER_GB, plugin_list
        from modules import timeout_model as tm
        m = tm.get_model()
        pl = plugin_list("windows", "vol3", mode)
        parts = []
        for gb in (2.0, 8.0):
            plugs = [p for p in pl if not (p == "windows.vadinfo.VadInfo"
                                           and m.expected(p, "vol3", "windows", gb) > 1800)]
            total, _ = m.estimate_total(plugs, "vol3", "windows", gb, 4)
            post = 0 if cmd == "extract" else POST_S_PER_GB * gb
            parts.append(f"<b>~{tm._fmt(total + post + 30)}</b> on a {gb:.0f} GB")
        html = (f"Model estimate for a Windows image, 4 parallel jobs: {parts[0]} dump, "
                f"{parts[1]} dump ({len(pl)} plugins). {fallback}")
    except Exception:
        html = fallback
    _cache[key] = html
    return html


def render(html: str, c: dict) -> str:
    def sub(m):
        kind, arg = m.group(1), m.group(2) or ""
        if kind == "plugins":
            return plugins_html(arg)
        if kind == "eta":
            cmd, _, mode = arg.partition(":")
            return eta_html(cmd, mode)
        return c.get(kind, "")
    out = html
    for _ in range(2):                      # plugin/eta fragments carry colour tokens
        out = re.sub(r"\[\[(\w+)(?::([\w:]+))?\]\]", sub, out)
    return out


# ── window ──────────────────────────────────────────────────────────────────
class GuideWindow(QDialog):
    _open: Dict[str, "GuideWindow"] = {}

    def __init__(self, key: str, parent: Optional[QWidget] = None, page: int = 0):
        super().__init__(parent, Qt.Window | Qt.WindowCloseButtonHint)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setModal(False)
        self.key = key
        self.g = help_registry.guide(key)
        self.movie: Optional[QMovie] = None
        self.setWindowTitle(f"Help - {self.g['title']}")
        helped(self, key)
        c = THEME
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)
        t = QLabel(self.g["title"])
        t.setObjectName("H1")
        lay.addWidget(t)
        intro = QLabel(self.g.get("intro", ""))
        intro.setObjectName("Muted")
        intro.setWordWrap(True)
        lay.addWidget(intro)
        body = QHBoxLayout()
        body.setSpacing(10)
        pages = self.g["pages"]
        self.pages = QListWidget()
        helped(self.pages, "guide.pages")
        for label, _m, _h in pages:
            self.pages.addItem(label)
        self.pages.setFixedWidth(150)
        self.pages.setVisible(len(pages) > 1)
        body.addWidget(self.pages)
        right = QVBoxLayout()
        right.setSpacing(6)
        self.media = QLabel()
        self.media.setAlignment(Qt.AlignCenter)
        self.media.setStyleSheet(f"QLabel{{border:1px solid {c.get('border_hi', '#3b4859')};"
                                 f"background:{c.get('panel', '#141921')};}}")
        helped(self.media, "guide.media")
        self.media.mousePressEvent = lambda _e: self._toggle()
        right.addWidget(self.media, 0, Qt.AlignHCenter)
        ctl = QHBoxLayout()
        ctl.setSpacing(4)
        self.b_prev = QToolButton()
        self.b_play = QToolButton()
        self.b_next = QToolButton()
        for b, ic, k in ((self.b_prev, "chevron-left", "guide.prev"),
                         (self.b_play, "pause", "guide.play"),
                         (self.b_next, "chevron-right", "guide.next")):
            b.setIcon(icons.icon(ic, c.get("text", "#dce2ea"), 16))
            helped(b, k)
            ctl.addWidget(b)
        self.step = QLabel("")
        self.step.setObjectName("Muted")
        ctl.addWidget(self.step)
        ctl.addStretch(1)
        right.addLayout(ctl)
        self.text = QTextBrowser()
        self.text.setOpenExternalLinks(False)
        helped(self.text, "guide.text")
        self.text.setMinimumHeight(170)
        right.addWidget(self.text, 1)
        body.addLayout(right, 1)
        lay.addLayout(body, 1)
        bb = QHBoxLayout()
        bb.addStretch(1)
        close = QPushButton("Close")
        helped(close, "guide.close")
        close.clicked.connect(self.close)
        bb.addWidget(close)
        lay.addLayout(bb)
        self.b_prev.clicked.connect(lambda: self._step(-1))
        self.b_next.clicked.connect(lambda: self._step(1))
        self.b_play.clicked.connect(self._toggle)
        self._fit()
        first = max(0, min(page, len(pages) - 1))
        self.pages.setCurrentRow(first)
        self.pages.currentRowChanged.connect(self.show_page)
        self.show_page(first)

    def _fit(self):
        scr = (self.parentWidget().screen() if self.parentWidget() else None) or \
            QApplication.primaryScreen()
        avail = scr.availableGeometry() if scr else None
        w, h = 900, 900
        if avail is not None:
            w, h = min(w, avail.width() - 40), min(h, avail.height() - 60)
        self._media_h = max(220, min(400, h - 370))          # leave >= ~170 px for the text
        self.resize(w, h)

    # -- pages and animation
    def show_page(self, i: int):
        if i < 0:
            return
        label, name, html = self.g["pages"][i]
        self.text.setHtml(render(html, THEME))
        if self.movie is not None:
            self.movie.stop()
            self.movie.deleteLater()
            self.movie = None
        p = media_path(name)
        mv = QMovie(str(p)) if p else None
        if mv is None or not mv.isValid():
            self.media.setMovie(None)
            self.media.setText("(animation not available)")
            self.media.setFixedSize(QSize(320, 40))
            for b in (self.b_prev, self.b_play, self.b_next):
                b.setEnabled(False)
            self.step.setText("")
            return
        mv.setCacheMode(QMovie.CacheAll)
        sz = QImageReader(str(p)).size()        # (jumpToFrame(0) + start() would skip frame 1)
        if sz.height() > self._media_h:
            sz = sz.scaled(QSize(10000, self._media_h), Qt.KeepAspectRatio)
            mv.setScaledSize(sz)
        self.media.setFixedSize(sz.width() + 2, sz.height() + 2)
        self.media.setMovie(mv)
        mv.frameChanged.connect(self._frame)
        self.movie = mv
        for b in (self.b_prev, self.b_play, self.b_next):
            b.setEnabled(True)
        mv.start()
        self._set_play_icon()

    def _frame(self, n: int):
        if self.movie is not None:
            self.step.setText(f"Step {n + 1} of {max(1, self.movie.frameCount())}"
                              + ("   (paused)" if self.movie.state() == QMovie.Paused else ""))

    def _toggle(self):
        mv = self.movie
        if mv is None:
            return
        mv.setPaused(mv.state() == QMovie.Running)
        self._set_play_icon()
        self._frame(mv.currentFrameNumber())

    def _set_play_icon(self):
        running = self.movie is not None and self.movie.state() == QMovie.Running
        self.b_play.setIcon(icons.icon("pause" if running else "play", THEME.get("text", "#dce2ea"), 16))

    def _step(self, d: int):
        mv = self.movie
        if mv is None or mv.frameCount() <= 0:
            return
        if mv.state() == QMovie.Running:
            mv.setPaused(True)
        n = (mv.currentFrameNumber() + d) % mv.frameCount()
        mv.jumpToFrame(n)
        self._set_play_icon()
        self._frame(n)

    def closeEvent(self, e):
        if self.movie is not None:
            self.movie.stop()
        if GuideWindow._open.get(self.key) is self:
            GuideWindow._open.pop(self.key, None)
        super().closeEvent(e)

    # -- entry point
    @classmethod
    def initial_page(cls, key: str, anchor: Optional[QWidget]) -> int:
        """Open on the page of what is selected now (not on the default choice)."""
        win = anchor.window() if anchor is not None else QApplication.activeWindow()
        setup = getattr(win, "setup", None)
        combo = {"setup.preset": getattr(setup, "preset", None),
                 "setup.category": getattr(setup, "category", None)}.get(key)
        if combo is None or combo.currentIndex() <= 0:
            return 0
        cur = combo.currentText().lower()
        for i, (label, _m, _h) in enumerate(help_registry.guide(key)["pages"]):
            if i and cur.startswith(label.lower().split(" (")[0].split()[0]):
                return i
        return 0

    @classmethod
    def show_for(cls, key: str, anchor: Optional[QWidget] = None, page: Optional[int] = None):
        w = cls._open.get(key)
        if w is not None:
            try:
                w.raise_()
                w.activateWindow()
                return w
            except RuntimeError:                # deleted on close
                cls._open.pop(key, None)
        parent = anchor.window() if anchor is not None else QApplication.activeWindow()
        w = cls(key, parent, cls.initial_page(key, anchor) if page is None else page)
        if anchor is not None:
            pos = anchor.mapToGlobal(QPoint(anchor.width() + 12, -40))
            scr = QApplication.screenAt(pos) or QApplication.primaryScreen()
            g = scr.availableGeometry()
            w.move(max(g.left(), min(pos.x(), g.right() - w.width() - 8)),
                   max(g.top(), min(pos.y(), g.bottom() - w.height() - 8)))
        w.show()
        cls._open[key] = w
        return w
