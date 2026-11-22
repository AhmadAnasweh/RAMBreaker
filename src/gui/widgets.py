"""Help plumbing (? buttons, rich popups, help mode) + small shared widgets."""

from PySide6.QtCore import QEvent, QObject, QPoint, QSortFilterProxyModel, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QCursor, QPainter, QPen
from PySide6.QtWidgets import (QAbstractSpinBox, QApplication, QComboBox, QFrame, QHBoxLayout,
                               QLabel, QSizePolicy, QSlider, QToolButton, QVBoxLayout, QWidget,
                               QTextBrowser)

from gui import help_registry, icons

THEME = {}          # filled by the main window (current palette)


def set_theme(c: dict) -> None:
    THEME.clear()
    THEME.update(c)


def _sort_norm(v):
    """One total order for mixed cells: numbers first (numerically), then text."""
    if isinstance(v, bool):
        v = int(v)
    if isinstance(v, (int, float)) and v == v:        # not NaN
        return (0, v, "")
    return (1, 0, "" if v is None else str(v).lower())


class FastSortProxy(QSortFilterProxyModel):
    """Sorts by reordering the source model's Python `rows` list ONCE per header
    click (one key per row) instead of QSortFilterProxyModel's n*log n lessThan
    -> data() round trips: a 54,071-row timeline took 16 s to open (the view's
    setSortingEnabled sorts immediately) and as long again per header click.
    The source model needs `rows` (list) and `sort_key(row, column)`. The proxy
    itself always stays in source order (internal sort column -1) and the last
    user sort is re-applied when the source model is reset."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._user_sort = (-1, Qt.AscendingOrder)

    def setSourceModel(self, m):
        super().setSourceModel(m)
        m.modelReset.connect(self._resort)

    def _resort(self):
        if self._user_sort[0] >= 0:
            self.sort(*self._user_sort)

    def sort(self, column, order=Qt.AscendingOrder):
        src = self.sourceModel()
        rows = getattr(src, "rows", None)
        if src is None or rows is None or not hasattr(src, "sort_key"):
            return super().sort(column, order)
        self._user_sort = (column, order)
        if column >= 0 and len(rows) > 1:
            src.layoutAboutToBeChanged.emit()
            pers = src.persistentIndexList()
            held = [(id(rows[ix.row()]), ix.column()) for ix in pers if 0 <= ix.row() < len(rows)]
            rows.sort(key=lambda r: _sort_norm(src.sort_key(r, column)),
                      reverse=(order == Qt.DescendingOrder))
            pos = {id(r): i for i, r in enumerate(rows)}
            src.changePersistentIndexList(
                [ix for ix in pers if 0 <= ix.row() < len(rows)],
                [src.index(pos[i], c) for i, c in held])
            src.layoutChanged.emit()
        super().sort(-1, Qt.AscendingOrder)     # (-1, Descending) would reverse the rows again


def helped(w: QWidget, key: str) -> QWidget:
    """Attach a help entry to a widget (property + hover tooltip)."""
    w.setProperty("help_key", key)
    if not w.toolTip():
        w.setToolTip(help_registry.tooltip(key))
    return w


class HelpPopup(QFrame):
    """Frameless rich-text help card shown next to a control."""
    _current = None

    def __init__(self, key: str, parent=None):
        super().__init__(parent, Qt.ToolTip | Qt.FramelessWindowHint)
        self.setObjectName("Panel")
        self.setAttribute(Qt.WA_DeleteOnClose)
        c = THEME
        self.setStyleSheet(f"QFrame#Panel{{background:{c['panel3']};border:1px solid {c['accent']};}}"
                           f"QTextBrowser{{background:transparent;border:none;color:{c['text']};}}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        tb = QTextBrowser()
        tb.setHtml(help_registry.html(key, c))
        tb.setOpenExternalLinks(False)
        tb.setFixedWidth(380)
        tb.document().setTextWidth(370)
        tb.setFixedHeight(int(tb.document().size().height()) + 8)
        tb.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        lay.addWidget(tb)
        hint = QLabel("Click anywhere or press Esc to close")
        hint.setObjectName("Muted")
        lay.addWidget(hint)

    @classmethod
    def show_for(cls, key: str, anchor: QWidget = None, pos: QPoint = None):
        if help_registry.guide(key):
            # in-depth guide (animations + long text): a non-modal window
            from gui.help_guide import GuideWindow
            return GuideWindow.show_for(key, anchor)
        if cls._current is not None:
            try:
                cls._current.close()
            except RuntimeError:
                pass
        p = cls(key)
        p.adjustSize()
        if pos is None:
            pos = anchor.mapToGlobal(QPoint(anchor.width() + 6, 0)) if anchor else QCursor.pos()
        scr = QApplication.screenAt(pos) or QApplication.primaryScreen()
        g = scr.availableGeometry()
        x = min(pos.x(), g.right() - p.width() - 8)
        y = min(pos.y(), g.bottom() - p.height() - 8)
        p.move(max(g.left(), x), max(g.top(), y))
        p.show()
        cls._current = p
        QApplication.instance().installEventFilter(_PopupCloser.get())
        return p


class _PopupCloser(QObject):
    _inst = None

    @classmethod
    def get(cls):
        if cls._inst is None:
            cls._inst = cls()
        return cls._inst

    def eventFilter(self, obj, ev):
        t = ev.type()
        if t in (QEvent.MouseButtonPress, QEvent.KeyPress) and HelpPopup._current is not None:
            if t == QEvent.KeyPress and ev.key() not in (Qt.Key_Escape,):
                return False
            try:
                HelpPopup._current.close()
            except RuntimeError:
                pass
            HelpPopup._current = None
            QApplication.instance().removeEventFilter(self)
        return False


class HelpButton(QToolButton):
    """Small '?' that opens the rich help card for `key`."""

    def __init__(self, key: str, parent=None):
        super().__init__(parent)
        self.key = key
        self.setObjectName("Help")
        self.setIcon(icons.icon("help", THEME.get("muted", "#8a95a5"), 14))
        self.setFixedSize(18, 18)
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(help_registry.tooltip(key))
        self.setProperty("help_key", key)
        self.setProperty("is_help_button", True)
        self.clicked.connect(lambda: HelpPopup.show_for(self.key, self))


def with_help(widget: QWidget, key: str, label: str = None, stretch: bool = True) -> QWidget:
    """[label] widget [?] in one row; the widget is tagged with `key`."""
    helped(widget, key)
    box = QWidget()
    lay = QHBoxLayout(box)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(6)
    if label:
        l = QLabel(label)
        l.setMinimumWidth(110)
        lay.addWidget(l)
    lay.addWidget(widget, 1 if stretch else 0)
    lay.addWidget(HelpButton(key))
    return box


class HelpMode(QObject):
    """While active, clicks on help-tagged widgets show help instead."""
    toggled = Signal(bool)

    def __init__(self):
        super().__init__()
        self.active = False

    def set_active(self, on: bool):
        self.active = on
        app = QApplication.instance()
        if on:
            app.installEventFilter(self)
            app.setOverrideCursor(Qt.WhatsThisCursor)
        else:
            app.removeEventFilter(self)
            app.restoreOverrideCursor()
        self.toggled.emit(on)

    def eventFilter(self, obj, ev):
        if ev.type() == QEvent.MouseButtonPress and isinstance(obj, QWidget):
            w = obj
            while w is not None:
                key = w.property("help_key")
                if key and not w.property("help_mode_switch"):
                    HelpPopup.show_for(key, pos=QCursor.pos() + QPoint(14, 10))
                    return True        # swallow: help mode never triggers actions
                if w.property("help_mode_switch"):
                    return False
                w = w.parentWidget()
        return False


class WheelGuard(QObject):
    """Hovering is not choosing: the mouse wheel over a drop-down, number box or
    slider scrolls the panel behind it and never changes the value.

    Qt's default gives the wheel (and keyboard focus) to whatever control is
    under the cursor, so scrolling down the Case setup panel changed Preset,
    Engine, Parallel jobs ... as they passed under the mouse. Values still change
    by clicking, typing, the arrow buttons or the keyboard; an OPEN drop-down list
    is a separate popup and still scrolls with the wheel.

    How: on Polish (once per control, before it is first shown) Qt's WheelFocus
    becomes StrongFocus, so the wheel no longer focuses it; on Wheel the event is
    marked ignored and filtered out, which makes QApplication pass the same real
    wheel event on to the parent widgets - the scroll area then scrolls."""
    GUARDED = (QComboBox, QAbstractSpinBox, QSlider)     # not QScrollBar: it must scroll
    _inst = None

    def eventFilter(self, obj, ev):
        t = ev.type()
        if t == QEvent.Wheel:
            if isinstance(obj, self.GUARDED):
                ev.ignore()
                return True
        elif t == QEvent.Polish:
            if isinstance(obj, self.GUARDED) and obj.focusPolicy() == Qt.WheelFocus:
                obj.setFocusPolicy(Qt.StrongFocus)
        return False


def install_wheel_guard() -> None:
    """Install the WheelGuard on the application once (idempotent)."""
    if WheelGuard._inst is None:
        WheelGuard._inst = WheelGuard()
        QApplication.instance().installEventFilter(WheelGuard._inst)


class Spinner(QWidget):
    """Tiny rotating arc, cheap to paint."""

    def __init__(self, size=14, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.angle = 0
        self.running = False
        self._t = QTimer(self)
        self._t.timeout.connect(self._tick)

    def start(self):
        self.running = True
        self._t.start(60)
        self.show()

    def stop(self):
        self.running = False
        self._t.stop()
        self.update()

    def _tick(self):
        self.angle = (self.angle + 30) % 360
        self.update()

    def paintEvent(self, _):
        if not self.running:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        pen = QPen(QColor(THEME.get("accent", "#3d8bfd")), 2)
        pen.setCapStyle(Qt.FlatCap)
        p.setPen(pen)
        r = self.rect().adjusted(2, 2, -2, -2)
        p.drawArc(r, -self.angle * 16, 270 * 16)


class StatTile(QFrame):
    """Number + caption block for summary rows."""

    def __init__(self, caption: str, value="-", parent=None):
        super().__init__(parent)
        self.setObjectName("Panel")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        self.v = QLabel(str(value))
        self.v.setObjectName("Stat")
        c = QLabel(caption)
        c.setObjectName("Muted")
        lay.addWidget(self.v)
        lay.addWidget(c)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

    def set(self, v):
        self.v.setText(str(v))
