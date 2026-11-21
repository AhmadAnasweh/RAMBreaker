"""Automated check: every interactive widget has a valid help entry."""

from PySide6.QtWidgets import (QAbstractButton, QAbstractItemView, QAbstractSpinBox, QComboBox,
                               QDockWidget, QHeaderView, QLineEdit, QMenu, QScrollBar, QTabBar,
                               QTabWidget, QTextEdit, QToolBar, QWidget, QPlainTextEdit)

from gui import help_registry

INTERACTIVE = (QAbstractButton, QLineEdit, QComboBox, QAbstractSpinBox, QAbstractItemView,
               QTextEdit, QPlainTextEdit, QTabBar)
# children Qt creates inside composite widgets: covered by the parent's help
COMPOSITE = (QComboBox, QAbstractSpinBox, QAbstractItemView, QTabWidget, QLineEdit,
             QDockWidget, QToolBar, QTextEdit, QPlainTextEdit)


def _key_of(w: QWidget):
    p = w
    while p is not None:
        k = p.property("help_key")
        if k:
            return k, p
        p = p.parentWidget()
    return None, None


def check(root: QWidget):
    missing, invalid, ok = [], [], 0
    for w in root.findChildren(QWidget):
        if not isinstance(w, INTERACTIVE) or isinstance(w, (QScrollBar, QHeaderView, QMenu)):
            continue
        own = w.property("help_key")
        if own:
            if help_registry.get(own) is None:
                invalid.append((w.metaObject().className(), w.objectName(), own))
            else:
                ok += 1
            continue
        par = w.parentWidget()
        internal = False
        while par is not None and par is not root:
            if isinstance(par, COMPOSITE):
                internal = True
                break
            par = par.parentWidget()
        k, holder = _key_of(w)
        if internal and k:
            ok += 1
            continue
        if isinstance(w, QTabBar) and isinstance(w.parentWidget(), QTabWidget) and \
                w.parentWidget().property("help_key"):
            ok += 1
            continue
        txt = getattr(w, "text", lambda: "")() if hasattr(w, "text") else ""
        missing.append((w.metaObject().className(), w.objectName(), str(txt)[:40]))
    return {"ok": ok, "missing": missing, "invalid": invalid}
