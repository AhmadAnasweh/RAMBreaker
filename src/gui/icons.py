"""Bundled Lucide SVG icons (ISC licence, see icons/LICENSE-lucide.txt),
recoloured at load time so they follow the active theme."""

import sys
from pathlib import Path
from typing import Dict, Tuple

from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer


def _icon_dir() -> Path:
    base = Path(getattr(sys, "_MEIPASS", "")) / "gui" / "icons"
    if base.is_dir():
        return base
    return Path(__file__).resolve().parent / "icons"


ALIASES = {
    "help": "circle-question-mark", "warn": "triangle-exclamation-point",
    "alert": "circle-exclamation-point", "ok": "circle-check", "fail": "circle-x",
    "spinner": "loader-circle", "stop": "square", "open": "folder-open",
    "filter": "funnel", "sigma": "shield-exclamation-point", "ioc": "crosshair",
    "email": "mail", "process": "list-tree", "plugin": "box", "timeline": "clock",
    "registry": "database", "report": "file-text", "dump": "memory-stick",
    "case": "folder-tree", "finding": "flag", "glossary": "book-open",
    "tour": "graduation-cap", "theme": "sun", "log": "scroll-text",
    "network": "network", "symbols": "binary", "strings": "file-search",
    "queued": "circle", "running": "loader-circle", "timeout": "hourglass",
}

_cache: Dict[Tuple[str, str, int], QIcon] = {}


def svg_bytes(name: str, color: str) -> bytes:
    name = ALIASES.get(name, name)
    p = _icon_dir() / f"{name}.svg"
    if not p.is_file():
        p = _icon_dir() / "circle.svg"
    return p.read_text(encoding="utf-8").replace("currentColor", color).encode()


def pixmap(name: str, color: str, size: int = 16) -> QPixmap:
    r = QSvgRenderer(QByteArray(svg_bytes(name, color)))
    pm = QPixmap(QSize(size, size) * 2)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    r.render(p)
    p.end()
    pm.setDevicePixelRatio(2.0)
    return pm


def icon(name: str, color: str, size: int = 16) -> QIcon:
    key = (name, color, size)
    if key not in _cache:
        _cache[key] = QIcon(pixmap(name, color, size))
    return _cache[key]


def clear_cache() -> None:
    _cache.clear()
