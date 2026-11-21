"""Render the RAMBreaker app icon (multi-size .ico with PNG entries)."""

import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QRectF, Qt
from PySide6.QtGui import QColor, QGuiApplication, QImage, QPainter, QPen


def render(size: int) -> bytes:
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing, True)
    s = size / 64.0
    p.fillRect(QRectF(0, 0, size, size), QColor("#0e1116"))
    p.setPen(QPen(QColor("#3d8bfd"), max(1.0, 2 * s)))
    p.drawRect(QRectF(1 * s, 1 * s, 62 * s, 62 * s))
    # DIMM body
    body = QRectF(8 * s, 18 * s, 48 * s, 24 * s)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor("#1d3b66"))
    p.drawRect(body)
    # chips
    p.setBrush(QColor("#3d8bfd"))
    for i in range(4):
        p.drawRect(QRectF((11 + i * 11.5) * s, 22 * s, 8 * s, 12 * s))
    # gold contacts with a notch
    p.setBrush(QColor("#d6a01d"))
    x = 10.0
    while x < 54:
        if not (30 <= x <= 33):
            p.drawRect(QRectF(x * s, 44 * s, 2.2 * s, 6 * s))
        x += 4
    # "break" slash
    p.setPen(QPen(QColor("#f0524a"), max(1.5, 3 * s)))
    p.drawLine(int(44 * s), int(10 * s), int(54 * s), int(56 * s))
    p.end()
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    return bytes(ba)


def main(out: Path):
    app = QGuiApplication(sys.argv)  # noqa: F841
    sizes = [16, 24, 32, 48, 64, 128, 256]
    pngs = [render(s) for s in sizes]
    hdr = struct.pack("<HHH", 0, 1, len(sizes))
    off = 6 + 16 * len(sizes)
    dirs = b""
    for s, data in zip(sizes, pngs):
        dirs += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), off)
        off += len(data)
    out.write_bytes(hdr + dirs + b"".join(pngs))
    (out.with_suffix(".png")).write_bytes(pngs[-1])
    print("wrote", out, out.stat().st_size)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
