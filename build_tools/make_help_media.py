"""Generate the animated help media (src/gui/help_media/*.gif) from the REAL GUI.

    runtime\\py3\\Scripts\\python.exe -X utf8 build_tools\\make_help_media.py --case <case dir> [--out DIR]

Drives MainWindow offscreen (QT_QPA_PLATFORM=offscreen), grabs widgets, and
annotates them with QPainter (spotlight, highlight boxes, numbered callouts,
arrows, a mouse pointer); Pillow assembles the GIFs (one palette per GIF, no
dithering, so flat UI colours stay crisp and small).

Privacy: the dump field always shows D:\\Cases\\memory.raw and the case is a
COPY (only the files the results view needs) named memory_raw in a temp
folder. The source case is only read. Never point --case at a case of a real
user machine.
"""

import argparse
import io
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_FONTDIR", os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
PROJECT = Path(__file__).resolve().parent.parent
SRC = PROJECT / "src"
sys.path.insert(0, str(SRC))

from PIL import Image  # noqa: E402
from PySide6.QtCore import QBuffer, QIODevice, QPoint, QPointF, QRect, QRectF, Qt  # noqa: E402
from PySide6.QtGui import (QBrush, QColor, QFont, QFontMetrics, QImage, QPainter,  # noqa: E402
                           QPainterPath, QPen, QPolygonF)
from PySide6.QtWidgets import QApplication  # noqa: E402

W, H, CAP = 640, 400, 46                 # canvas, caption band
DUMP = r"D:\Cases\memory.raw"
OUTDIR = r"D:\Cases\output"
SIZE_GB = 2.0
TI_SHOT = ""
AMBER = {"dark": "#f5a524", "light": "#c2410c"}

VOL2_FAST = {"cmdscan", "consoles", "hashdump", "clipboard", "iehistory"}
VOL2_SLOW = {"timers", "apihooks"}


def pump(sec=0.25):
    app = QApplication.instance()
    end = time.time() + sec
    while time.time() < end:
        app.processEvents()
        time.sleep(0.01)


# ═════════════════════════════════════════════════════════════ case copies
def make_case(src: Path, dst_root: Path, preset: str, mw) -> Path:
    """A copy of `src` holding only what `preset` would have produced."""
    from gui.main_window import plugin_list
    mode = {"standard": "full", "fulldfir": "full", "quick": "fast"}.get(preset, preset)
    core = preset != "quick"
    od = dst_root / preset / "memory_raw"
    if od.exists():
        shutil.rmtree(od)
    (od / "json").mkdir(parents=True)
    keep = {p.replace(".", "_") + ".json" for p in plugin_list("windows", "vol3", mode)}
    for f in (src / "json").glob("*.json"):
        n = f.name
        if n.startswith("windows_"):
            ok = n in keep
        elif n.endswith("_vol2.json"):
            v2 = n[:-len("_vol2.json")]
            ok = v2 in VOL2_FAST if mode == "fast" else (v2 not in VOL2_SLOW or preset == "fulldfir")
        elif n.startswith("_"):
            ok = False
        else:                                   # derived analysis files
            ok = core
            if n.startswith("injection_correlation"):
                ok = core and mode in ("full", "malware")
            if n.startswith("network_map"):
                ok = core and mode in ("full", "network")
        if ok:
            shutil.copy2(f, od / "json" / n)
    if core:
        for rel in ("iocs/ioc_results.json", "iocs/json/email_artifacts.json",
                    "iocs/json/browser_history.json", "sigma/sigma_results.json"):
            s = src / rel
            if s.is_file():
                (od / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(s, od / rel)
    rh = {}
    try:
        rh = json.loads((src / "run_health.json").read_text(encoding="utf-8"))
    except Exception:
        pass
    n_ok = len(list((od / "json").glob("windows_*.json"))) + len(list((od / "json").glob("*_vol2.json")))
    rh.update(mode=mode, plugins_ok=n_ok, plugins_failed=0, status="OK", banner=[])
    for k in ("image", "image_path", "dump", "output"):
        rh.pop(k, None)
    (od / "run_health.json").write_text(json.dumps(rh), encoding="utf-8")
    # minimal SUMMARY so the Extraction workspace knows the OS (no paths)
    (od / "SUMMARY.txt").write_text(
        f"Image: {DUMP}\nOS: windows\nEngine: vol3\nMode: {mode}\n", encoding="utf-8")
    return od


# ═══════════════════════════════════════════════════════════════ painting
class Mark:
    def __init__(self, rect: QRect, num=None, text=None, place="right", pad=3):
        self.rect, self.num, self.text, self.place, self.pad = QRect(rect), num, text, place, pad


def qimg_to_pil(img: QImage) -> Image.Image:
    buf = QBuffer()
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    return Image.open(io.BytesIO(bytes(buf.data()))).convert("RGB")


def widget_rect(w, widget, pad=0) -> QRect:
    tl = widget.mapTo(w, QPoint(0, 0))
    return QRect(tl.x() - pad, tl.y() - pad, widget.width() + 2 * pad, widget.height() + 2 * pad)


def union(*rects) -> QRect:
    r = QRect(rects[0])
    for x in rects[1:]:
        r = r.united(x)
    return r


def item_rect(w, tree, item) -> QRect:
    r = tree.visualItemRect(item)
    tl = tree.viewport().mapTo(w, r.topLeft())
    return QRect(tl.x(), tl.y(), min(r.width(), tree.viewport().width()), r.height())


def badge(p: QPainter, center: QPointF, n, color: QColor):
    p.setPen(QPen(QColor("#ffffff"), 1.5))
    p.setBrush(color)
    p.drawEllipse(center, 11, 11)
    f = QFont("Segoe UI", 9)
    f.setBold(True)
    p.setFont(f)
    p.setPen(QColor("#111111") if color.lightness() > 150 else QColor("#ffffff"))
    p.drawText(QRectF(center.x() - 11, center.y() - 11, 22, 22), Qt.AlignCenter, str(n))


def arrow(p: QPainter, a: QPointF, b: QPointF, color: QColor):
    p.setPen(QPen(color, 2))
    p.drawLine(a, b)
    import math
    ang = math.atan2(b.y() - a.y(), b.x() - a.x())
    s = 9
    pts = [b, QPointF(b.x() - s * math.cos(ang - 0.45), b.y() - s * math.sin(ang - 0.45)),
           QPointF(b.x() - s * math.cos(ang + 0.45), b.y() - s * math.sin(ang + 0.45))]
    p.setBrush(color)
    p.setPen(Qt.NoPen)
    p.drawPolygon(QPolygonF(pts))


def cursor(p: QPainter, at: QPointF):
    x, y = at.x(), at.y()
    pts = [(0, 0), (0, 17), (4.5, 13), (8, 20.5), (10.5, 19.5), (7, 12), (12.5, 12)]
    poly = QPolygonF([QPointF(x + dx, y + dy) for dx, dy in pts])
    p.setPen(QPen(QColor("#000000"), 1.2))
    p.setBrush(QColor("#ffffff"))
    p.drawPolygon(poly)


def compose(c: dict, theme: str, src: QImage, crop: QRect, marks, caption: str, step, title: str,
            layout="right", cursor_at: QPoint = None, overlay: tuple = None) -> QImage:
    """One annotated frame. `overlay` = (QImage, QPoint window pos) pasted over src first."""
    if overlay is not None:
        src = src.copy()
        pp = QPainter(src)
        pp.drawImage(overlay[1], overlay[0])
        pp.end()
    amber = QColor(AMBER[theme])
    img = QImage(W, H, QImage.Format_RGB32)
    img.fill(QColor(c["bg"]))
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    p.setRenderHint(QPainter.SmoothPixmapTransform)
    area = QRect(0, 0, W, H - CAP)
    gutter = 236 if layout == "right" else 0
    sc = min((area.width() - 28 - gutter) / crop.width(), (area.height() - 20) / crop.height(), 1.0)
    dw, dh = int(crop.width() * sc), int(crop.height() * sc)
    ox = 16 if layout == "right" else (W - dw) // 2
    oy = (area.height() - dh) // 2
    p.drawImage(QRect(ox, oy, dw, dh), src.copy(crop))
    p.setPen(QPen(QColor(c["border_hi"]), 1))
    p.setBrush(Qt.NoBrush)
    p.drawRect(QRect(ox, oy, dw, dh).adjusted(0, 0, -1, -1))
    shown = QRectF(ox, oy, dw, dh)

    def tr(r: QRect, pad=0) -> QRectF:
        q = QRectF(ox + (r.x() - crop.x()) * sc - pad, oy + (r.y() - crop.y()) * sc - pad,
                   r.width() * sc + 2 * pad, r.height() * sc + 2 * pad)
        return q.intersected(shown.adjusted(1, 1, -1, -1))

    # spotlight: dim everything except the marked rectangles
    if marks:
        path = QPainterPath()
        path.addRect(shown)
        hole = QPainterPath()
        for m in marks:
            hole.addRect(tr(m.rect, m.pad))
        p.fillPath(path.subtracted(hole), QColor(0, 0, 0, 125 if theme == "dark" else 100))
    for m in marks:
        p.setPen(QPen(amber, 2.2))
        p.setBrush(Qt.NoBrush)
        p.drawRect(tr(m.rect, m.pad))
    # callout boxes: right layout = in the gutter beside their mark; full
    # layout = stacked in the lower right (over the dimmed part of the picture)
    fbox = QFont("Segoe UI", 9)
    fm = QFontMetrics(fbox)
    boxes = []
    for m in marks:
        if not m.text:
            continue
        bw = (W - (ox + dw + 22) - 10) if layout == "right" else 280
        tw = bw - (40 if m.num is not None else 16)
        tb = fm.boundingRect(QRect(0, 0, int(tw), 400), Qt.TextWordWrap, m.text)
        boxes.append([m, bw, tw, max(30, tb.height() + 14)])
    if layout == "right":
        next_y = 8
        for bx_ in boxes:
            m, bw, tw, bh = bx_
            r = tr(m.rect, m.pad)
            by = max(next_y, r.center().y() - bh / 2)
            by = max(6, min(area.height() - bh - 6, by))
            next_y = by + bh + 8
            bx_.append(QRectF(ox + dw + 22, by, bw, bh))
    else:
        tot = sum(b[3] for b in boxes) + 8 * max(0, len(boxes) - 1)
        y = area.height() - tot - 12
        for bx_ in boxes:
            m, bw, tw, bh = bx_
            bx_.append(QRectF(W - bw - 14, y, bw, bh))
            y += bh + 8
    for m, bw, tw, bh, box in boxes:
        r = tr(m.rect, m.pad)
        p.setPen(QPen(amber, 1.4))
        p.setBrush(QColor(c["panel"]))
        p.drawRect(box)
        tx = box.x() + (32 if m.num is not None else 8)
        if m.num is not None:
            badge(p, QPointF(box.x() + 16, box.y() + bh / 2), m.num, amber)
        p.setFont(fbox)
        p.setPen(QColor(c["text"]))
        p.drawText(QRectF(tx, box.y() + 7, tw, bh - 14), Qt.TextWordWrap | Qt.AlignVCenter, m.text)
        # arrow from the box to the highlight
        if box.left() > r.right():
            a, b = QPointF(box.left(), box.center().y()), QPointF(r.right() + 3, r.center().y())
        elif box.right() < r.left():
            a, b = QPointF(box.right(), box.center().y()), QPointF(r.left() - 3, r.center().y())
        elif box.top() > r.bottom():
            x = max(box.left() + 20, min(box.right() - 20, r.center().x()))
            a, b = QPointF(x, box.top()), QPointF(x, r.bottom() + 3)
        elif box.bottom() < r.top():
            x = max(box.left() + 20, min(box.right() - 20, r.center().x()))
            a, b = QPointF(x, box.bottom()), QPointF(x, r.top() - 3)
        else:
            a = b = None
        if a is not None:
            arrow(p, a, b, amber)
    for m in marks:
        if m.num is not None:
            r = tr(m.rect, m.pad)
            badge(p, QPointF(max(12, r.left()), max(12, r.top())), m.num, amber)
    if cursor_at is not None:
        cursor(p, QPointF(ox + (cursor_at.x() - crop.x()) * sc, oy + (cursor_at.y() - crop.y()) * sc))
    # caption band
    p.fillRect(QRect(0, H - CAP, W, CAP), QColor(c["panel3"]))
    p.fillRect(QRect(0, H - CAP, 4, CAP), amber)
    f = QFont("Segoe UI", 8)
    f.setBold(True)
    p.setFont(f)
    p.setPen(amber)
    st = f"STEP {step[0]}/{step[1]}"
    p.drawText(QRect(14, H - CAP, 80, CAP), Qt.AlignVCenter | Qt.AlignLeft, st)
    f2 = QFont("Segoe UI", 10)
    f2.setBold(True)
    p.setFont(f2)
    p.setPen(QColor(c["text"]))
    p.drawText(QRect(86, H - CAP, W - 86 - 150, CAP), Qt.AlignVCenter | Qt.TextWordWrap, caption)
    f3 = QFont("Segoe UI", 8)
    p.setFont(f3)
    p.setPen(QColor(c["muted"]))
    p.drawText(QRect(W - 160, H - CAP, 150, CAP), Qt.AlignVCenter | Qt.AlignRight, title)
    p.end()
    return img


def save_gif(frames, durations, path: Path):
    pil = [qimg_to_pil(f) for f in frames]
    sheet = Image.new("RGB", (W, H * len(pil)))
    for i, im in enumerate(pil):
        sheet.paste(im, (0, i * H))
    pal = sheet.quantize(colors=96, method=Image.Quantize.MEDIANCUT)
    q = [im.quantize(palette=pal, dither=Image.Dither.NONE) for im in pil]
    q[0].save(path, save_all=True, append_images=q[1:], duration=durations, loop=0,
              optimize=True, disposal=1)
    return path.stat().st_size


# ═════════════════════════════════════════════════════════════════ driver
class Studio:
    def __init__(self, theme: str, cases: dict, out: Path):
        from gui import main_window as mw
        self.mw = mw
        self.theme = theme
        self.cases = cases
        self.out = out
        mw.load_settings = lambda: dict(mw.DEFAULT_SETTINGS, theme=theme, tour_on_start=False)
        mw.save_settings = lambda s: None
        w = mw.MainWindow()
        w.resize(1480, 1000)
        w.show()
        w.d_log.hide()
        pump(0.5)
        self.w = w
        self.c = w.c
        s = w.setup
        s.dump.setText(DUMP)
        s.out.setText(OUTDIR)
        s.estimate = lambda: mw.SetupPanel.estimate(s, SIZE_GB)
        pump(0.6)
        self.sizes = {}

    # -- grabbing helpers
    def grab(self) -> QImage:
        pump(0.15)
        return self.w.grab().toImage()

    def popup(self, combo, idx):
        """Open combo's list, select idx; return (image, window pos, item rect in window)."""
        combo.showPopup()
        pump(0.3)
        view = combo.view()
        cont = view.window()
        ix = view.model().index(idx, 0)
        view.setCurrentIndex(ix)
        pump(0.15)
        img = cont.grab().toImage()
        pos = cont.mapToGlobal(QPoint(0, 0)) - self.w.mapToGlobal(QPoint(0, 0))
        # offscreen: the popup may be placed anywhere; anchor it under the combo
        below = combo.mapTo(self.w, QPoint(0, combo.height()))
        if abs(pos.x() - below.x()) > 4 or pos.y() < 0 or pos.y() > self.w.height():
            pos = below
        vr = view.visualRect(ix)
        vtl = view.viewport().mapTo(cont, vr.topLeft())
        irect = QRect(pos.x() + vtl.x(), pos.y() + vtl.y(), vr.width(), vr.height())
        prect = QRect(pos, img.size())
        combo.hidePopup()
        pump(0.15)
        return img, pos, irect, prect

    def r(self, widget, pad=0):
        return widget_rect(self.w, widget, pad)

    def setup_crop(self, top_widget, bottom_widget, extra_bottom=6):
        s = self.w.setup
        a, b = self.r(top_widget), self.r(bottom_widget)
        x0 = self.r(s).x()
        return QRect(x0, a.y() - 14, s.width(), b.bottom() - a.y() + 14 + extra_bottom)

    def write(self, name, frames, durations):
        path = self.out / f"{name}_{self.theme}.gif"
        self.sizes[path.name] = save_gif(frames, durations, path)
        print(f"  {path.name}: {self.sizes[path.name] // 1024} KB, {len(frames)} frames")

    # -- results-view helpers
    def load_case(self, preset):
        w = self.w
        w.case = self.cases[preset]
        w.results.load(w.case)
        pump(0.6)
        return w.results

    def node(self, text_prefix):
        tree = self.w.results.tree
        it = tree.topLevelItem(0)
        stack = [it]
        while stack:
            x = stack.pop()
            if x.text(0).startswith(text_prefix):
                return x
            stack.extend(x.child(i) for i in range(x.childCount()))
        return None

    def open_node(self, text_prefix):
        it = self.node(text_prefix)
        if it is not None:
            self.w.results.tree.setCurrentItem(it)
            self.w.results._open_item(it, 0)
            pump(0.6)
        return it

    def results_crop(self, width=760, height=430):
        r = self.r(self.w.results)
        return QRect(r.x(), r.y(), min(width, r.width()), min(height, r.height()))

    def rows_rect(self, n=4):
        """First n rows of the table in the current results tab."""
        from PySide6.QtWidgets import QTableView
        tab = self.w.results.tabs.currentWidget()
        tv = tab.findChild(QTableView) if tab is not None else None
        if tv is None:
            return self.r(self.w.results.tabs)
        hdr = tv.horizontalHeader()
        rh = tv.verticalHeader().defaultSectionSize()
        tl = tv.viewport().mapTo(self.w, QPoint(0, 0))
        return QRect(tl.x(), tl.y() - hdr.height(), tv.viewport().width(), hdr.height() + n * rh)


def build_all(st: Studio, which=None):
    w, s, mw = st.w, st.w.setup, st.mw
    PR = [p[0] for p in mw.PRESETS]
    pidx = {"standard": 0, "quick": 1, "fulldfir": 2, "malware": 3, "network": 4,
            "persistence": 5, "registry": 6}
    titles = {"standard": "Standard", "quick": "Quick triage", "fulldfir": "Full DFIR",
              "malware": "Malware hunt", "network": "Network focus",
              "persistence": "Persistence focus", "registry": "Registry focus"}
    hidden_mon = False

    def setup_view():
        nonlocal hidden_mon
        if hidden_mon:
            w.d_mon.show()
            hidden_mon = False
        w.d_setup.show()
        w.resize(1480, 1000)
        pump(0.3)

    def results_view():
        nonlocal hidden_mon
        w.d_mon.hide()
        hidden_mon = True
        w.resize(1480, 520)          # results area ~ the crop: the tree scrolls like on a laptop
        pump(0.4)

    def est_count():
        t = s.est.text()
        return t.split(" for ")[-1].split(" on ")[0] if " for " in t else ""

    def est_time():
        t = s.est.text()
        return t.split("~")[1].split(" ")[0] if "~" in t else "?"

    # ── frames shared by presets and categories: "what you get"
    def result_frames(key, n0, step, title):
        frames = []
        results_view()
        st.load_case(key)
        tree = w.results.tree
        tree.collapseAll()
        tree.topLevelItem(0).setExpanded(True)
        for n in ("Findings", "Plugins") + (("IOCs",) if key == "standard" else ()):
            if st.node(n) is not None:
                st.node(n).setExpanded(True)
        pump(0.3)
        crop = st.results_crop()
        from PySide6.QtWidgets import QAbstractItemView

        def vis_union(items):
            vp = st.r(tree.viewport())
            out = QRect()
            for i in items:
                out = out.united(item_rect(w, tree, i).intersected(vp))
            return out
        if key == "standard":
            st.open_node("Summary")
            fnd, ioc = st.node("Findings"), st.node("IOCs")
            tiles = st.r(w.results.tabs.currentWidget())
            tiles = QRect(tiles.x(), tiles.y() + 34, tiles.width(), 150)
            img = st.grab()
            frames.append(compose(st.c, st.theme, img, crop, [
                Mark(union(item_rect(w, tree, fnd), item_rect(w, tree, fnd.child(fnd.childCount() - 1))),
                     n0, "Findings: Sigma hits, fileless injection, correlation, timeline", "below"),
                Mark(tiles, n0 + 1, "Summary: counts of processes, connections, IOCs, rule hits", "below"),
            ], "What you get: the complete case, every page filled", step, title, layout="full"))
        elif key == "quick":
            st.open_node("Processes")
            pl, fnd, ioc = st.node("Plugins"), st.node("Findings"), st.node("IOCs")
            img = st.grab()
            frames.append(compose(st.c, st.theme, img, crop, [
                Mark(item_rect(w, tree, pl), n0, f"{pl.text(0)}: one table per quick plugin", "right"),
                Mark(union(item_rect(w, tree, fnd), item_rect(w, tree, ioc)), n0 + 1,
                     "Findings and IOCs stay empty: no strings, IOC or Sigma step", "right"),
                Mark(item_rect(w, tree, st.node("Processes")), None, None),
                Mark(st.rows_rect(5), None, None),
            ], "What you get: processes, network and the plugin tables", step, title,
                layout="full"))
        elif key == "fulldfir":
            w.open_extract()
            xv = w.xview
            for _ in range(80):
                pump(0.25)
                if not xv._loaders:
                    break
            xv.dump.setText(DUMP)
            xv.dump.setStyleSheet("")
            xv.dest.setText(OUTDIR + r"\memory_raw\extracted")
            xv.tabs.setCurrentIndex(0)
            xv.f_search.setText("evtx")
            pump(0.8)
            img = st.grab()
            rr = st.r(xv.f_view)
            rows = QRect(rr.x(), rr.y(), rr.width(), min(rr.height(), 160))
            crop2 = QRect(st.r(w.results).x(), st.r(xv.f_search).y() - 40, 760, 420)
            frames.append(compose(st.c, st.theme, img, crop2, [
                Mark(st.r(xv.f_search, 2), n0, "The event logs held in this dump", "right"),
                Mark(rows, n0 + 1, "Full DFIR dumps every .evtx found here and parses it into the report",
                     "below"),
            ], "What you get: Standard + carved and parsed event logs", step, title,
                layout="full"))
        elif key == "malware":
            st.open_node("Fileless injection")
            it = st.node("Fileless injection")
            img = st.grab()
            frames.append(compose(st.c, st.theme, img, crop, [
                Mark(item_rect(w, tree, it), n0, "Injected code regions, graded HIGH / MEDIUM / LOW", "below"),
                Mark(st.rows_rect(4), None, None),
            ], "What you get: injection, hooks, drivers, hidden processes", step, title,
                layout="full"))
        elif key == "network":
            st.open_node("Network")
            it = st.node("Network")
            img = st.grab()
            frames.append(compose(st.c, st.theme, img, crop, [
                Mark(item_rect(w, tree, it), n0, "Connections and listening ports with the owning process",
                     "below"),
                Mark(st.rows_rect(5), None, None),
            ], "What you get: every connection and socket", step, title, layout="full"))
        elif key == "persistence":
            st.open_node("windows_svcscan")
            it, first = st.node("windows_svcscan"), st.node("windows_callbacks")
            tree.scrollToItem(it, QAbstractItemView.PositionAtBottom)
            pump(0.3)
            img = st.grab()
            frames.append(compose(st.c, st.theme, img, crop, [
                Mark(vis_union([first, it]), n0,
                     "Services, drivers, callbacks, SSDT, registry hives and UserAssist", "below"),
                Mark(st.rows_rect(4), None, None),
            ], "What you get: how something survives a reboot", step, title, layout="full"))
        elif key == "registry":
            st.open_node("windows_registry_userassist")
            first, last = st.node("windows_registry_hivelist"), st.node("windows_registry_userassist")
            tree.scrollToItem(last, QAbstractItemView.PositionAtBottom)
            pump(0.3)
            img = st.grab()
            frames.append(compose(st.c, st.theme, img, crop, [
                Mark(vis_union([first, last]), n0,
                     "Only the 4 registry plugins ran - there is no Processes page", "below"),
                Mark(st.rows_rect(4), None, None),
            ], "What you get: hives, keys and UserAssist", step, title, layout="full"))
        setup_view()
        return frames

    def preset_frames(key):
        title = titles[key]
        i = pidx[key]
        setup_view()
        s.preset.setCurrentIndex(0 if i else 1)
        pump(0.2)
        img = st.grab()
        pop, pos, irect, prect = st.popup(s.preset, i)
        crop = st.setup_crop(s.preset, s.est)
        f1 = compose(st.c, st.theme, img, crop, [
            Mark(irect, 1, f"Choose '{PR[i]}'", "right"),
        ], f"Open Preset and pick {title}", (1, 3), title, overlay=(pop, pos),
            cursor_at=QPoint(irect.x() + 60, irect.center().y()))
        s.preset.setCurrentIndex(i)
        pump(0.6)
        img = st.grab()
        fast = s.fast.isChecked()
        f2 = compose(st.c, st.theme, img, crop, [
            Mark(st.r(s.category.parentWidget()), 2,
                 f"Category: {s.category.currentText()}" + (" (locked)" if fast else ""), "right"),
            Mark(st.r(s.fast.parentWidget()), 3, "Fast mode: " + ("ON - quick plugin set" if fast else "off"),
                 "right"),
            Mark(st.r(s.est), 4, f"{est_count()}, about {est_time()} on a 2 GB dump", "right"),
        ], "The preset fills in the controls and the estimate", (2, 3), title)
        f3 = result_frames(key, 5, (3, 3), title)[0]
        # step counter of the last frame = 3/3 (badges continue at 5, 6)
        return [f1, f2, f3]

    def want(name):
        return which is None or name in which

    # ── preset overview
    if want("preset_overview"):
        setup_view()
        s.preset.setCurrentIndex(0)
        pump(0.3)
        img = st.grab()
        pop, pos, irect, prect = st.popup(s.preset, 1)
        crop = st.setup_crop(s.preset, s.start)
        f1 = compose(st.c, st.theme, img, crop, [
            Mark(prect, 1, "Open the Preset list: eight ready-made recipes", "right"),
        ], "Open the Preset list", (1, 4), "Presets", overlay=(pop, pos),
            cursor_at=QPoint(irect.x() + 60, irect.center().y()))
        s.preset.setCurrentIndex(1)
        pump(0.6)
        img = st.grab()
        f2 = compose(st.c, st.theme, img, crop, [
            Mark(st.r(s.preset.parentWidget()), 1, "Quick triage chosen", "right"),
            Mark(st.r(s.category.parentWidget()), None, None),
            Mark(union(st.r(s.fast.parentWidget()), st.r(s.fast_note)), 2,
                 "It set Fast mode ON and locked Category to 'All categories'", "right"),
        ], "The preset fills in Category and Fast mode", (2, 4), "Presets")
        f3 = compose(st.c, st.theme, img, crop, [
            Mark(st.r(s.est), 3, f"Estimate updates: {est_count()}, ~{est_time()}", "right"),
        ], "Check the estimated time", (3, 4), "Presets")
        s.preset.setCurrentIndex(0)
        pump(0.6)
        img = st.grab()
        f4 = compose(st.c, st.theme, img, crop, [
            Mark(st.r(s.preset.parentWidget()), None, None),
            Mark(st.r(s.est), None, None),
            Mark(st.r(s.start), 4, "Standard is right for most cases. Press Start.", "right"),
        ], "Press Start - the window stays usable while it runs", (4, 4), "Presets",
            cursor_at=QPoint(st.r(s.start).center().x(), st.r(s.start).center().y()))
        st.write("preset_overview", [f1, f2, f3, f4], [2600, 3000, 2600, 3400])

    # ── DFIR + Threat Intel (v2.2): preset -> options window -> report tab
    if want("preset_dfirti"):
        from gui.ti_dialog import ThreatIntelDialog
        i = len(PR) - 1
        title = "DFIR + Threat Intel"
        setup_view()
        s.preset.setCurrentIndex(0)
        pump(0.2)
        img = st.grab()
        pop, pos, irect, prect = st.popup(s.preset, i)
        crop = st.setup_crop(s.preset, s.est)
        f1 = compose(st.c, st.theme, img, crop, [
            Mark(irect, 1, "Choose 'DFIR + Threat Intel' and press Start", "right"),
        ], "Pick the preset, then Start", (1, 3), title, overlay=(pop, pos),
            cursor_at=QPoint(irect.x() + 60, irect.center().y()))
        d = ThreatIntelDialog(dict(w.s), "memory.raw", w)
        d.key.clear()
        d.remember.setChecked(False)
        d.resize(940, 820)
        d.show()
        pump(0.6)
        dimg = d.grab().toImage()

        def dr(x, pad=0):
            tl = x.mapTo(d, QPoint(0, 0))
            return QRect(tl.x() - pad, tl.y() - pad, x.width() + 2 * pad, x.height() + 2 * pad)
        f2 = compose(st.c, st.theme, dimg, QRect(0, 0, d.width(), d.height()), [
            Mark(dr(d.key.parentWidget()), 2, "Optional VirusTotal key (lookups only)", "right"),
            Mark(dr(d.yset.parentWidget()), 3, "YARA set + your own rules", "right"),
            Mark(dr(d.db.table), 4, "Database ages; Update is your choice", "right"),
            Mark(dr(d.go), 5, "Start", "right"),
        ], "Options: VirusTotal, YARA rules, threat-intel databases", (2, 3), title)
        d.close()
        frames = [f1, f2]
        if TI_SHOT and Path(TI_SHOT).is_file():
            rimg = QImage(str(TI_SHOT))
            top = min(150, rimg.height() - 10)
            rc = QRect(0, top, rimg.width(), min(rimg.height() - top, 860))
            f3 = compose(st.c, st.theme, rimg, rc, [
                Mark(QRect(36, 340, rimg.width() - 72, 90), 6, "Totals: hashed, YARA, feeds, VirusTotal",
                     "below"),
                Mark(QRect(26, 650, rimg.width() - 52, 345), 7, "Look here first: scored, with the reasons",
                     "above"),
            ], "Results: report.html > Threat Intelligence", (3, 3), title, layout="full")
            frames.append(f3)
        st.write("preset_dfirti", frames, [2600, 4200, 4600][:len(frames)])

    for key in ("standard", "quick", "fulldfir", "malware", "network", "persistence", "registry"):
        if want(f"preset_{key}"):
            fr = preset_frames(key)
            st.write(f"preset_{key}", fr, [2400, 3200, 4200])

    # ── categories
    cats = [("full", "All categories", "standard"), ("malware", "Malware", "malware"),
            ("network", "Network", "network"), ("persistence", "Persistence", "persistence"),
            ("registry", "Registry", "registry")]
    if want("category_overview"):
        setup_view()
        s.preset.setCurrentIndex(0)
        pump(0.3)
        img = st.grab()
        pop, pos, irect, prect = st.popup(s.category, 2)
        crop = st.setup_crop(s.preset, s.est)
        f1 = compose(st.c, st.theme, img, crop, [
            Mark(prect, 1, "Open Plugin category: everything, or one topic", "right"),
        ], "Pick WHAT the plugins look at", (1, 3), "Plugin category", overlay=(pop, pos),
            cursor_at=QPoint(irect.x() + 50, irect.center().y()))
        s.category.setCurrentIndex(2)
        pump(0.6)
        img = st.grab()
        f2 = compose(st.c, st.theme, img, crop, [
            Mark(st.r(s.category.parentWidget()), 2, "Network: only the network plugins", "right"),
            Mark(st.r(s.est), 3, f"{est_count()}, ~{est_time()} instead of the complete set", "right"),
        ], "Fewer plugins, shorter run", (2, 3), "Plugin category")
        s.fast.setChecked(True)
        pump(0.6)
        img = st.grab()
        f3 = compose(st.c, st.theme, img, crop, [
            Mark(st.r(s.fast.parentWidget()), 4, "Fast mode is the other control: HOW MUCH runs", "right"),
            Mark(st.r(s.category.parentWidget()), 5, "With Fast mode on, Category is locked to 'All categories'", "right"),
            Mark(st.r(s.fast_note), None, None),
        ], "Category and Fast mode are separate choices", (3, 3), "Plugin category",
            cursor_at=QPoint(st.r(s.fast).x() + 8, st.r(s.fast).center().y()))
        s.fast.setChecked(False)
        st.write("category_overview", [f1, f2, f3], [2600, 3000, 3600])

    for val, label, rkey in cats:
        name = f"category_{'all' if val == 'full' else val}"
        if not want(name):
            continue
        setup_view()
        s.preset.setCurrentIndex(0)
        pump(0.3)
        ci = s.category.findData(val)
        s.category.setCurrentIndex(0 if ci else 1)
        pump(0.2)
        img = st.grab()
        pop, pos, irect, prect = st.popup(s.category, ci)
        crop = st.setup_crop(s.preset, s.est)
        f1 = compose(st.c, st.theme, img, crop, [
            Mark(irect, 1, f"Choose '{label}'", "right"),
        ], f"Open Plugin category and pick {label}", (1, 3), "Plugin category", overlay=(pop, pos),
            cursor_at=QPoint(irect.x() + 50, irect.center().y()))
        s.category.setCurrentIndex(ci)
        pump(0.6)
        img = st.grab()
        f2 = compose(st.c, st.theme, img, crop, [
            Mark(st.r(s.category.parentWidget()), 2, f"Category: {label}", "right"),
            Mark(st.r(s.est), 3, f"{est_count()}, ~{est_time()} on a 2 GB dump", "right"),
        ], "The plugin list and the estimate change", (2, 3), "Plugin category")
        f3 = result_frames(rkey, 4, (3, 3), "Plugin category")[0]
        st.write(name, [f1, f2, f3], [2400, 3000, 4200])
        s.category.setCurrentIndex(0)

    # ── fast mode
    if want("fastmode"):
        setup_view()
        s.preset.setCurrentIndex(0)
        s.fast.setChecked(True)                 # crop sized for the taller layout (note shown)
        pump(0.6)
        crop = st.setup_crop(s.preset, s.est)
        s.fast.setChecked(False)
        pump(0.6)
        img = st.grab()
        f1 = compose(st.c, st.theme, img, crop, [
            Mark(st.r(s.fast.parentWidget()), 1, "Fast mode off: the complete set", "right"),
            Mark(st.r(s.est), 2, f"{est_count()}, ~{est_time()}", "right"),
        ], "Without Fast mode every plugin of the category runs", (1, 3), "Fast mode")
        s.fast.setChecked(True)
        pump(0.6)
        img = st.grab()
        f2 = compose(st.c, st.theme, img, crop, [
            Mark(st.r(s.fast.parentWidget()), 3, "Tick Fast mode", "right"),
            Mark(st.r(s.category.parentWidget()), 4, "Category locks to 'All categories'", "right"),
            Mark(st.r(s.fast_note), None, None),
            Mark(st.r(s.est), 5, f"{est_count()}, ~{est_time()}", "right"),
        ], "Quick plugin set: about a third of the plugins", (2, 3), "Fast mode",
            cursor_at=QPoint(st.r(s.fast).x() + 8, st.r(s.fast).center().y()))
        s.fast.setChecked(False)
        f3 = result_frames("quick", 6, (3, 3), "Fast mode")[0]
        st.write("fastmode", [f1, f2, f3], [2800, 3400, 4200])

    # ── RAM / jobs mode
    if want("speedmode"):
        setup_view()
        s.preset.setCurrentIndex(0)
        pump(0.3)
        img = st.grab()
        pop, pos, irect, prect = st.popup(s.speed, 0)
        crop = st.setup_crop(s.fast, s.ioc, 30)
        f1 = compose(st.c, st.theme, img, crop, [
            Mark(prect, 1, "normal / fast / fastest: how much RAM each job may use", "right"),
        ], "RAM / jobs mode: how hard the PC may work", (1, 3), "RAM / jobs mode", overlay=(pop, pos),
            cursor_at=QPoint(irect.x() + 50, irect.center().y()))
        img = st.grab()
        f2 = compose(st.c, st.theme, img, crop, [
            Mark(st.r(s.jobs.parentWidget()), 2, "Parallel jobs: plugins running at the same time", "right"),
            Mark(st.r(s.speed.parentWidget()), 3, "normal lowers jobs when RAM is short; fastest never does",
                 "right"),
            Mark(st.r(s.fast.parentWidget()), None, "Fast mode is different: it changes WHICH plugins run",
                 "right"),
        ], "It never changes which plugins run", (2, 3), "RAM / jobs mode")
        # run monitor with four parallel plugins (illustration fed through the real event handler)
        w.state = {"plugins": {}, "total": 0, "done": 0, "failed": 0, "timeouts": 0, "jobs": 4,
                   "expected": {}, "detect_done": True, "step": 1, "steps": 8, "size_gb": SIZE_GB,
                   "cmd": "core", "batch_t": time.time(), "running_since": {}}
        w.monitor.plugins.clear()
        pl = mw.plugin_list("windows", "vol3", "full")[:9]
        w._on_event({"ev": "batch", "plugins": pl, "jobs": 4,
                     "expected": {p: 20 + 7 * i for i, p in enumerate(pl)}, "eta_s": 420})
        for p, d in zip(pl[:3], (4, 11, 9)):
            w._on_event({"ev": "plugin", "plugin": p, "state": "running", "timeout_s": 300})
            w._on_event({"ev": "plugin", "plugin": p, "state": "done", "duration_s": d})
        for p in pl[3:7]:
            w._on_event({"ev": "plugin", "plugin": p, "state": "running", "timeout_s": 300})
        w.monitor.stage.setText("Running Volatility plugins...")
        pump(0.5)
        img = st.grab()
        tv = w.monitor.plugins
        r0 = item_rect(w, tv, tv.topLevelItem(3))
        r1 = item_rect(w, tv, tv.topLevelItem(6))
        running = QRect(st.r(tv).x(), r0.y(), st.r(tv).width(), r1.bottom() - r0.y())
        mcrop = QRect(st.r(w.monitor).x(), st.r(w.monitor.stage).y() - 8, st.r(w.monitor).width(),
                      st.r(tv).y() + 230 - st.r(w.monitor.stage).y())
        f3 = compose(st.c, st.theme, img, mcrop, [
            Mark(running, 4, "4 jobs = 4 plugins at once; each can take 1-2 GB of RAM", "right"),
        ], "Run monitor: the jobs at work", (3, 3), "RAM / jobs mode")
        w.monitor.plugins.clear()
        st.write("speedmode", [f1, f2, f3], [2800, 3600, 3600])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True, help="finished Windows case folder (read only)")
    ap.add_argument("--out", default=str(SRC / "gui" / "help_media"))
    ap.add_argument("--themes", default="dark,light")
    ap.add_argument("--only", default="", help="comma list of media names")
    ap.add_argument("--ti-shot", default="", help="PNG of a report's Threat Intelligence tab (preset_dfirti frame 3)")
    a = ap.parse_args()
    global TI_SHOT
    TI_SHOT = a.ti_shot
    src = Path(a.case)
    if "windows10_dmp" in src.name.lower():
        sys.exit("refusing: that case is a real user machine")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(sys.argv)
    from gui import main_window as mw
    tmp = Path(tempfile.mkdtemp(prefix="rb_help_media_"))
    try:
        cases = {k: make_case(src, tmp, k, mw) for k in
                 ("standard", "quick", "fulldfir", "malware", "network", "persistence", "registry")}
        sizes = {}
        for theme in a.themes.split(","):
            print(f"theme {theme}")
            st = Studio(theme, cases, out)
            build_all(st, set(a.only.split(",")) if a.only else None)
            sizes.update(st.sizes)
            st.w.close()
            pump(0.2)
        tot = sum(sizes.values())
        print(f"{len(sizes)} files, {tot // 1024} KB total")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
