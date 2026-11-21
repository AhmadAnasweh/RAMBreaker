"""Confirm box for the per-plugin retry button (RAMBreaker v2.3).

Shows what went wrong with the plugin, which skipped plugins will run with it,
which analysis steps are re-computed (the HTML report is always rebuilt), and
asks for the time limit: pre-filled with double the limit it was killed at
(or the calibrated limit for a failed plugin), with a "no time limit" option.
"""

from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QDialog, QFrame, QHBoxLayout, QLabel, QPushButton,
                               QSpinBox, QVBoxLayout)

from gui.widgets import helped, with_help
from modules import plugin_retry as pr

MAX_S = 7 * 86400


def _fmt(s: Optional[float]) -> str:
    if not s:
        return "-"
    s = int(s)
    if s < 120:
        return f"{s} s"
    if s < 7200:
        return f"{s // 60} min {s % 60:02d} s"
    return f"{s // 3600} h {(s % 3600) // 60:02d} min"


def _esc(t: str) -> str:
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class RetryDialog(QDialog):
    def __init__(self, row: Dict[str, Any], deps: List[str], steps: List[str],
                 expected_s: Optional[int], calibrated_s: Optional[int], queued: bool,
                 colors: Dict[str, str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Retry plugin")
        self.setMinimumWidth(560)
        p = row["plugin"]
        lay = QVBoxLayout(self)
        lay.setSpacing(8)
        h = QLabel(f"<b>Retry {_esc(p)}</b>")
        h.setObjectName("H2")
        h.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(h)
        st = row.get("state")
        if st == "timeout":
            what = f"It timed out: it was killed after {_fmt(row.get('last_limit_s'))}."
        elif st == "failed":
            what = f"It failed: {_esc(row.get('error') or 'see the log')}"
        elif st == "skipped":
            what = f"It was skipped because {_esc(row.get('parent') or 'a plugin it needs')} failed."
        else:
            what = "It did not run (the analysis was stopped, or the plugin was left out for this dump)."
        lw = QLabel(what)
        lw.setWordWrap(True)
        lay.addWidget(lw)
        if deps:
            dl = QLabel(f"<b>{len(deps)} plugin(s) were skipped because it failed; they run right after it:</b> "
                        + ", ".join(_esc(d) for d in deps))
            dl.setWordWrap(True)
            lay.addWidget(dl)
        # the warning the user asked for: the report is rebuilt, and what is re-computed
        box = QFrame()
        box.setObjectName("WarnBox")
        box.setStyleSheet(f"QFrame#WarnBox {{ border: 1px solid {colors.get('warn', '#d97706')}; }}")
        bl = QVBoxLayout(box)
        steps_txt = ", ".join(steps) if steps else "none (no analysis step reads this plugin)"
        w = QLabel(
            f"<b style='color:{colors.get('warn', '#d97706')}'>Warning: the whole HTML report will be "
            f"recreated.</b><br>After the retry, report.html is generated again from all results "
            f"(the current one is replaced). Analysis steps that read this plugin's output and are "
            f"re-computed: <b>{_esc(steps_txt)}</b>.<br>"
            f"Not redone: {_esc('; '.join(pr.NOT_REDONE))}.")
        w.setWordWrap(True)
        bl.addWidget(w)
        lay.addWidget(box)
        # time limit
        if st == "timeout" and row.get("last_limit_s"):
            pre = int(row["last_limit_s"]) * 2
            why = f"double the {_fmt(row['last_limit_s'])} it was killed at"
        else:
            pre = int(calibrated_s or 600)
            why = "the calibrated limit for this dump"
        pre = max(30, min(MAX_S, pre))
        self.limit = QSpinBox()
        self.limit.setRange(30, MAX_S)
        self.limit.setSingleStep(60)
        self.limit.setSuffix(" s")
        self.limit.setValue(pre)
        self.limit_txt = QLabel()
        self.limit.valueChanged.connect(lambda v: self.limit_txt.setText(f"= {_fmt(v)}  (pre-filled: {why})"))
        self.limit.valueChanged.emit(pre)
        r = QHBoxLayout()
        r.addWidget(with_help(self.limit, "retry.limit", "Time limit"))
        r.addWidget(self.limit_txt, 1)
        lay.addLayout(r)
        self.nolimit = QCheckBox("No time limit (runs until it finishes or you press Stop)")
        self.nolimit.toggled.connect(lambda on: self.limit.setEnabled(not on))
        lay.addWidget(with_help(self.nolimit, "retry.nolimit"))
        est = QLabel(f"Calibrated estimate for this plugin on this dump: ~{_fmt(expected_s)}."
                     + (" The plugins skipped because of it use their own calibrated limits." if deps else ""))
        est.setWordWrap(True)
        est.setObjectName("Muted")
        lay.addWidget(est)
        if queued:
            q = QLabel("An analysis is running now: this retry is <b>queued</b> and starts automatically "
                       "when it finishes (then the report is rebuilt once).")
            q.setWordWrap(True)
            lay.addWidget(q)
        b = QHBoxLayout()
        b.addStretch(1)
        self.ok = QPushButton("Queue retry" if queued else "Retry now")
        self.ok.setObjectName("Primary")
        helped(self.ok, "retry.ok")
        self.cancel = QPushButton("Cancel")
        helped(self.cancel, "retry.cancel")
        self.ok.clicked.connect(self.accept)
        self.cancel.clicked.connect(self.reject)
        b.addWidget(self.ok)
        b.addWidget(self.cancel)
        lay.addLayout(b)

    def timeout_s(self) -> int:
        """The chosen limit in seconds; 0 = no limit."""
        return 0 if self.nolimit.isChecked() else int(self.limit.value())
