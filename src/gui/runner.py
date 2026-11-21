"""Runs the analysis as a child process and turns its output into signals.

The child is the normal command-line toolkit with RAMBREAKER_PROGRESS=1, so
the GUI and CLI share one code path. Lines starting with "@@RB " are JSON
progress events; all other lines are human log lines.
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QObject, QProcess, QProcessEnvironment, Signal

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def toolkit_argv() -> List[str]:
    """argv prefix that starts the analysis CLI.

    Packaged build: <exe dir>\\runtime\\py3\\python.exe runs <exe dir>\\app\\crescent_toolkit.py
    (portable CPython with every dependency). Source tree: the current interpreter."""
    if getattr(sys, "frozen", False):
        root = Path(sys.executable).resolve().parent
        # pythonw: GUI-subsystem interpreter, so no console window appears;
        # stdout/stderr still flow through QProcess's pipes.
        py = root / "runtime" / "py3" / "pythonw.exe"
        if not py.is_file():
            py = root / "runtime" / "py3" / "python.exe"
        return [str(py), "-X", "utf8", str(root / "app" / "crescent_toolkit.py")]
    src = Path(__file__).resolve().parent.parent
    return [sys.executable, "-X", "utf8", str(src / "crescent_toolkit.py")]


def classify(line: str) -> str:
    s = line.lstrip()
    if s.startswith("[x]") or " [ERROR]" in s or " [CRITICAL]" in s or "Traceback" in s:
        return "error"
    if s.startswith("[!]") or " [WARNING]" in s:
        return "warn"
    if s.startswith("[+]"):
        return "ok"
    return "info"


class AnalysisRunner(QObject):
    event = Signal(dict)             # parsed @@RB event
    log_line = Signal(str, str)      # (level, text)
    finished = Signal(int, bool)     # exit code, was_stopped
    started = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.proc: Optional[QProcess] = None
        self._buf = b""
        self._stopped = False
        self.last_activity = time.time()
        self.cmdline: List[str] = []

    def running(self) -> bool:
        return self.proc is not None and self.proc.state() != QProcess.NotRunning

    def start(self, args: List[str], cwd: Optional[str] = None, extra_env: Optional[dict] = None):
        """extra_env: variables for the child only (e.g. the VirusTotal key, which must
        never appear on the command line or in the log)."""
        if self.running():
            return
        argv = toolkit_argv() + args
        self.cmdline = argv
        self.proc = QProcess(self)
        env = QProcessEnvironment.systemEnvironment()
        env.insert("RAMBREAKER_PROGRESS", "1")
        env.insert("PYTHONUTF8", "1")
        env.insert("PYTHONIOENCODING", "utf-8")
        env.insert("PYTHONUNBUFFERED", "1")
        env.insert("RAMBREAKER_NO_REEXEC", "1")
        env.insert("NO_COLOR", "1")
        self.proc.setProcessEnvironment(env)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        env.insert("RAMBREAKER_NO_WINDOW", "1")   # child adds CREATE_NO_WINDOW to its tools
        for k, v in (extra_env or {}).items():
            if v:
                env.insert(k, str(v))
        self.proc.setProcessEnvironment(env)
        self.proc.errorOccurred.connect(self._error)
        if cwd:
            self.proc.setWorkingDirectory(cwd)
        self.proc.readyReadStandardOutput.connect(self._read)
        self.proc.finished.connect(self._done)
        self._buf = b""
        self._stopped = False
        self.last_activity = time.time()
        self.proc.start(argv[0], argv[1:])
        self.started.emit(argv)

    def stop(self):
        if not self.running():
            return
        self._stopped = True
        pid = self.proc.processId()
        if os.name == "nt" and pid:
            # kill the whole tree: vol.py children would otherwise survive
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                           capture_output=True, creationflags=0x08000000)
        else:
            self.proc.kill()

    def _read(self):
        self._buf += bytes(self.proc.readAllStandardOutput())
        *lines, self._buf = self._buf.split(b"\n")
        for raw in lines:
            self.last_activity = time.time()
            line = ANSI.sub("", raw.decode("utf-8", "replace").rstrip("\r"))
            if line.startswith("@@RB "):
                try:
                    self.event.emit(json.loads(line[5:]))
                except Exception:
                    pass
                continue
            if line.strip():
                self.log_line.emit(classify(line), line)

    def _error(self, err):
        if err == QProcess.FailedToStart:
            self.log_line.emit("error", f"Could not start the analysis process: "
                                        f"{self.proc.errorString()} ({' '.join(self.cmdline[:2])})")
            self.finished.emit(-1, False)

    def _done(self, code, _status):
        if self._buf:
            self._buf += b"\n"
            self._read()
        self.finished.emit(int(code), self._stopped)
