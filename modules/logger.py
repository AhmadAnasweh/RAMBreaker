"""CresCent RAM Forensics Toolkit v4.0 - Centralized Logging Service"""

import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

VERSION = "4.0"


class _ConsoleFormatter(logging.Formatter):
    _MAP = {
        logging.DEBUG: "   [D] ", logging.INFO: "   [+] ",
        logging.WARNING: "   [!] ", logging.ERROR: "   [x] ",
        logging.CRITICAL: "   [X] ",
    }
    def format(self, record):
        return f"{self._MAP.get(record.levelno, '   [?] ')}{record.getMessage()}"


class CrescentLogger:
    """Centralized logging. Writes ALL output to crescent_toolkit.log.
    Format: [HH:MM:SS] [MODULE] [LEVEL] message
    """
    def __init__(self, output_dir, quiet=False, log_path=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.quiet = quiet
        self.log_file = Path(log_path) if log_path else self.output_dir / "crescent_toolkit.log"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._root = logging.getLogger("crescent")
        self._root.setLevel(logging.DEBUG)
        self._root.handlers.clear()
        fh = logging.FileHandler(str(self.log_file), mode="a", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
        self._root.addHandler(fh)
        if not self.quiet:
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.INFO)
            ch.setFormatter(_ConsoleFormatter())
            self._root.addHandler(ch)
        self._write_header()

    def get_logger(self, name):
        return self._root.getChild(name)

    def log_command(self, logger, cmd, returncode, stdout, stderr, duration):
        logger.debug("Command: %s", cmd)
        logger.debug("Exit code: %d, Duration: %.2fs", returncode, duration)
        if returncode != 0:
            logger.error("Command failed (rc=%d): %s", returncode,
                         (stderr[:1000] if stderr else "(no stderr)"))
        if stdout:
            logger.debug("Output size: %d bytes", len(stdout))

    def log_session_info(self, image, output, vol_version="", profile="", mode=""):
        log = self.get_logger("MAIN")
        log.info("Image:   %s", image); log.info("Output:  %s", output)
        if vol_version: log.info("Engine:  %s", vol_version)
        if profile: log.info("Profile: %s", profile)
        if mode: log.info("Mode:    %s", mode)

    def _write_header(self):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"  CresCent RAM Forensics Toolkit v{VERSION}\n")
            f.write(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")


class Timer:
    def __init__(self):
        self._start = 0.0; self._end = 0.0
    def start(self):
        self._start = time.time(); return self
    def stop(self):
        self._end = time.time(); return self.elapsed
    @property
    def elapsed(self):
        return (self._end if self._end else time.time()) - self._start
    def __enter__(self):
        self.start(); return self
    def __exit__(self, *a):
        self.stop()
