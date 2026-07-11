"""html_report.py — OS-aware dispatcher for v6.

Loads html_report.windows.py / html_report.linux.py / html_report.mac.py
using importlib (dotted filenames can't be imported conventionally).

The factory function HTMLReportGenerator() returns an instance of the
appropriate OS-specific class. os_type defaults to None which falls
back to 'windows' (used by _cmd_report which has no vol context).
"""

import importlib.util
import pathlib


def _load_os_module(os_type: str):
    """Load the OS-specific html_report module using importlib."""
    _DIR = pathlib.Path(__file__).parent
    _MAP = {'linux': 'html_report.linux', 'mac': 'html_report.mac'}
    name = _MAP.get(str(os_type).lower() if os_type else 'windows', 'html_report.windows')
    path = _DIR / (name + '.py')
    try:
        if not path.exists():
            # Fallback to windows if requested variant doesn't exist
            path = _DIR / 'html_report.windows.py'
            name = 'html_report.windows'
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        # Fallback to windows
        fallback_path = _DIR / 'html_report.windows.py'
        spec = importlib.util.spec_from_file_location('html_report.windows', fallback_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def HTMLReportGenerator(logger, os_type: str = None):
    """Factory: load the OS-specific HTMLReportGenerator and return an instance."""
    mod = _load_os_module(os_type)
    return mod.HTMLReportGenerator(logger)
