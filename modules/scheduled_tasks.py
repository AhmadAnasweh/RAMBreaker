"""scheduled_tasks.py — OS-aware dispatcher for v6.

Loads scheduled_tasks.windows.py / scheduled_tasks.linux.py / scheduled_tasks.mac.py
using importlib (dotted filenames can't be imported conventionally).

The factory function ScheduledTasksScanner() returns an instance of
the appropriate OS-specific class.
"""

import importlib.util
import pathlib


def _load_os_module(os_type: str):
    """Load the OS-specific scheduled_tasks module using importlib."""
    _DIR = pathlib.Path(__file__).parent
    _MAP = {'linux': 'scheduled_tasks.linux', 'mac': 'scheduled_tasks.mac'}
    name = _MAP.get(str(os_type).lower() if os_type else 'windows', 'scheduled_tasks.windows')
    path = _DIR / (name + '.py')
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        # Fallback to windows
        fallback_path = _DIR / 'scheduled_tasks.windows.py'
        spec = importlib.util.spec_from_file_location('scheduled_tasks.windows', fallback_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def ScheduledTasksScanner(logger, os_type: str = 'windows'):
    """Factory: load the OS-specific ScheduledTasksScanner and return an instance."""
    mod = _load_os_module(os_type)
    return mod.ScheduledTasksScanner(logger)
