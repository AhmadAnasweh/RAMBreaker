"""popular_files.py — OS-aware dispatcher for v6.

Loads popular_files.windows.py / popular_files.linux.py / popular_files.mac.py
using importlib (dotted filenames can't be imported conventionally).

The factory function PopularFilesScanner() returns an instance of
the appropriate OS-specific class.
"""

import importlib.util
import pathlib


def _load_os_module(os_type: str):
    """Load the OS-specific popular_files module using importlib."""
    _DIR = pathlib.Path(__file__).parent
    _MAP = {'linux': 'popular_files.linux', 'mac': 'popular_files.mac'}
    name = _MAP.get(str(os_type).lower() if os_type else 'windows', 'popular_files.windows')
    path = _DIR / (name + '.py')
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        # Fallback to windows
        fallback_path = _DIR / 'popular_files.windows.py'
        spec = importlib.util.spec_from_file_location('popular_files.windows', fallback_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def PopularFilesScanner(logger, os_type: str = 'windows'):
    """Factory: load the OS-specific PopularFilesScanner and return an instance."""
    mod = _load_os_module(os_type)
    return mod.PopularFilesScanner(logger)
