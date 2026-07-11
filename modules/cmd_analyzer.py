"""cmd_analyzer.py — OS-aware dispatcher for v6.

Loads cmd_analyzer.windows.py / cmd_analyzer.linux.py / cmd_analyzer.mac.py
using importlib (dotted filenames can't be imported conventionally).

Factory functions CommandAnalyzer() and MitreMapper() return instances of
the appropriate OS-specific classes.
"""

import importlib.util
import pathlib


def _load_os_module(os_type: str):
    """Load the OS-specific cmd_analyzer module using importlib."""
    _DIR = pathlib.Path(__file__).parent
    _MAP = {'linux': 'cmd_analyzer.linux', 'mac': 'cmd_analyzer.mac'}
    name = _MAP.get(str(os_type).lower() if os_type else 'windows', 'cmd_analyzer.windows')
    path = _DIR / (name + '.py')
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        # Fallback to windows
        fallback_path = _DIR / 'cmd_analyzer.windows.py'
        spec = importlib.util.spec_from_file_location('cmd_analyzer.windows', fallback_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def CommandAnalyzer(logger, os_type: str = 'windows'):
    """Factory: load the OS-specific CommandAnalyzer and return an instance."""
    mod = _load_os_module(os_type)
    return mod.CommandAnalyzer(logger)


def MitreMapper(logger, os_type: str = 'windows'):
    """Factory: load the OS-specific MitreMapper and return an instance."""
    mod = _load_os_module(os_type)
    return mod.MitreMapper(logger)


# Re-export MITRE_TECHNIQUES from windows variant for backward compat
_win_mod = _load_os_module('windows')
MITRE_TECHNIQUES = _win_mod.MITRE_TECHNIQUES
