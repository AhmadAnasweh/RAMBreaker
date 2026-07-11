"""extractor.py — OS-aware dispatcher for v6.

Loads extractor.windows.py / extractor.linux.py / extractor.mac.py
using importlib (dotted filenames can't be imported conventionally).

The factory function Extractor() returns an instance of the appropriate
OS-specific Extractor class. PLUGINS and VOL2_EXCLUSIVE are re-exported
from the windows variant for backward compatibility.
"""

import importlib.util
import pathlib

VALID_MODES = ("fast", "full", "malware", "network", "persistence", "registry")


def _load_os_module(os_type: str):
    """Load the OS-specific extractor module using importlib."""
    _DIR = pathlib.Path(__file__).parent
    _MAP = {'linux': 'extractor.linux', 'mac': 'extractor.mac'}
    name = _MAP.get(str(os_type).lower() if os_type else 'windows', 'extractor.windows')
    path = _DIR / (name + '.py')
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        # Fallback to windows if loading fails
        fallback_path = _DIR / 'extractor.windows.py'
        spec = importlib.util.spec_from_file_location('extractor.windows', fallback_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def Extractor(vol, logger, jobs: int = 4, speed: str = 'normal'):
    """Factory: load the OS-specific Extractor and return an instance."""
    os_type = getattr(vol, 'os_type', 'windows') or 'windows'
    mod = _load_os_module(os_type)
    return mod.Extractor(vol, logger, jobs, speed)


# Expose PLUGINS and VOL2_EXCLUSIVE from the windows variant for any
# legacy code that still does: from modules.extractor import PLUGINS
_win_mod = _load_os_module('windows')
PLUGINS = _win_mod.PLUGINS
VOL2_EXCLUSIVE = _win_mod.VOL2_EXCLUSIVE
