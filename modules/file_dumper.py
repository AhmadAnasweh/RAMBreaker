"""file_dumper.py — OS-aware dispatcher for v6.

Loads file_dumper.windows.py / file_dumper.linux.py / file_dumper.mac.py
using importlib (dotted filenames can't be imported conventionally).

The factory function FileDumper() returns an instance of the
appropriate OS-specific class.
"""

import importlib.util
import pathlib


def _load_os_module(os_type: str):
    _DIR = pathlib.Path(__file__).parent
    _MAP = {'linux': 'file_dumper.linux', 'mac': 'file_dumper.mac'}
    name = _MAP.get(str(os_type).lower() if os_type else 'windows',
                    'file_dumper.windows')
    path = _DIR / (name + '.py')
    try:
        if not path.exists():
            path = _DIR / 'file_dumper.windows.py'
            name = 'file_dumper.windows'
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        fallback = _DIR / 'file_dumper.windows.py'
        spec = importlib.util.spec_from_file_location('file_dumper.windows', fallback)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def FileDumper(vol, logger, jobs=8, timeout=90):
    """Factory: load the OS-specific FileDumper and return an instance."""
    os_type = getattr(vol, 'os_type', 'windows')
    mod = _load_os_module(os_type)
    return mod.FileDumper(vol, logger, jobs, timeout)
