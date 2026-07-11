"""process_dumper.py — OS-aware dispatcher for v6.

Loads process_dumper.windows.py / process_dumper.linux.py / process_dumper.mac.py
using importlib (dotted filenames can't be imported conventionally).

The factory function ProcessDumper() returns an instance of the
appropriate OS-specific class.
"""

import importlib.util
import pathlib


def _load_os_module(os_type: str):
    _DIR = pathlib.Path(__file__).parent
    _MAP = {'linux': 'process_dumper.linux', 'mac': 'process_dumper.mac'}
    name = _MAP.get(str(os_type).lower() if os_type else 'windows',
                    'process_dumper.windows')
    path = _DIR / (name + '.py')
    try:
        if not path.exists():
            path = _DIR / 'process_dumper.windows.py'
            name = 'process_dumper.windows'
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        fallback = _DIR / 'process_dumper.windows.py'
        spec = importlib.util.spec_from_file_location('process_dumper.windows', fallback)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def ProcessDumper(vol, logger, jobs=4, timeout=120):
    """Factory: load the OS-specific ProcessDumper and return an instance."""
    os_type = getattr(vol, 'os_type', 'windows')
    mod = _load_os_module(os_type)
    return mod.ProcessDumper(vol, logger, jobs, timeout)
