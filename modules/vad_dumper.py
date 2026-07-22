"""vad_dumper.py — OS-aware dispatcher for the VAD / memory-region dumper (v6.1).

Loads vad_dumper.windows.py / vad_dumper.linux.py / vad_dumper.mac.py via importlib
(dotted filenames can't be imported conventionally) and returns an instance of the
right OS-specific VADDumper.

VAD (Virtual Address Descriptor) dumping recovers each of a process's committed
memory regions — heaps, stacks, mapped data, and injected code — NOT just its PE
image, which is what the plain process dumper writes. On Linux/macOS the equivalent
is the process memory map (proc.Maps / proc_maps).
"""

import importlib.util
import pathlib


def _load_os_module(os_type: str):
    _DIR = pathlib.Path(__file__).parent
    _MAP = {'linux': 'vad_dumper.linux', 'mac': 'vad_dumper.mac'}
    name = _MAP.get(str(os_type).lower() if os_type else 'windows',
                    'vad_dumper.windows')
    path = _DIR / (name + '.py')
    try:
        if not path.exists():
            path = _DIR / 'vad_dumper.windows.py'
            name = 'vad_dumper.windows'
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        fallback = _DIR / 'vad_dumper.windows.py'
        spec = importlib.util.spec_from_file_location('vad_dumper.windows', fallback)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def VADDumper(vol, logger, jobs=4, timeout=300):
    """Factory: load the OS-specific VADDumper and return an instance."""
    os_type = getattr(vol, 'os_type', 'windows')
    mod = _load_os_module(os_type)
    return mod.VADDumper(vol, logger, jobs, timeout)
