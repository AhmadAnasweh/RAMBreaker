"""linux_resolver.py — OS-aware dispatcher for v6.

Loads linux_resolver.linux.py or linux_resolver.mac.py using importlib
(dotted filenames can't be imported conventionally).

The resolve_symbols() function signature is unchanged from v5:
    resolve_symbols(image, os_type, output_dir=None)

Callers in crescent_toolkit.py do:
    from modules.linux_resolver import resolve_symbols
    resolve_symbols(image, vol.os_type, output_dir=od)
"""

import importlib.util
import pathlib
from typing import Optional


def _load_os_module(os_type: str):
    """Load the OS-specific linux_resolver module using importlib."""
    _DIR = pathlib.Path(__file__).parent
    name = 'linux_resolver.mac' if str(os_type).lower() == 'mac' else 'linux_resolver.linux'
    path = _DIR / (name + '.py')
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        # Fallback to linux
        fallback_path = _DIR / 'linux_resolver.linux.py'
        spec = importlib.util.spec_from_file_location('linux_resolver.linux', fallback_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def resolve_symbols(image: str, os_type: str = 'linux',
                    output_dir=None) -> bool:
    """Dispatcher: load the OS-specific resolver and call resolve_symbols().

    Signature matches the v5 API exactly so crescent_toolkit.py needs no changes.
    """
    mod = _load_os_module(os_type)
    return mod.resolve_symbols(image, os_type, output_dir=output_dir)
