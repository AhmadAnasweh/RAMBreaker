"""correlator.py — OS-aware dispatcher for v6.

Loads correlator.windows.py / correlator.linux.py / correlator.mac.py
using importlib (dotted filenames can't be imported conventionally).

The factory function Correlator() returns an instance of the
appropriate OS-specific class.  os_type defaults to 'windows' so
existing call-sites that don't pass os_type keep working.
"""

import importlib.util
import logging
import pathlib


def _load_os_module(os_type: str):
    _DIR = pathlib.Path(__file__).parent
    _MAP = {"linux": "correlator.linux", "mac": "correlator.mac"}
    name = _MAP.get(str(os_type).lower() if os_type else "windows",
                    "correlator.windows")
    path = _DIR / (name + ".py")
    if not path.exists():
        path = _DIR / "correlator.windows.py"
        name = "correlator.windows"
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def Correlator(logger: logging.Logger, os_type: str = "windows"):
    """Factory: load the OS-specific correlator and return a Correlator instance."""
    mod = _load_os_module(os_type)
    return mod.Correlator(logger)
