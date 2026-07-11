"""evtx_parser.py — thin re-export from evtx_parser.windows.py (v6 dispatcher)

EVTX parsing is Windows-only. This dispatcher loads the windows variant.
"""
import importlib.util
import pathlib


def _load():
    _DIR = pathlib.Path(__file__).parent
    path = _DIR / 'evtx_parser.windows.py'
    try:
        spec = importlib.util.spec_from_file_location('evtx_parser.windows', path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception as e:
        raise ImportError(f"Failed to load evtx_parser.windows: {e}") from e


_mod = _load()
EVTXParser = _mod.EVTXParser
