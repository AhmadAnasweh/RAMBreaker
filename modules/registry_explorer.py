"""registry_explorer.py — thin re-export from registry_explorer.windows.py (v6 dispatcher)

Registry analysis is Windows-only. This dispatcher loads the windows variant.
"""
import importlib.util
import pathlib


def _load():
    _DIR = pathlib.Path(__file__).parent
    path = _DIR / 'registry_explorer.windows.py'
    try:
        spec = importlib.util.spec_from_file_location('registry_explorer.windows', path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception as e:
        raise ImportError(f"Failed to load registry_explorer.windows: {e}") from e


_mod = _load()
RegistryExplorer = _mod.RegistryExplorer
PERSISTENCE_KEYS = _mod.PERSISTENCE_KEYS
