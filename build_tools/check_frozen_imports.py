"""Build check: every standard-library module that the GUI's app modules import must be
inside the frozen exe.

The exe excludes modules\\ and utils\\ (they are loaded at run time from app\\), so
PyInstaller never sees their imports. A stdlib module that only they use is missing
from the bundle, and the GUI dies at start (v2.2 build: secret_store -> ctypes.wintypes).

Usage: python check_frozen_imports.py <src dir> <PYZ-00.toc>  (PKG-00.toc and base_library.zip next to it are read too)
Exit 1 and list the missing modules (add them as --hidden-import in build.ps1).
"""

import ast
import sys
from pathlib import Path


def imports_of(py: Path):
    tree = ast.parse(py.read_text(encoding="utf-8"), str(py))
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                yield a.name
        elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
            yield n.module
            for a in n.names:                      # "from ctypes import wintypes" = a submodule
                yield f"{n.module}.{a.name}"


def main(src: Path, toc: Path) -> int:
    stdlib = set(sys.stdlib_module_names)
    text = toc.read_text(encoding="utf-8", errors="replace")
    pkg = toc.parent / "PKG-00.toc"                 # bootstrap modules (struct, ...) live in the PKG
    if pkg.is_file():
        text += " " + pkg.read_text(encoding="utf-8", errors="replace")
    bundled = set()
    for tok in text.replace("(", " ").replace(")", " ").replace(",", " ").split():
        tok = tok.strip("'\"")
        if tok and tok.replace(".", "").replace("_", "").isalnum():
            bundled.add(tok)
    bl = toc.parent / "base_library.zip"            # os, re, io ... live here, not in the PYZ
    if bl.is_file():
        import zipfile
        for n in zipfile.ZipFile(bl).namelist():
            if n.endswith(".pyc"):
                m = n[:-4].replace("/", ".")
                bundled.add(m[:-9] if m.endswith(".__init__") else m)
    # app modules the GUI reaches: start from gui\*.py, follow "modules.x" / "utils.x"
    todo = list((src / "gui").glob("*.py")) + [src / "rambreaker_gui.py"]
    seen, need = set(), {}
    while todo:
        py = todo.pop()
        if py in seen or not py.is_file():
            continue
        seen.add(py)
        frozen_side = py.parent.name == "gui" or py.name == "rambreaker_gui.py"
        for name in imports_of(py):
            top = name.split(".")[0]
            if top in ("modules", "utils"):
                parts = name.split(".")
                for k in range(2, len(parts) + 1):
                    cand = src.joinpath(*parts[:k]).with_suffix(".py")
                    if cand.is_file():
                        todo.append(cand)
                continue
            if top in stdlib and not frozen_side:
                need.setdefault(name, py.relative_to(src).as_posix())
    missing = {}
    for name, where in sorted(need.items()):
        if name in bundled or name in sys.builtin_module_names:
            continue
        parent = name.rsplit(".", 1)[0]
        if "." in name and parent in bundled and not _is_module(name):
            continue                                # "from os import path" style: an attribute
        if name.split(".")[0] in sys.builtin_module_names:
            continue
        missing[name] = where
    for name, where in missing.items():
        print(f"MISSING in the frozen exe: {name}  (imported by app\\{where})")
    print(f"frozen-import check: {len(need)} stdlib imports of {len(seen)} GUI-side files, {len(missing)} missing")
    return 1 if missing else 0


def _is_module(name: str) -> bool:
    import importlib.util
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError, AttributeError):
        return False


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
