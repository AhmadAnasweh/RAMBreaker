"""
Central workspace / scratch-directory configuration.

The default system temp dir (/tmp) is frequently a small tmpfs (5 GB on this
box), far too small for the Linux ISF build pipeline which needs to stage a
~1 GB .ddeb + ~730 MB extracted vmlinux + the emitted JSON. We therefore route
ALL scratch to a large on-disk workspace (the user's Desktop by default) and
point tempfile/TMPDIR at it so every `tempfile.mkdtemp()` across every module
lands there automatically — no per-call plumbing required.

Override the base with the CRESCENT_WORK env var. Results dir with CRESCENT_RESULTS.
"""
import os
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Base locations (env-overridable).
# Default lives INSIDE the toolkit directory (parent of this modules/ package)
# so the work + results dirs travel with the tool and don't clutter the Desktop
# next to it. The old default put them at ~/Desktop level; that was only to avoid
# the small /tmp tmpfs, and the toolkit dir is on the same big partition, so
# nesting them here keeps the space benefit without the loose top-level folders.
# Override with CRESCENT_WORK / CRESCENT_RESULTS to place them elsewhere (e.g. a
# separate large disk).
# ---------------------------------------------------------------------------
def _default_base() -> Path:
    # modules/workspace.py -> parent (modules) -> parent (toolkit root)
    toolkit_root = Path(__file__).resolve().parent.parent
    return toolkit_root / "CresCentC_work"


WORK_BASE = Path(os.environ.get("CRESCENT_WORK", str(_default_base())))
RESULTS_BASE = Path(os.environ.get(
    "CRESCENT_RESULTS",
    str(WORK_BASE.parent / "CresCentC_RESULTS")))

# Sub-directories used across the toolkit.
SCRATCH_DIR = WORK_BASE / "scratch"      # generic mkdtemp target (TMPDIR)
CACHE_DIR = WORK_BASE / "cache"          # misc caches (symbol catalogue, etc.)
DDEB_CACHE_DIR = WORK_BASE / "ddeb_cache"  # downloaded debug packages (reused)
ISF_BUILD_DIR = WORK_BASE / "isf_build"  # built ISFs before install
IMAGES_DIR = WORK_BASE / "images"        # local copies of RAM images

_ALL_DIRS = (WORK_BASE, RESULTS_BASE, SCRATCH_DIR, CACHE_DIR,
             DDEB_CACHE_DIR, ISF_BUILD_DIR, IMAGES_DIR)

_INITIALISED = False


def ensure_dirs() -> None:
    for d in _ALL_DIRS:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass


def setup(force: bool = False) -> Path:
    """Create the workspace and redirect all temp allocation into it.

    Idempotent. Safe to call from the toolkit entrypoint AND from any module's
    standalone __main__ so scratch never lands on the small /tmp tmpfs.
    Returns the scratch dir.
    """
    global _INITIALISED
    if _INITIALISED and not force:
        return SCRATCH_DIR
    ensure_dirs()
    # Only redirect if the scratch dir is actually writable; otherwise leave the
    # system default alone rather than break tempfile entirely.
    if os.access(str(SCRATCH_DIR), os.W_OK):
        os.environ["TMPDIR"] = str(SCRATCH_DIR)
        tempfile.tempdir = str(SCRATCH_DIR)
    _INITIALISED = True
    return SCRATCH_DIR


def new_scratch(prefix: str = "crescent_") -> Path:
    """A fresh scratch subdir on the big disk (not /tmp)."""
    setup()
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(SCRATCH_DIR)))
