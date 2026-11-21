# RAMBreaker: Volatility 2 address space for a VMware .vmem without .vmss/.vmsn.
# Loaded through vol.py --plugins=<this folder>. Python 2.7.
#
# VMware stores guest RAM in the .vmem back to back, but the guest sees the RAM
# above the PCI hole at 4 GB and up; the split is only in the .vmss/.vmsn.
# RAMBreaker (modules/vmem_gap.py) finds the split from the guest's page tables
# and saves it as vmem_maps/<key>.json; this address space applies it. Without
# a map file it refuses to stack, so other images are not affected.
import hashlib
import json
import os

import volatility.addrspace as addrspace

MAP_VERSION = 1
MAP_DIR_ENV = "RB_VMEM_MAP_DIR"


def _map_key(path):
    # must match modules/vmem_gap.map_key
    st = os.stat(path)
    raw = "%s|%d|%d" % (os.path.basename(path).lower(), st.st_size, int(st.st_mtime))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]


def _map_dirs():
    dirs = []
    if os.environ.get(MAP_DIR_ENV):
        dirs.append(os.environ[MAP_DIR_ENV])
    vc = os.environ.get("RAMBREAKER_VOL3_CACHE")
    if vc:
        dirs.append(os.path.join(vc, "vmem_maps"))
    return dirs


def load_runs(path):
    try:
        key = _map_key(path)
        size = os.path.getsize(path)
    except Exception:
        return None
    for d in _map_dirs():
        try:
            with open(os.path.join(d, key + ".json")) as fh:
                m = json.load(fh)
        except Exception:
            continue
        if m.get("version") != MAP_VERSION or not m.get("remap") or m.get("size") != size:
            return None
        return sorted((int(p), int(o), int(n)) for p, o, n in m["segments"])
    return None


class RBVmemGapAddressSpace(addrspace.AbstractRunBasedMemory):
    """VMware .vmem without .vmss/.vmsn, remapped around the PCI hole (RAMBreaker map)"""
    # after VMWareAddressSpace (30), which handles a .vmss/.vmsn given as -f
    order = 31

    def __init__(self, base, config, **kwargs):
        self.as_assert(base, "No base Address Space")
        self.as_assert(base.__class__.__name__ == "FileAddressSpace",
                       "Only stacks directly on the image file")
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)
        path = getattr(base, "fname", None) or getattr(base, "name", None)
        runs = load_runs(path) if path else None
        self.as_assert(runs, "No RAMBreaker memory map for this file")
        self.runs = runs
        self.header = None
