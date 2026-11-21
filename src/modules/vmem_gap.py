"""Guest-physical memory map for a VMware .vmem that has no .vmss/.vmsn beside it.

VMware writes guest RAM into the .vmem back to back, but the guest sees the RAM
above the PCI hole at 4 GB and up (e.g. 4 GB VM: file 0-3 GB = phys 0-3 GB,
file 3-4 GB = phys 4-5 GB). The split is stored only in the .vmss/.vmsn
metadata. Without it every page-table walk that touches the upper RAM fails:
Vol3 rejects the DTB ("Max pointer ... not met: 0x13ffffa00 > 0xffffffff"),
windows.info / imageinfo find nothing and the tool says "could not detect OS".

This module finds the split from the guest's own x86-64 page tables, without
assuming a size:
  1. one pass over the file finds top-level page tables: Windows PML4s (one
     self-referencing kernel entry, exactly Vol3's DtbSelfRef64bit test, either
     at their own file offset or shifted by the hole) and, for any OS, groups of
     top-level tables with an identical kernel half (all processes share it);
  2. every split X (low RAM = file [0, X) at phys 0, the rest at phys 4 GB) is
     scored by walking those tables two levels: a pointer to a page table must
     land inside the file and not in the hole, and the table it points to must
     itself point to valid places. The right X makes all of them valid, a wrong
     X reads unrelated pages and produces invalid pointers;
  3. "no remap" (identity) is scored the same way, so a dump that does not need
     a remap is left alone.
The map is cached as JSON (vmem_maps/<key>.json); the RAMBreaker Vol3 layer
(vol_layers/rb_vmem_gap.py) and Vol2 address space (vol2_addrspaces/) read it.
Only page-table structure is read; no memory contents are logged.
"""
from __future__ import annotations

import hashlib
import json
import mmap
import os
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

PAGE = 0x1000
GB4 = 1 << 32
ADDR_MASK = 0x000FFFFFFFFFF000          # bits 12-51 of a page-structure entry
MB = 0x100000
SIDECARS = (".vmss", ".vmsn")
MAP_VERSION = 1
MAP_DIR_ENV = "RB_VMEM_MAP_DIR"
_CHUNK = 64 * MB
_MAX_ROOTS = 64
_MAX_L1 = 4000


# --------------------------------------------------------------------------- keys
def map_key(image: str) -> str:
    """Same key in the tool, the Vol3 layer and the Vol2 address space:
    file name (lower case) + size + mtime (seconds)."""
    st = os.stat(image)
    raw = "%s|%d|%d" % (os.path.basename(image).lower(), st.st_size, int(st.st_mtime))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]


def map_file(image: str, map_dir) -> Path:
    return Path(map_dir) / (map_key(image) + ".json")


def sidecar_present(image: str) -> bool:
    stem = os.path.splitext(image)[0]
    return any(os.path.exists(stem + s) or os.path.exists(stem + s.upper()) for s in SIDECARS)


def is_vmem_without_metadata(image: str) -> bool:
    return image.lower().endswith(".vmem") and not sidecar_present(image)


def load_map(image: str, map_dir) -> Optional[dict]:
    try:
        d = json.loads(map_file(image, map_dir).read_text(encoding="utf-8"))
        if d.get("version") == MAP_VERSION:
            return d
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------- scan
def _scan_roots(path: str, size: int, progress: Optional[Callable[[float], None]] = None):
    """One pass: (identity PML4 offsets, {shift D: [offsets]},
    {kernel-half signature: [offsets]})."""
    import numpy as np

    ident: List[int] = []
    shifted: Dict[int, List[int]] = {}
    groups: Dict[str, List[int]] = {}
    with open(path, "rb") as f:
        off = 0
        while off < size:
            buf = f.read(_CHUNK)
            n = (len(buf) // PAGE) * PAGE
            if n == 0:
                break
            a = np.frombuffer(buf, dtype="<u8", count=n // 8).reshape(-1, 512)
            pres = (a & np.uint64(1)).astype(bool)
            # a present entry with bit 7 (PS) set cannot be in a PML4/PGD
            bad = (pres & ((a & np.uint64(0x80)) != 0)).any(axis=1)
            kp = pres[:, 0x100:0x1FF]
            addr = (a[:, 0x100:0x1FF] & np.uint64(ADDR_MASK)).astype(np.int64)
            pos = off + np.arange(a.shape[0], dtype=np.int64) * PAGE
            diff = addr - pos[:, None]
            # Windows self-reference at its own offset (phys == file offset)
            nid = (kp & (diff == 0)).sum(axis=1)
            for r in np.nonzero((nid == 1) & ~bad & (pos > 0))[0]:
                ident.append(int(pos[r]))
            # ... or shifted by the hole (page stored above the split)
            sh = kp & (diff > 0) & (diff < GB4) & ((diff % MB) == 0)
            for r in np.nonzero(sh.any(axis=1) & ~bad)[0]:
                ds = diff[r][sh[r]]
                vals, cnt = np.unique(ds, return_counts=True)
                if len(vals) == 1 and cnt[0] == 1:
                    shifted.setdefault(int(vals[0]), []).append(int(pos[r]))
            # any OS: the top-level tables of all processes share the same
            # kernel half (Linux/macOS copy it into every PGD/PML4)
            cand = pres[:, 511] & ~bad & (kp.sum(axis=1) >= 2)
            for r in np.nonzero(cand)[0]:
                sig = hashlib.sha1(a[r, 0x100:].tobytes()).hexdigest()[:16]
                groups.setdefault(sig, []).append(int(pos[r]))
            off += len(buf)
            if progress:
                progress(min(1.0, off / float(size)))
    return ident, shifted, groups


# --------------------------------------------------------------------------- scoring
class _Img:
    def __init__(self, path: str, size: int):
        self.size = size
        self._f = open(path, "rb")
        self._m = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)

    def entries(self, off: int):
        import numpy as np
        # bytes copy: an array viewing the mmap would block mmap.close()
        return np.frombuffer(self._m[off:off + PAGE], dtype="<u8")

    def close(self):
        try:
            self._m.close()
        finally:
            self._f.close()


def _valid_mask(q, x: int, size: int):
    """numpy: which physical addresses q are backed by the file under split x."""
    import numpy as np
    q = q.astype(np.int64)
    if x >= size:                                     # identity (no remap)
        return q + PAGE <= size
    return (q < x) | ((q >= GB4) & (q - GB4 + x + PAGE <= size))


def _phys_to_file(p: int, x: int, size: int) -> Optional[int]:
    if x >= size:
        return p if p + PAGE <= size else None
    if p < x:
        return p
    if p < GB4:
        return None                    # inside the hole
    o = p - GB4 + x
    return o if o + PAGE <= size else None


def _root_ok(img: "_Img", l1, x: int) -> bool:
    """A top-level table is consistent under split x when every table it points
    to is backed by the file and every non-leaf entry of those tables points
    to a backed address too (at least 16 of them, so pages of zeros read at a
    wrong x do not count). Empty tables are fine: Windows keeps present but
    empty PDPTs in every process. Stale or random pages are not consistent for
    every x, so they cannot out-vote real page tables."""
    import numpy as np
    size = img.size
    if not _valid_mask(l1, x, size).all():
        return False
    deeper = 0
    hi_tables = hi_used = 0
    for p in l1.tolist():
        e = img.entries(_phys_to_file(int(p), x, size))
        nonleaf = e[((e & np.uint64(1)) != 0) & ((e & np.uint64(0x80)) == 0)]
        if p >= GB4:
            hi_tables += 1
        if nonleaf.size:
            if not _valid_mask(nonleaf & np.uint64(ADDR_MASK), x, size).all():
                return False
            deeper += int(nonleaf.size)
            if p >= GB4:
                hi_used += 1
    # tables above the hole must be found where x puts them: a wrong x reads
    # other pages there, and pages of zeros would otherwise pass as empty tables
    if hi_tables and not hi_used:
        return False
    return deeper >= 16


def _spread(items: List[int], n: int) -> List[int]:
    if len(items) <= n:
        return list(items)
    step = len(items) / float(n)
    return [items[int(i * step)] for i in range(n)]


def solve(image: str, progress: Optional[Callable[[float], None]] = None) -> dict:
    """Find the split. Returns a map dict (see module doc); 'remap' False when
    the dump does not need one or no page tables were found ('reason')."""
    t0 = time.time()
    size = os.path.getsize(image)
    res = {"version": MAP_VERSION, "image": os.path.basename(image), "size": size,
           "remap": False, "segments": [[0, 0, size]], "method": "page-table walk"}
    try:
        import numpy as np
    except Exception:
        res["reason"] = "numpy not available"
        return res
    ident, shifted, groups = _scan_roots(image, size, progress)

    # roots (each one votes for the splits it is consistent with; look-alike
    # pages are consistent with none, so they cannot skew the vote): Windows
    # PML4s (identity + the dominant hole shift) and, for any OS, samples of
    # the largest groups of pages sharing one kernel half
    x_hints: List[int] = []
    roots: List[int] = _spread(sorted(ident), 24)
    if shifted:
        ranked = sorted(shifted.items(), key=lambda kv: -len(kv[1]))
        d, offs = ranked[0]
        second = len(ranked[1][1]) if len(ranked) > 1 else 0
        if len(offs) >= 3 and len(offs) >= 2 * second and 0 < GB4 - d <= size:
            x_hints.append(GB4 - d)
            roots += _spread(sorted(offs), 24)
    for offs in sorted(groups.values(), key=len, reverse=True)[:6]:
        if len(offs) >= 3:
            roots += _spread(sorted(offs), 12)
    roots = sorted(set(roots))
    res.update(roots=len(roots), windows_pml4=len(ident) + sum(len(v) for v in shifted.values()))
    if not roots:
        res["reason"] = "no x86-64 top-level page tables found"
        return res

    img = _Img(image, size)
    try:
        l1s = []
        for r in roots:
            e = img.entries(r)
            pr = e[((e & np.uint64(1)) != 0) & ((e & np.uint64(0x80)) == 0)]
            l1 = np.unique(pr & np.uint64(ADDR_MASK))
            l1 = l1[l1 != 0]
            if l1.size >= 4:        # real top-level tables point to several tables
                l1s.append(l1)
        if not l1s:
            res["reason"] = "page tables have no entries"
            return res
        top = min(size, GB4)
        cands = set(x_hints) | set(range(max(MB, GB4 // 16), top, 16 * MB))

        def score(x):
            return sum(1 for l1 in l1s if _root_ok(img, l1, x))

        scored = {size: score(size)}
        for c in cands:
            scored[c] = score(c)
        best_coarse = sorted((c for c in scored if c != size), key=lambda c: -scored[c])[:3]
        for c in best_coarse:                      # refine at 1 MB
            for f in range(max(MB, c - 16 * MB), min(top, c + 16 * MB) + 1, MB):
                if f not in scored:
                    scored[f] = score(f)
        # ties: prefer identity, then the larger power-of-two alignment
        def key(c):
            align = (c & -c) if c else 0
            return (scored[c], c == size, align)
        best = max(scored, key=key)
        res.update(roots_with_tables=len(l1s), consistent=scored[best],
                   consistent_identity=scored[size], candidates=len(scored))
        # evidence = roots that only make sense with this split. Real page
        # tables fail again when the split moves (their upper tables are read
        # from the wrong place); look-alike pages that fit any split do not.
        peaked = False
        if best != size:
            evid = [l1 for l1 in l1s if _root_ok(img, l1, best) and not _root_ok(img, l1, size)]
            probes = [best + d for d in (-256 * MB, -64 * MB, 64 * MB, 256 * MB)
                      if MB <= best + d < top]
            still = max((sum(1 for l1 in evid if _root_ok(img, l1, q)) for q in probes),
                        default=0)
            peaked = len(evid) >= 3 and still * 2 <= len(evid)
            res.update(evidence=len(evid), evidence_off_peak=still)
        if best != size and peaked and scored[best] > scored[size]:
            res["remap"] = True
            res["split"] = best
            res["segments"] = [[0, 0, best], [GB4, best, size - best]]
        else:
            res["reason"] = ("identity mapping already valid" if scored[size] > 0
                             else "no split explains the page tables")
    finally:
        img.close()
    res["seconds"] = round(time.time() - t0, 1)
    return res


def ensure_map(image: str, map_dir, log=None, progress=None) -> Optional[dict]:
    """Cached solve(); writes <map_dir>/<key>.json (also for 'no remap', so the
    scan runs once per image). Returns the map dict or None on error."""
    m = load_map(image, map_dir)
    if m is not None:
        return m
    try:
        m = solve(image, progress)
    except Exception as e:  # never break detection because of this
        if log:
            log.warning("VMware memory-map check failed: %s", e)
        return None
    try:
        Path(map_dir).mkdir(parents=True, exist_ok=True)
        map_file(image, map_dir).write_text(json.dumps(m, indent=1), encoding="utf-8")
    except Exception as e:
        if log:
            log.warning("Could not save the memory map (%s): %s", map_dir, e)
    return m


def describe(m: dict) -> str:
    if not m.get("remap"):
        return "no remap needed (%s)" % m.get("reason", "")
    x = m["split"]
    hi = m["size"] - x
    return ("file 0-%.2f GB -> RAM 0-%.2f GB, file %.2f-%.2f GB -> RAM 4.00-%.2f GB "
            "(%d of %d page tables consistent)"
            % (x / 2**30, x / 2**30, x / 2**30, m["size"] / 2**30, (GB4 + hi) / 2**30,
               m.get("consistent", 0), m.get("roots_with_tables", 0)))
