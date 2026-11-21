# RAMBreaker: guest-physical memory map for a VMware .vmem without .vmss/.vmsn.
# Installed into volatility3/framework/layers/ (Vol3 imports every module there).
#
# VMware stores guest RAM in the .vmem back to back, but the guest sees the RAM
# above the PCI hole at 4 GB and up; the split is only in the .vmss/.vmsn. When
# that file is missing, RAMBreaker (modules/vmem_gap.py) finds the split from
# the guest's own page tables and saves it as <cache>/vmem_maps/<key>.json.
# This stacker turns that map into a segmented layer under the OS stackers.
# Without a map file it does nothing, so other images are not affected.
import hashlib
import json
import logging
import os
import urllib.parse
import urllib.request
from typing import List, Optional

from volatility3.framework import constants, interfaces
from volatility3.framework.layers import physical, segmented

vollog = logging.getLogger(__name__)

MAP_VERSION = 1
MAP_DIR_ENV = "RB_VMEM_MAP_DIR"


def _location_path(location: str) -> str:
    if location.lower().startswith("file:"):
        return urllib.request.url2pathname(urllib.parse.urlparse(location).path)
    return location


def _map_key(path: str) -> str:
    # must match modules/vmem_gap.map_key
    st = os.stat(path)
    raw = "%s|%d|%d" % (os.path.basename(path).lower(), st.st_size, int(st.st_mtime))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]


def _map_dirs() -> List[str]:
    dirs = []
    if os.environ.get(MAP_DIR_ENV):
        dirs.append(os.environ[MAP_DIR_ENV])
    dirs.append(os.path.join(constants.CACHE_PATH, "vmem_maps"))
    return dirs


def load_segments(location: str) -> Optional[list]:
    """[(phys, file_offset, length), ...] when RAMBreaker saved a remap for
    this file, else None."""
    try:
        path = _location_path(location)
        if not os.path.isfile(path):
            return None
        key = _map_key(path)
        size = os.path.getsize(path)
    except Exception:
        return None
    for d in _map_dirs():
        f = os.path.join(d, key + ".json")
        try:
            with open(f, encoding="utf-8") as fh:
                m = json.load(fh)
        except Exception:
            continue
        if m.get("version") != MAP_VERSION or not m.get("remap") or m.get("size") != size:
            return None
        return [(int(p), int(o), int(n)) for p, o, n in m["segments"]]
    return None


class RBVmemGapLayer(segmented.SegmentedLayer):
    """Physical layer of a .vmem without metadata, remapped around the PCI hole."""

    def _load_segments(self) -> None:
        base = self._context.layers[self._base_layer]
        segs = load_segments(getattr(base, "location", ""))
        if not segs:
            raise ValueError("No RAMBreaker memory map for this file")
        self._segments = [(p, o, n, n) for p, o, n in sorted(segs)]


class RBVmemGapStacker(interfaces.automagic.StackerLayerInterface):
    # after VmwareStacker (20; it handles .vmem files WITH .vmss/.vmsn), before
    # the Linux (35) and Windows (40) page-table stackers
    stack_order = 21

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        layer = context.layers[layer_name]
        if not isinstance(layer, physical.FileLayer):
            return None
        if not load_segments(layer.location):
            return None
        new_name = context.layers.free_layer_name("RBVmemGapLayer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = (
            layer_name
        )
        vollog.info("RAMBreaker memory map applied (VMware .vmem without .vmss/.vmsn)")
        return RBVmemGapLayer(context, new_name, new_name)
