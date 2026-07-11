# CresCentC — macOS page-cache (Unified Buffer Cache) file-content recovery.
#
# Volatility 3 ships no macOS equivalent of windows.dumpfiles / linux.pagecache:
# mac.list_files enumerates vnodes (paths only) and stops there. This plugin goes
# the rest of the way — for each regular-file vnode it follows the Unified Buffer
# Cache to the file's cached physical pages and reassembles the file content:
#
#   vnode.v_un.vu_ubcinfo -> ubc_info.ui_control -> memory_object_control.moc_object
#     -> vm_object.memq (resident-page queue) -> vm_page.{offset, phys_page}
#
# Each resident vm_page carries its offset within the file object and a physical
# page number; PAGE_SIZE bytes are read from the physical layer at
# phys_page * PAGE_SIZE and written at that offset, exactly like the Windows/Linux
# page-cache dumpers. ui_size bounds the reconstructed file.
#
# NB: XNU packs the vm_object.memq links into 32-bit values (vm_page_packed_t).
# The walk unpacks them with VM_PAGE_UNPACK_PTR using the kernel's own runtime
# constants (vm_packed_pointer_shift / vm_min_kernel_and_kext_address /
# vm_packed_from_vm_pages_array_mask / vm_pages), read by symbol so the KASLR
# slide is handled. Each unpacked link points to the next vm_page base directly
# (no container_of), terminating when it resolves back to &memq.

import logging
import re
from typing import Iterable, Optional, Tuple

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import list_files, mount

vollog = logging.getLogger(__name__)


class Pagecache(plugins.PluginInterface):
    """Recovers cached file contents from the macOS Unified Buffer Cache (page cache)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    PAGE_SIZE = 4096
    VREG = 1  # enum vtype: VNON=0, VREG=1, VDIR=2, ...

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="mount", component=mount.Mount, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="mac_utilities", component=mac.MacUtilities, version=(1, 3, 0)
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Reconstruct each file's cached content and write it to disk",
                default=False,
                optional=True,
            ),
            requirements.StringRequirement(
                name="name",
                description="Only operate on files whose full path contains this "
                            "substring (comma-separated = match ANY of them)",
                optional=True,
            ),
        ]

    # -- Unified Buffer Cache walk --------------------------------------------

    @classmethod
    def _vnode_vm_object(cls, kernel, vnode):
        """vnode -> (vm_object, file_size). Only regular files have a UBC info."""
        try:
            if int(vnode.v_type) != cls.VREG:
                return None, 0
        except exceptions.InvalidAddressException:
            return None, 0
        try:
            ubc_ptr = vnode.v_un.vu_ubcinfo
            if not ubc_ptr:
                return None, 0
            ubc = ubc_ptr.dereference()
            size = int(ubc.ui_size)
            control_ptr = ubc.ui_control
            if not control_ptr:
                return None, size
            obj_ptr = control_ptr.dereference().moc_object
            if not obj_ptr:
                return None, size
            return obj_ptr.dereference(), size
        except exceptions.InvalidAddressException:
            return None, 0

    @classmethod
    def _read_global(cls, context, kernel, name, size):
        """Read a kernel global by symbol name (module applies the KASLR slide)."""
        try:
            addr = kernel.get_absolute_symbol_address(name)
            return int.from_bytes(
                context.layers[kernel.layer_name].read(addr, size), "little")
        except Exception:
            return None

    @classmethod
    def _load_packing(cls, context, kernel):
        """Resolve XNU's vm_page packed-pointer constants from kernel globals.

        10.12 packs vm_page queue links into 32-bit values via a dual scheme:
          - array pages:  &vm_pages[p & ~mask]
          - zoned pages:  (p << shift) + vm_min_kernel_and_kext_address
        The shift/base/mask/array-base are runtime globals (KASLR-slid)."""
        elem = kernel.get_type("vm_page").size
        return {
            "shift": cls._read_global(context, kernel, "vm_packed_pointer_shift", 4),
            "base": cls._read_global(context, kernel, "vm_min_kernel_and_kext_address", 8),
            "mask": cls._read_global(context, kernel, "vm_packed_from_vm_pages_array_mask", 4),
            "arr": cls._read_global(context, kernel, "vm_pages", 8),
            "elem": elem,
        }

    @staticmethod
    def _unpack(pk, p):
        """VM_PAGE_UNPACK_PTR: 32-bit packed link -> vm_page virtual address."""
        p &= 0xFFFFFFFF
        if p == 0:
            return 0
        mask = pk["mask"]
        if mask and (p & mask):
            if not pk["arr"]:
                return 0
            return pk["arr"] + (p & ~mask) * pk["elem"]
        return (p << pk["shift"]) + pk["base"]

    @classmethod
    def _iter_pages(cls, context, kernel, vm_object, pk):
        """Yield each resident vm_page linked into vm_object.memq.

        memq is XNU's packed page queue: each link is a 32-bit packed pointer to
        the next vm_page *base*, terminating when it unpacks back to &memq.
        """
        if not pk or pk["shift"] is None or pk["base"] is None:
            return
        try:
            head_addr = vm_object.memq.vol.offset  # &vm_object.memq (memq is at obj+0)
            node = cls._unpack(pk, int(vm_object.memq.next))
        except exceptions.InvalidAddressException:
            return
        seen = set()
        # A healthy object holds far fewer pages than this; the cap only guards
        # against a smeared/looping chain in a partial image.
        for _ in range(1 << 21):
            if not node or node == head_addr or node in seen:
                break
            seen.add(node)
            try:
                page = kernel.object(object_type="vm_page", offset=node,
                                     absolute=True)
                nxt = cls._unpack(pk, int(page.listq.next))
            except exceptions.InvalidAddressException:
                break
            yield page
            node = nxt

    @classmethod
    def _page_has_data(cls, page):
        """A page holds recoverable data only if it has a real physical frame and
        isn't an absent/fictitious placeholder. XNU keeps such placeholders in an
        object's memq (e.g. reserved-but-never-faulted or evicted pages) with
        phys_page == 0 — those carry no bytes."""
        try:
            if int(page.absent) or int(page.fictitious):
                return False
            return int(page.phys_page) != 0
        except exceptions.InvalidAddressException:
            return False

    @classmethod
    def _read_page(cls, context, kernel, page):
        """Read a resident page's PAGE_SIZE bytes from the physical layer."""
        if not cls._page_has_data(page):
            return None
        try:
            ppn = int(page.phys_page)
        except exceptions.InvalidAddressException:
            return None
        if ppn == 0:
            return None
        paddr = ppn * cls.PAGE_SIZE
        phys_name = context.layers[kernel.layer_name].config.get(
            "memory_layer", kernel.layer_name)
        phys = context.layers[phys_name]
        if not phys.is_valid(paddr, cls.PAGE_SIZE):
            return None
        try:
            return phys.read(paddr, cls.PAGE_SIZE)
        except exceptions.InvalidAddressException:
            return None

    @classmethod
    def _cached_page_offsets(cls, context, kernel, vm_object, size, pk):
        """Return the sorted list of in-bounds file offsets that are resident."""
        offs = []
        for page in cls._iter_pages(context, kernel, vm_object, pk):
            if not cls._page_has_data(page):
                continue
            try:
                off = int(page.offset)
            except exceptions.InvalidAddressException:
                continue
            # Genuine file pages are page-aligned and inside the file.
            if 0 <= off < size and (off & (cls.PAGE_SIZE - 1)) == 0:
                offs.append(off)
        return offs

    @classmethod
    def _write_content(cls, context, kernel, vm_object, size, stream, pk):
        """Reassemble the file from its resident pages into `stream`. Returns
        (pages_written, bytes_written)."""
        stream.truncate(size)
        pages = written = 0
        for page in cls._iter_pages(context, kernel, vm_object, pk):
            try:
                off = int(page.offset)
            except exceptions.InvalidAddressException:
                continue
            if not (0 <= off < size) or (off & (cls.PAGE_SIZE - 1)):
                continue
            data = cls._read_page(context, kernel, page)
            if not data:
                continue
            n = min(cls.PAGE_SIZE, size - off)
            stream.seek(off)
            stream.write(data[:n])
            pages += 1
            written += n
        return pages, written

    # -- plugin plumbing -------------------------------------------------------

    @staticmethod
    def _safe_name(path, vnode_off):
        stem = re.sub(r"[^\w.\-]", "_", path.lstrip("/"))[:180] or "unnamed"
        return f"mac_pagecache.{stem}.0x{vnode_off:x}.dmp"

    def _generator(self):
        kernel_name = self.config["kernel"]
        kernel = self.context.modules[kernel_name]
        name_filters = [s for s in (self.config.get("name") or "").split(",") if s]
        do_dump = self.config.get("dump", False)

        pk = self._load_packing(self.context, kernel)
        if pk["shift"] is None or pk["base"] is None:
            vollog.error("Could not resolve vm_page packed-pointer constants "
                         "(vm_packed_pointer_shift / vm_min_kernel_and_kext_address) "
                         "— page-cache walk unavailable for this kernel.")
            return

        for vnode, path in list_files.List_Files.list_files(self.context, kernel_name):
            if name_filters and not any(s in path for s in name_filters):
                continue
            vm_object, size = self._vnode_vm_object(kernel, vnode)
            if vm_object is None or size <= 0:
                continue
            offs = self._cached_page_offsets(self.context, kernel, vm_object, size, pk)
            if not offs:
                continue

            file_output = renderers.NotAvailableValue()
            if do_dump:
                fname = self._safe_name(path, vnode.vol.offset)
                try:
                    with self.open(fname) as fobj:
                        pages, _ = self._write_content(
                            self.context, kernel, vm_object, size, fobj, pk)
                    file_output = fname if pages else renderers.NotAvailableValue()
                except Exception as exc:
                    vollog.debug("dump failed for %s: %s", path, exc)

            yield (0, (
                format_hints.Hex(vnode.vol.offset),
                path,
                size,
                len(offs),
                len(offs) * self.PAGE_SIZE,
                file_output,
            ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Vnode", format_hints.Hex),
                ("Path", str),
                ("Size", int),
                ("CachedPages", int),
                ("CachedBytes", int),
                ("FileOutput", str),
            ],
            self._generator(),
        )
