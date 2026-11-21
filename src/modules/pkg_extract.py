"""Pure-Python extraction of kernel debug packages (Windows port).

Replaces dpkg-deb / ar / tar / rpm2cpio / cpio for the one thing the ISF
pipeline needs: pulling the debug `vmlinux` out of a .ddeb/.deb or a
kernel-debuginfo .rpm. Only members whose basename starts with "vmlinux"
are written (a debug package is mostly modules we don't need), and every
output path is confined to the work directory.
"""

import gzip
import bz2
import io
import lzma
import os
import struct
import tarfile
from pathlib import Path
from typing import BinaryIO, List, Optional

_MAGIC = {
    b"\xfd7zXZ\x00": "xz",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"\x1f\x8b": "gz",
    b"BZh": "bz2",
}


def _want(name: str) -> bool:
    return os.path.basename(name.rstrip("/")).startswith("vmlinux")


def _safe_dest(workdir: Path, name: str) -> Path:
    name = name.lstrip("./").replace("\\", "/")
    dest = (workdir / name).resolve()
    root = workdir.resolve()
    if root not in dest.parents:
        raise ValueError(f"unsafe archive path: {name}")
    return dest


def _decompressor(fobj: BinaryIO) -> BinaryIO:
    head = fobj.read(6)
    fobj.seek(0)
    kind = next((k for m, k in _MAGIC.items() if head.startswith(m)), None)
    if kind == "xz":
        return lzma.open(fobj)
    if kind == "gz":
        return gzip.open(fobj)
    if kind == "bz2":
        return bz2.open(fobj)
    if kind == "zstd":
        import zstandard  # pip: zstandard (bundled)
        return zstandard.ZstdDecompressor().stream_reader(fobj)
    return fobj  # uncompressed


def _copy(src: BinaryIO, dest: Path, size: Optional[int] = None) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as out:
        left = size
        while left is None or left > 0:
            n = 8 * 1024 * 1024 if left is None else min(left, 8 * 1024 * 1024)
            b = src.read(n)
            if not b:
                break
            out.write(b)
            if left is not None:
                left -= len(b)


# ---------------------------------------------------------------- .deb/.ddeb

def ar_members(path: Path):
    """Yield (name, offset, size) of each member of an ar archive."""
    with open(path, "rb") as f:
        if f.read(8) != b"!<arch>\n":
            raise ValueError("not an ar archive")
        while True:
            hdr = f.read(60)
            if len(hdr) < 60:
                return
            name = hdr[0:16].decode("ascii", "replace").strip().rstrip("/")
            size = int(hdr[48:58].decode("ascii").strip())
            off = f.tell()
            yield name, off, size
            f.seek(off + size + (size & 1))


def extract_deb(deb: Path, workdir: Path) -> List[Path]:
    """Extract vmlinux* from a .deb/.ddeb's data.tar.* into workdir."""
    workdir.mkdir(parents=True, exist_ok=True)
    out: List[Path] = []
    for name, off, size in ar_members(deb):
        if not name.startswith("data.tar"):
            continue
        with open(deb, "rb") as f:
            f.seek(off)
            raw = io.BufferedReader(_Slice(f, off, size))
            stream = _decompressor(raw)
            with tarfile.open(fileobj=stream, mode="r|") as tf:
                for m in tf:
                    if m.isfile() and _want(m.name):
                        dest = _safe_dest(workdir, m.name)
                        src = tf.extractfile(m)
                        _copy(src, dest)
                        out.append(dest)
        break
    return out


class _Slice(io.RawIOBase):
    """Read-only window [off, off+size) of an open file (seekable)."""

    def __init__(self, f, off, size):
        self.f, self.off, self.size, self.pos = f, off, size, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, pos, whence=0):
        if whence == 0:
            self.pos = pos
        elif whence == 1:
            self.pos += pos
        else:
            self.pos = self.size + pos
        self.pos = max(0, min(self.pos, self.size))
        return self.pos

    def tell(self):
        return self.pos

    def readinto(self, b):
        n = min(len(b), self.size - self.pos)
        if n <= 0:
            return 0
        self.f.seek(self.off + self.pos)
        data = self.f.read(n)
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


# ---------------------------------------------------------------------- .rpm

def _rpm_payload_offset(f: BinaryIO) -> int:
    lead = f.read(96)
    if lead[:4] != b"\xed\xab\xee\xdb":
        raise ValueError("not an RPM")
    pos = 96
    for i in range(2):               # signature header, then main header
        f.seek(pos)
        h = f.read(16)
        if h[:3] != b"\x8e\xad\xe8":
            raise ValueError("bad RPM header magic")
        nindex, hsize = struct.unpack(">II", h[8:16])
        pos += 16 + nindex * 16 + hsize
        if i == 0:
            pos = (pos + 7) & ~7     # signature header is 8-byte aligned
    return pos


def extract_rpm(rpm: Path, workdir: Path) -> List[Path]:
    """Extract vmlinux* from a .rpm's (cpio newc) payload into workdir."""
    workdir.mkdir(parents=True, exist_ok=True)
    out: List[Path] = []
    with open(rpm, "rb") as f:
        start = _rpm_payload_offset(f)
        size = os.fstat(f.fileno()).st_size - start
        stream = _decompressor(io.BufferedReader(_Slice(f, start, size)))

        def read_exact(n):
            buf = b""
            while len(buf) < n:
                b = stream.read(n - len(buf))
                if not b:
                    raise EOFError("truncated cpio")
                buf += b
            return buf

        consumed = 0
        while True:
            hdr = read_exact(110)
            consumed += 110
            if hdr[:6] not in (b"070701", b"070702"):
                raise ValueError("unsupported cpio format")
            fields = [int(hdr[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
            mode, fsize, namesize = fields[1], fields[6], fields[11]
            name = read_exact(namesize)[:-1].decode("utf-8", "replace")
            consumed += namesize
            pad = (-consumed) % 4
            read_exact(pad)
            consumed += pad
            if name == "TRAILER!!!":
                break
            is_reg = (mode & 0o170000) == 0o100000
            if is_reg and _want(name) and fsize:
                dest = _safe_dest(workdir, name)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with open(dest, "wb") as o:
                    left = fsize
                    while left:
                        b = stream.read(min(left, 8 * 1024 * 1024))
                        if not b:
                            raise EOFError("truncated file data")
                        o.write(b)
                        left -= len(b)
                out.append(dest)
            else:
                left = fsize
                while left:
                    b = stream.read(min(left, 8 * 1024 * 1024))
                    if not b:
                        raise EOFError("truncated file data")
                    left -= len(b)
            consumed += fsize
            pad = (-consumed) % 4
            read_exact(pad)
            consumed += pad
    return out
