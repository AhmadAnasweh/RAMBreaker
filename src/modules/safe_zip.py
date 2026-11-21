"""Password-protected output for files dumped from memory (RAMBreaker v2.5).

A file pulled out of a memory dump can be live malware (ransomware, a loader).
Written to disk as it is, one double-click starts it, and the virus scanner
may quarantine it (the evidence is gone). With protection on, every dumped
file goes straight into its own password-protected ZIP, <name>.zip, encrypted
with AES-256 (WinZip AE-2) under the password 'infected' (the usual
malware-exchange convention, changeable): the plain bytes never reach the
disk, nothing can be started from it, and no scanner can look inside.

The member is stored (not compressed) so Volatility may write pages in any
order (windows.dumpfiles seeks to each page's file offset): AES-CTR encrypts
every byte where it lands, holes are filled with encrypted zeros at the end.

The ZIP comment (plain text) carries the file's metadata as JSON, so
RAMBreaker can hash, classify and report a file without ever decrypting it:
  {"rambreaker": 1, "name", "size", "sha256", "sha1", "md5", "type",
   "nonzero_pct", "zero_pages", "pages", "pe_raw_end", "encryption"}

Opens with 7-Zip, WinRAR, PeaZip, bsdtar... Windows Explorer's built-in ZIP
support cannot open AES-encrypted ZIPs, so nobody can run a sample from there.

This file is ALSO installed into Volatility 3 as volatility3/rb_safe_zip.py
(modules/installer.py): Vol3's CLI file handler writes through
vol3_handler_class() when RAMBREAKER_SAFE_ZIP=1 is set. Keep it standalone:
standard library + pycryptodome only.
"""

import bisect
import hashlib
import hmac
import io
import json
import os
import struct
import time
import zlib
from typing import Any, Dict, List, Optional

ENV_ON = "RAMBREAKER_SAFE_ZIP"          # "1": Vol3 writes every output file as <name>.zip
ENV_PW = "RAMBREAKER_ZIP_PASSWORD"      # password (default: DEFAULT_PASSWORD)
DEFAULT_PASSWORD = "infected"
SUFFIX = ".zip"
TMP_SUFFIX = ".rbzip.tmp"               # name while a ZIP is still being written
ENCRYPTION = "AES-256 (WinZip AE-2)"
PAGE = 4096
_CHUNK = 1 << 20                        # multiple of PAGE: page boundaries stay aligned
_KEYLEN, _SALT, _PWV, _MAC = 32, 16, 2, 10
_ZERO_PAGE = bytes(PAGE)

MAGIC = [(b"MZ", "PE (Windows executable/DLL)"), (b"\x7fELF", "ELF (Linux executable/library)"),
         (b"\xcf\xfa\xed\xfe", "Mach-O 64"), (b"\xce\xfa\xed\xfe", "Mach-O 32"),
         (b"\xca\xfe\xba\xbe", "Mach-O universal"), (b"PK\x03\x04", "ZIP / Office / JAR"),
         (b"%PDF", "PDF"), (b"regf", "Registry hive"), (b"ElfFile", "EVTX event log"),
         (b"\x89PNG", "PNG image"), (b"\xff\xd8\xff", "JPEG image"), (b"GIF8", "GIF image"),
         (b"SQLite format 3", "SQLite database"), (b"\x1f\x8b", "gzip"),
         (b"#!", "script"), (b"<?xml", "XML"), (b"{", "JSON/text")]


def sniff_type(head: bytes, size: int, nonzero: int) -> str:
    """File type from the first bytes (shared with extract_jobs.describe)."""
    typ = "empty" if size == 0 else "data"
    for sig, name in MAGIC:
        if head.startswith(sig):
            return name
    if size and nonzero == 0:
        return "all zeros (pages not resident)"
    if head and all(32 <= c < 127 or c in (9, 10, 13) for c in head[:64]):
        return "text"
    return typ


def pe_raw_end(h: bytes) -> Optional[int]:
    """End of the last PE section's raw data (the on-disk size without overlay),
    from the first 4 KiB of the file; None if it is not a PE."""
    if h[:2] != b"MZ" or len(h) < 0x40:
        return None
    e = int.from_bytes(h[0x3C:0x40], "little")
    if h[e:e + 4] != b"PE\0\0":
        return None
    nsec = int.from_bytes(h[e + 6:e + 8], "little")
    opt = int.from_bytes(h[e + 20:e + 22], "little")
    sec = e + 24 + opt
    end = 0
    for i in range(nsec):
        o = sec + 40 * i
        if o + 40 > len(h):
            return None
        end = max(end, int.from_bytes(h[o + 20:o + 24], "little") + int.from_bytes(h[o + 16:o + 20], "little"))
    return end or None


class _Meta:
    """Hashes and statistics of a byte stream, fed in order from offset 0
    in PAGE-aligned chunks."""

    def __init__(self):
        self.h256, self.h1, self.h5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
        self.size = self.nz = self.zero_pages = self.pages = 0
        self.head = b""

    def update(self, b: bytes):
        if not b:
            return
        if len(self.head) < PAGE:
            self.head += b[:PAGE - len(self.head)]
        self.h256.update(b)
        self.h1.update(b)
        self.h5.update(b)
        n = len(b)
        z = b.count(0)
        self.size += n
        self.nz += n - z
        full = n // PAGE
        self.pages += full + (1 if n % PAGE else 0)
        if z == n:
            self.zero_pages += full
        elif z >= PAGE:
            for i in range(0, full * PAGE, PAGE):
                if b[i:i + PAGE] == _ZERO_PAGE:
                    self.zero_pages += 1

    def result(self, name: str) -> Dict[str, Any]:
        return {"rambreaker": 1, "name": name, "size": self.size,
                "sha256": self.h256.hexdigest(), "sha1": self.h1.hexdigest(), "md5": self.h5.hexdigest(),
                "type": sniff_type(self.head[:64], self.size, self.nz),
                "nonzero_pct": round(100.0 * self.nz / self.size, 1) if self.size else 0.0,
                "zero_pages": self.zero_pages, "pages": self.pages,
                "pe_raw_end": pe_raw_end(self.head), "encryption": ENCRYPTION}


def _derive(password: str, salt: bytes):
    dk = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, 1000, 2 * _KEYLEN + _PWV)
    return dk[:_KEYLEN], dk[_KEYLEN:2 * _KEYLEN], dk[2 * _KEYLEN:]


def _ctr(key: bytes, offset: int):
    """AES-CTR positioned at byte `offset` of the encrypted data (WinZip AES:
    little-endian block counter starting at 1)."""
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    blk, skip = divmod(offset, 16)
    c = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=blk + 1, little_endian=True))
    if skip:
        c.encrypt(bytes(skip))
    return c


def _dos_time(t: float):
    lt = time.localtime(t)
    return ((lt.tm_hour << 11) | (lt.tm_min << 5) | (lt.tm_sec // 2),
            ((max(lt.tm_year, 1980) - 1980) << 9) | (lt.tm_mon << 5) | lt.tm_mday)


_AES_EXTRA = struct.pack("<HHH2sBH", 0x9901, 7, 2, b"AE", 3, 0)    # AE-2, AES-256, stored


class AesZipWriter:
    """A one-member AES-256 ZIP written in place. write_at() accepts any
    offset in any order; finish() fills the holes, adds the authentication
    code, the central directory and the metadata comment."""

    def __init__(self, path: str, member: str, password: str = DEFAULT_PASSWORD):
        self.path = path
        self.member = member
        self.f = open(path, "w+b")
        salt = os.urandom(_SALT)
        self.ek, self.ak, pwv = _derive(password or DEFAULT_PASSWORD, salt)
        name = member.encode("utf-8")
        self.flags = 0x1 | (0 if member.isascii() else 0x800)
        self.dtime, self.ddate = _dos_time(time.time())
        extra = struct.pack("<HHQQ", 0x0001, 16, 0, 0) + _AES_EXTRA
        hdr = struct.pack("<IHHHHHIIIHH", 0x04034B50, 51, self.flags, 99, self.dtime, self.ddate,
                          0, 0xFFFFFFFF, 0xFFFFFFFF, len(name), len(extra)) + name + extra
        self._name = name
        self._zip64_at = 30 + len(name) + 4         # the two 8-byte sizes in the local header
        self.f.write(hdr + salt + pwv)
        self.data0 = len(hdr) + _SALT + _PWV
        self.extents: List[List[int]] = []          # written [start, end), sorted, merged
        self.size = 0
        self._seq = None                            # (offset the cipher stands at, cipher)
        self.meta: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------ writing
    def _mark(self, a: int, b: int):
        ex = self.extents
        if not ex or a > ex[-1][1]:
            ex.append([a, b])
            return
        if a >= ex[-1][0]:
            ex[-1][1] = max(ex[-1][1], b)
            return
        i = bisect.bisect_left(ex, [a, a])
        if i > 0 and ex[i - 1][1] >= a:
            i -= 1
        j = i
        while j < len(ex) and ex[j][0] <= b:
            j += 1
        if i < j:
            a, b = min(a, ex[i][0]), max(b, ex[j - 1][1])
        ex[i:j] = [[a, b]]

    def write_at(self, off: int, data) -> int:
        n = len(data)
        if not n:
            return 0
        c = self._seq[1] if self._seq and self._seq[0] == off else _ctr(self.ek, off)
        self.f.seek(self.data0 + off)
        self.f.write(c.encrypt(bytes(data)))
        self._seq = (off + n, c)
        self._mark(off, off + n)
        self.size = max(self.size, off + n)
        return n

    def truncate(self, size: int):
        self.size = size
        self.extents = [[a, min(b, size)] for a, b in self.extents if a < size]
        self._seq = None

    def read_at(self, off: int, n: int) -> bytes:
        end = min(off + n, self.size)
        if off >= end:
            return b""
        self.f.seek(self.data0 + off)
        ct = self.f.read(end - off)
        pt = bytearray(_ctr(self.ek, off).encrypt(ct) + bytes(end - off - len(ct)))
        pos = off
        for a, b in self.extents + [[end, end]]:    # zero the holes nobody wrote
            if b <= pos:
                continue
            if a > pos:
                ga, gb = pos, min(a, end)
                if ga < gb:
                    pt[ga - off:gb - off] = bytes(gb - ga)
            pos = max(pos, b)
            if pos >= end:
                break
        return bytes(pt)

    def _fill(self, a: int, b: int):
        c = _ctr(self.ek, a)
        self.f.seek(self.data0 + a)
        while a < b:
            k = min(_CHUNK, b - a)
            self.f.write(c.encrypt(bytes(k)))
            a += k

    # ------------------------------------------------------------ closing
    def finish(self) -> Dict[str, Any]:
        n = self.size
        pos = 0
        for a, b in self.extents:
            if a > pos:
                self._fill(pos, min(a, n))
            pos = max(pos, b)
        if pos < n:
            self._fill(pos, n)
        mac = hmac.new(self.ak, digestmod=hashlib.sha1)
        dec = _ctr(self.ek, 0)
        m = _Meta()
        self.f.seek(self.data0)
        left = n
        while left:
            ct = self.f.read(min(_CHUNK, left))
            if not ct:
                raise OSError(f"{self.path}: encrypted data shorter than expected")
            mac.update(ct)
            m.update(dec.encrypt(ct))
            left -= len(ct)
        self.f.seek(self.data0 + n)
        self.f.truncate()
        self.f.write(mac.digest()[:_MAC])
        csize = n + _SALT + _PWV + _MAC
        cd_off = self.f.tell()
        extra = struct.pack("<HHQQ", 0x0001, 16, n, csize) + _AES_EXTRA
        cd = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 51, 51, self.flags, 99, self.dtime, self.ddate,
                         0, 0xFFFFFFFF, 0xFFFFFFFF, len(self._name), len(extra), 0, 0, 0, 0, 0) + self._name + extra
        self.f.write(cd)
        self.meta = m.result(self.member)
        com = json.dumps(self.meta, separators=(",", ":")).encode("ascii")
        if cd_off >= 0xFFFFFFFF:
            z64 = self.f.tell()
            self.f.write(struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 1, 1, len(cd), cd_off))
            self.f.write(struct.pack("<IIQI", 0x07064B50, 0, z64, 1))
            self.f.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, 0xFFFFFFFF, 0xFFFFFFFF, len(com)))
        else:
            self.f.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd), cd_off, len(com)))
        self.f.write(com)
        self.f.seek(self._zip64_at)
        self.f.write(struct.pack("<QQ", n, csize))
        self.f.close()
        return self.meta

    def abort(self):
        try:
            self.f.close()
        except OSError:
            pass
        try:
            os.remove(self.path)
        except OSError:
            pass


# ================================================================ reading
def read_meta(path) -> Optional[Dict[str, Any]]:
    """The metadata JSON of a RAMBreaker-protected ZIP, or None (not one of ours)."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size < 22:
                return None
            for want in (4096, 65535 + 22):
                k = min(size, want)
                f.seek(size - k)
                tail = f.read(k)
                i = tail.rfind(b"PK\x05\x06")
                if i >= 0 and i + 22 + struct.unpack("<H", tail[i + 20:i + 22])[0] == len(tail):
                    break
            else:
                return None
        com = tail[i + 22:]
        d = json.loads(com.decode("utf-8")) if com[:1] == b"{" else None
        return d if isinstance(d, dict) and d.get("rambreaker") else None
    except (OSError, ValueError, struct.error, UnicodeDecodeError):
        return None


def is_protected(path) -> bool:
    return str(path).lower().endswith(SUFFIX) and read_meta(path) is not None


def plain_name(name: str) -> str:
    """'x.exe.dat.zip' -> 'x.exe.dat' (names RAMBreaker gave protected outputs)."""
    return name[:-len(SUFFIX)] if name.lower().endswith(SUFFIX) else name


class AesZipReader(io.RawIOBase):
    """Sequential reader of the first member of an AES-encrypted (or plain)
    ZIP: decrypts and inflates on the fly, checks the password and, at the
    end, the authentication code. Nothing is written anywhere."""

    def __init__(self, path, password: str = DEFAULT_PASSWORD):
        super().__init__()
        self.f = open(path, "rb")
        try:
            self._open(password or DEFAULT_PASSWORD)
        except Exception:
            self.f.close()
            raise

    def _open(self, password: str):
        f = self.f
        f.seek(0, 2)
        size = f.tell()
        k = min(size, 65535 + 22 + 20 + 56)
        f.seek(size - k)
        tail = f.read(k)
        i = tail.rfind(b"PK\x05\x06")
        if i < 0:
            raise ValueError("not a ZIP file")
        cd_size, cd_off = struct.unpack("<II", tail[i + 12:i + 20])
        if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
            j = tail.rfind(b"PK\x06\x07", 0, i)
            if j < 0:
                raise ValueError("ZIP64 locator missing")
            z64 = struct.unpack("<Q", tail[j + 8:j + 16])[0]
            f.seek(z64)
            rec = f.read(56)
            cd_size, cd_off = struct.unpack("<QQ", rec[40:56])
        f.seek(cd_off)
        cd = f.read(46)
        (sig, _vm, _vn, flags, method, _t, _d, crc, csize, usize, nlen, xlen, clen,
         _dk, _ia, _ea, loff) = struct.unpack("<IHHHHHHIIIHHHHHII", cd)
        if sig != 0x02014B50:
            raise ValueError("bad central directory")
        rest = f.read(nlen + xlen)
        self.name = rest[:nlen].decode("utf-8" if flags & 0x800 else "cp437")
        ex = rest[nlen:]
        aes = None
        p = 0
        while p + 4 <= len(ex):
            hid, hl = struct.unpack("<HH", ex[p:p + 4])
            body = ex[p + 4:p + 4 + hl]
            if hid == 0x0001:
                q = 0
                if usize == 0xFFFFFFFF:
                    usize = struct.unpack("<Q", body[q:q + 8])[0]
                    q += 8
                if csize == 0xFFFFFFFF:
                    csize = struct.unpack("<Q", body[q:q + 8])[0]
                    q += 8
                if loff == 0xFFFFFFFF:
                    loff = struct.unpack("<Q", body[q:q + 8])[0]
            elif hid == 0x9901 and hl >= 7:
                aes = struct.unpack("<H2sBH", body[:7])     # version, "AE", strength, method
            p += 4 + hl
        f.seek(loff)
        lh = f.read(30)
        if lh[:4] != b"PK\x03\x04":
            raise ValueError("bad local header")
        ln, lx = struct.unpack("<HH", lh[26:30])
        f.seek(loff + 30 + ln + lx)
        self.size = usize
        self._crc = crc
        self._crc_now = 0
        self._ctr = self._mac = None
        if flags & 1:
            if method != 99 or not aes:
                raise ValueError("only AES-encrypted ZIP members are supported")
            _ver, _vid, strength, method = aes
            klen = {1: 16, 2: 24, 3: 32}[strength]
            salt = f.read(klen // 2)
            pwv = f.read(_PWV)
            dk = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, 1000, 2 * klen + _PWV)
            if dk[2 * klen:] != pwv:
                raise ValueError("wrong ZIP password")
            self._ctr = _ctr(dk[:klen], 0)
            self._mac = hmac.new(dk[klen:2 * klen], digestmod=hashlib.sha1)
            self._left = csize - klen // 2 - _PWV - _MAC
            self._crc = None                        # AE-2: the HMAC protects the data
        else:
            self._left = csize
        if method not in (0, 8):
            raise ValueError(f"unsupported ZIP compression method {method}")
        self._inflate = zlib.decompressobj(-15) if method == 8 else None
        self._buf = b""
        self._eof = False

    def readable(self):
        return True

    def _more(self) -> bool:
        if self._eof:
            return False
        if self._left <= 0:
            out = self._inflate.flush() if self._inflate else b""
            self._finish()
            self._buf += out
            return bool(out)
        ct = self.f.read(min(_CHUNK, self._left))
        if not ct:
            raise ValueError("ZIP data is truncated")
        self._left -= len(ct)
        if self._ctr is not None:
            self._mac.update(ct)
            ct = self._ctr.encrypt(ct)          # CTR: decrypting = encrypting
        out = self._inflate.decompress(ct) if self._inflate else ct
        if self._crc is not None:
            self._crc_now = zlib.crc32(out, self._crc_now)
        self._buf += out
        return True

    def _finish(self):
        self._eof = True
        if self._mac is not None:
            if not hmac.compare_digest(self.f.read(_MAC), self._mac.digest()[:_MAC]):
                raise ValueError("ZIP authentication code mismatch (file damaged or altered)")
        elif self._crc is not None and self._crc_now != self._crc:
            raise ValueError("ZIP CRC mismatch (file damaged)")

    def readinto(self, b) -> int:
        while not self._buf and self._more():
            pass
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            parts = [self._buf]
            self._buf = b""
            while self._more():
                parts.append(self._buf)
                self._buf = b""
            return b"".join(parts)
        while len(self._buf) < n and self._more():
            pass
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        try:
            self.f.close()
        finally:
            super().close()


def read_member(path, password: str = DEFAULT_PASSWORD, limit: Optional[int] = None) -> bytes:
    """The decrypted content (in memory only). limit: read at most that many bytes."""
    with AesZipReader(path, password) as r:
        return r.read() if limit is None else r.read(limit)


# ================================================================ packing
def pack_stream(src, dst: str, member: str, password: str = DEFAULT_PASSWORD) -> Dict[str, Any]:
    """Write a readable stream into a new protected ZIP `dst` (via a temporary
    name, so a half-written ZIP never carries the final name). Returns the metadata."""
    tmp = dst + TMP_SUFFIX
    w = AesZipWriter(tmp, member, password)
    try:
        off = 0
        while True:
            b = src.read(_CHUNK)
            if not b:
                break
            off += w.write_at(off, b)
        meta = w.finish()
    except BaseException:
        w.abort()
        raise
    os.replace(tmp, dst)
    return meta


def pack_file(src, password: str = DEFAULT_PASSWORD, dst: Optional[str] = None,
              remove: bool = True) -> str:
    """Put an existing plain file into <src>.zip and delete the plain copy
    (Volatility 2 output, files dumped before protection existed)."""
    src = str(src)
    dst = dst or src + SUFFIX
    stem, ext = os.path.splitext(src)
    k = 1
    while os.path.exists(dst):
        dst = f"{stem}-{k}{ext}{SUFFIX}"
        k += 1
    with open(src, "rb") as f:
        pack_stream(f, dst, os.path.basename(src), password)
    if remove:
        os.remove(src)
    return dst


# ======================================================= Volatility 3 hook
def vol3_handler_class(base):
    """A Volatility 3 CLI file handler (subclass of the CLI's CLIFileHandler)
    that writes every plugin output straight into <final name>.zip. Used by
    the RAMBreaker patch of volatility3/cli/__init__.py when RAMBREAKER_SAFE_ZIP=1."""
    import tempfile
    password = os.environ.get(ENV_PW) or DEFAULT_PASSWORD

    class RBSafeZipFileHandler(base):
        def __init__(self, filename: str):
            base.__init__(self, filename)
            outdir = os.path.dirname(self._get_final_filename())    # creates the folder
            fd, self._tmp = tempfile.mkstemp(suffix=TMP_SUFFIX, prefix="tmp_", dir=outdir)
            os.close(fd)
            self._zw = AesZipWriter(self._tmp, self.preferred_filename, password)
            self._pos = 0

        def readable(self):
            return True

        def writable(self):
            return True

        def seekable(self):
            return True

        def write(self, b) -> int:
            n = self._zw.write_at(self._pos, b)
            self._pos += n
            return n

        def seek(self, offset: int, whence: int = 0) -> int:
            p = offset if whence == 0 else self._pos + offset if whence == 1 else self._zw.size + offset
            if p < 0:
                raise ValueError("negative seek position")
            self._pos = p
            return p

        def tell(self) -> int:
            return self._pos

        def truncate(self, size=None) -> int:
            size = self._pos if size is None else size
            self._zw.truncate(size)
            return size

        def readinto(self, b) -> int:
            d = self._zw.read_at(self._pos, len(b))
            b[:len(d)] = d
            self._pos += len(d)
            return len(d)

        def flush(self):
            pass

        def close(self):
            if self.closed:
                return None
            try:
                plain = self._get_final_filename()
                target, k = plain + SUFFIX, 1
                while os.path.exists(target):
                    stem, ext = os.path.splitext(plain)
                    target = f"{stem}-{k}{ext}{SUFFIX}"
                    k += 1
                self._zw.finish()
                os.replace(self._tmp, target)
                self.preferred_filename = os.path.basename(target)
            except BaseException:
                self._zw.abort()
                raise
            finally:
                io.RawIOBase.close(self)
            return None

    return RBSafeZipFileHandler
