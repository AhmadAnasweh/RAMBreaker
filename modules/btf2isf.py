#!/usr/bin/env python3
"""btf2isf.py — build a Volatility3 Linux ISF from the BTF + kallsyms that live
INSIDE a memory image. Standalone experiment (NOT wired into the toolkit).

Stage 1 (this file, so far): LiME parsing, VMCOREINFO recovery, kernel banner.
More stages appended as they are validated.
"""
import base64, hashlib, json, lzma, os, re, struct, sys

LIME_MAGIC = 0x4C694D45  # "EMiL"
__START_KERNEL_map = 0xFFFFFFFF80000000


class Image:
    """Raw physical view over a LiME (or flat raw) image."""
    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.f = open(path, "rb")
        self.ranges = self._parse_lime()   # (s_addr, e_addr, file_off, length)
        if not self.ranges:
            # flat raw: treat whole file as phys 0..size-1
            self.ranges = [(0, self.size - 1, 0, self.size)]

    def _parse_lime(self):
        ranges = []
        pos = 0
        while pos + 32 <= self.size:
            self.f.seek(pos)
            hdr = self.f.read(32)
            if len(hdr) < 32:
                break
            magic, version, s_addr, e_addr = struct.unpack_from("<IIQQ", hdr, 0)
            if magic != LIME_MAGIC:
                break
            length = e_addr - s_addr + 1
            if length <= 0 or length > self.size:
                break
            data_off = pos + 32
            ranges.append((s_addr, e_addr, data_off, length))
            pos = data_off + length
        return ranges

    def file_to_phys(self, foff):
        for s, e, fo, ln in self.ranges:
            if fo <= foff < fo + ln:
                return s + (foff - fo)
        return None

    def phys_to_file(self, paddr):
        for s, e, fo, ln in self.ranges:
            if s <= paddr <= e:
                return fo + (paddr - s)
        return None

    def phys_read(self, paddr, size):
        """Read `size` bytes of physical memory, spanning ranges; gaps -> zeros."""
        out = bytearray()
        while size > 0:
            fo = self.phys_to_file(paddr)
            if fo is None:
                # find next range start >= paddr
                nxt = min((s for s, e, f, l in self.ranges if s > paddr), default=None)
                if nxt is None:
                    out += b"\x00" * size
                    break
                gap = min(size, nxt - paddr)
                out += b"\x00" * gap
                paddr += gap
                size -= gap
                continue
            # bytes available in this range from fo
            for s, e, f, l in self.ranges:
                if f <= fo < f + l:
                    avail = (f + l) - fo
                    break
            n = min(size, avail)
            self.f.seek(fo)
            out += self.f.read(n)
            paddr += n
            size -= n
        return bytes(out)

    def detect_vmware_hole(self, phys_base, stext_va, swapper_va):
        """Flat raw dumps (VMware .vmem, QEMU) store RAM as [low][high] with a
        PCI hole below 4 GB: guest-phys >= 4 GB is stored at file offset
        (phys - 4 GB + low_size). A naive phys==file_offset map then can't reach
        a kernel loaded high (phys_base >= 4 GB), as with linux.vmem.

        Recover the low_size split with zero external metadata: it is the single
        value that makes the _stext page-table walk land exactly on _stext's
        linear-map physical address. On success, install a 2-range map so the
        existing range-aware reads/scan transparently handle the hole.
        Returns low_size (L) or None (no hole / not a flat image)."""
        HIGH = 0x100000000
        if len(self.ranges) != 1 or self.ranges[0][0] != 0:
            return None                       # LiME etc. already carries a map
        dtb = kern_va_to_phys_linear(swapper_va, phys_base)
        want = kern_va_to_phys_linear(stext_va, phys_base)
        if not (dtb and stext_va and want):
            return None
        if PageWalk(self, dtb).translate(stext_va) == want:
            return None                       # flat map already reaches kernel
        saved, size = self.ranges, self.size
        # nice boundaries first (typical top-of-low-RAM), then a 1 MB sweep
        common = [0xC0000000, 0xE0000000, 0x80000000, 0xBF000000,
                  0xDD000000, 0xDE000000, 0x40000000]
        for L in common + list(range(0x40000000, min(HIGH, size), 0x100000)):
            self.ranges = [(0, L - 1, 0, L),
                           (HIGH, HIGH + (size - L) - 1, L, size - L)]
            try:
                if PageWalk(self, dtb).translate(stext_va) == want:
                    return L
            except Exception:
                pass
        self.ranges = saved
        return None

    def scan(self, needle, limit=None):
        """Return a list of FILE offsets of every occurrence of needle.

        Uses its OWN file handle (not self.f) so the caller is free to seek/read
        self.f while processing the results.
        """
        CH = 64 * 1024 * 1024
        ov = len(needle) - 1
        out = []
        with open(self.path, "rb") as sf:
            base = 0
            prev = b""
            while True:
                buf = sf.read(CH)
                if not buf:
                    break
                data = prev + buf
                i = 0
                while True:
                    j = data.find(needle, i)
                    if j < 0:
                        break
                    out.append(base - len(prev) + j)
                    if limit and len(out) >= limit:
                        return out
                    i = j + 1
                base += len(buf)
                prev = buf[-ov:] if ov else b""
        return out


def find_vmcoreinfo(img):
    """Locate + parse the VMCOREINFO note. Returns dict of parsed keys.

    Anchor on 'OSRELEASE=' (unique to VMCOREINFO). The kernel also carries the
    printf *template* literal "OSRELEASE=%s\\n" in .rodata, which parses to a
    junk note with OSRELEASE=%s; score every candidate and keep the richest real
    note (most SYMBOL()/NUMBER()/PAGESIZE keys), so the template never wins.
    """
    best, best_score = {}, -1
    for foff in img.scan(b"OSRELEASE=", limit=32):
        img.f.seek(max(0, foff - 4))
        blob = img.f.read(16384)
        start = blob.find(b"OSRELEASE=")
        text = blob[start:]
        end = text.find(b"\x00")
        text = text[:end if end >= 0 else len(text)].decode("ascii", "replace")
        info = {"_file_off": foff, "_raw": text}
        for line in text.splitlines():
            if "=" in line:
                key, _, val = line.partition("=")
                info[key.strip()] = val.strip()
        if info.get("OSRELEASE", "%s") == "%s":
            continue                                   # the .rodata template
        # richness score: real notes have PAGESIZE + many SYMBOL()/NUMBER() keys
        score = sum(1 for k in info if k.startswith(("SYMBOL(", "NUMBER(",
                    "OFFSET(", "SIZE(", "LENGTH(", "PAGESIZE")))
        if score > best_score:
            best, best_score = info, score
    return best


def find_banner(img):
    # Require a real version (digits) right after "Linux version " so we skip the
    # kernel's printf template literal "Linux version %d.%d.%d" that also lives in
    # memory (same trap as the OSRELEASE=%s VMCOREINFO template).
    for foff in img.scan(b"Linux version ", limit=32):
        img.f.seek(foff)
        raw = img.f.read(512)
        m = re.match(rb"Linux version \d+\.\d+[ -~]+", raw)
        if m and b"(" in m.group(0):        # genuine banners carry a "(builder@host)"
            return m.group(0).decode("ascii", "replace")
    return ""


# ---------------------------------------------------------------------------
# Stage 2 — kernel address translation + BTF extraction
# ---------------------------------------------------------------------------

def kern_va_to_phys_linear(va, phys_base):
    """Kernel-image (text/rodata) linear map: __pa(x)=x-__START_KERNEL_map+phys_base."""
    if va < __START_KERNEL_map:
        return None
    return va - __START_KERNEL_map + phys_base


class PageWalk:
    """Minimal x86-64 4-level page-table walker over an Image, given the DTB."""
    def __init__(self, img, dtb):
        self.img = img
        self.dtb = dtb & 0x000FFFFFFFFFF000

    def _ent(self, table_phys, idx):
        raw = self.img.phys_read(table_phys + idx * 8, 8)
        if len(raw) < 8:
            return 0
        return struct.unpack("<Q", raw)[0]

    def translate(self, va):
        va &= (1 << 48) - 1
        pml4 = self._ent(self.dtb, (va >> 39) & 0x1FF)
        if not (pml4 & 1):
            return None
        pdpt_base = pml4 & 0x000FFFFFFFFFF000
        pdpt = self._ent(pdpt_base, (va >> 30) & 0x1FF)
        if not (pdpt & 1):
            return None
        if pdpt & 0x80:  # 1 GiB page
            return (pdpt & 0x000FFFFFC0000000) | (va & 0x3FFFFFFF)
        pd_base = pdpt & 0x000FFFFFFFFFF000
        pd = self._ent(pd_base, (va >> 21) & 0x1FF)
        if not (pd & 1):
            return None
        if pd & 0x80:  # 2 MiB page
            return (pd & 0x000FFFFFFFE00000) | (va & 0x1FFFFF)
        pt_base = pd & 0x000FFFFFFFFFF000
        pte = self._ent(pt_base, (va >> 12) & 0x1FF)
        if not (pte & 1):
            return None
        return (pte & 0x000FFFFFFFFFF000) | (va & 0xFFF)

    def vread(self, va, size):
        """Read `size` bytes of kernel virtual memory, page by page."""
        out = bytearray()
        while size > 0:
            p = self.translate(va)
            page_left = 0x1000 - (va & 0xFFF)
            n = min(size, page_left)
            if p is None:
                out += b"\x00" * n
            else:
                out += self.img.phys_read(p, n)
            va += n
            size -= n
        return bytes(out)


BTF_MAGIC = b"\x9f\xeb\x01"


def _btf_valid_header(hdr):
    if len(hdr) < 24:
        return None
    magic, ver, flags, hdr_len = struct.unpack_from("<HBBI", hdr, 0)
    if magic != 0xEB9F or ver != 1 or hdr_len != 24:
        return None
    type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", hdr, 8)
    if type_off != 0 or str_off != type_len:
        return None
    if not (0 < type_len < 64 * 1024 * 1024 and 0 < str_len < 64 * 1024 * 1024):
        return None
    return type_len, str_len


def _btf_looks_clean(blob):
    """A correctly-reassembled vmlinux BTF: header valid AND its string section
    holds real kernel type names."""
    v = _btf_valid_header(blob[:24])
    if not v:
        return False
    type_len, str_len = v
    s = blob[24 + type_len: 24 + type_len + str_len]
    return (len(s) == str_len and s[:1] == b"\x00"
            and b"task_struct" in s and b"init_task" in s)


def extract_btf(img, phys_base, dtb):
    """Find + cleanly extract the vmlinux base BTF. Returns (blob, how, phys)."""
    print("[btf] scanning for BTF blobs...")
    cands = []
    for foff in img.scan(BTF_MAGIC):
        hdr = img.phys_read(img.file_to_phys(foff), 24) if False else None
        img.f.seek(foff)
        hdr = img.f.read(24)
        v = _btf_valid_header(hdr)
        if v:
            type_len, str_len = v
            total = 24 + type_len + str_len
            if total > 1_000_000:            # only base-vmlinux-sized blobs
                cands.append((foff, total))
    cands.sort(key=lambda c: -c[1])
    print(f"[btf] {len(cands)} large candidate(s): "
          + ", ".join(f"@file0x{o:x}({t/1024/1024:.2f}MB)" for o, t in cands[:6]))

    walker = PageWalk(img, dtb) if dtb else None
    for foff, total in cands:
        phys = img.file_to_phys(foff)
        # (a) physical-contiguous copy?
        img.f.seek(foff)
        blob = img.f.read(total)
        if _btf_looks_clean(blob):
            return blob, "physical-contiguous", phys
        # (b) virtual reassembly via kernel-image linear map + page walk
        if walker:
            va = kern_va_to_phys_linear  # placeholder to satisfy linters
            va = None
            # this blob's kernel VA (if it's the in-image .BTF)
            va = phys - phys_base + __START_KERNEL_map
            vblob = walker.vread(va, total)
            if _btf_looks_clean(vblob):
                return vblob, f"virtual-reassembled @VA 0x{va:x}", phys
    return None, "not found", None


# ---------------------------------------------------------------------------
# Stage 3 — pure-Python BTF parser  ->  ISF types (base_types/user_types/enums)
# ---------------------------------------------------------------------------
(K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM, K_FWD, K_TYPEDEF, K_VOLATILE,
 K_CONST, K_RESTRICT, K_FUNC, K_FUNC_PROTO, K_VAR, K_DATASEC, K_FLOAT,
 K_DECL_TAG, K_TYPE_TAG, K_ENUM64) = range(1, 20)

_TRANSPARENT = {K_TYPEDEF, K_CONST, K_VOLATILE, K_RESTRICT, K_TYPE_TAG}


class BTF:
    def __init__(self, blob):
        magic, ver, flags, hdr_len = struct.unpack_from("<HBBI", blob, 0)
        assert magic == 0xEB9F and ver == 1, "bad BTF header"
        type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", blob, 8)
        self.types = [None]           # index 0 = void
        tsec = blob[hdr_len + type_off: hdr_len + type_off + type_len]
        self.strs = blob[hdr_len + str_off: hdr_len + str_off + str_len]
        self._parse_types(tsec)
        self._size_memo = {}

    def s(self, off):
        if off == 0:
            return ""
        e = self.strs.find(b"\x00", off)
        return self.strs[off:e].decode("utf-8", "replace")

    def _parse_types(self, tsec):
        p, n = 0, len(tsec)
        while p + 12 <= n:
            name_off, info, sz = struct.unpack_from("<III", tsec, p)
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kflag = (info >> 31) & 1
            p += 12
            t = {"kind": kind, "name_off": name_off, "sz": sz, "vlen": vlen,
                 "kflag": kflag}
            if kind == K_INT:
                (enc,) = struct.unpack_from("<I", tsec, p); p += 4
                t["int_bits"] = enc & 0xFF
                t["int_enc"] = (enc >> 24) & 0x0F
            elif kind == K_ARRAY:
                et, it, ne = struct.unpack_from("<III", tsec, p); p += 12
                t["arr_elem"] = et; t["arr_n"] = ne
            elif kind in (K_STRUCT, K_UNION):
                mems = []
                for _ in range(vlen):
                    mn, mt, mo = struct.unpack_from("<III", tsec, p); p += 12
                    mems.append((mn, mt, mo))
                t["members"] = mems
            elif kind == K_ENUM:
                cs = []
                for _ in range(vlen):
                    cn, cv = struct.unpack_from("<Ii", tsec, p); p += 8
                    cs.append((cn, cv))
                t["consts"] = cs
            elif kind == K_ENUM64:
                cs = []
                for _ in range(vlen):
                    cn, lo, hi = struct.unpack_from("<III", tsec, p); p += 12
                    cs.append((cn, (hi << 32) | lo))
                t["consts"] = cs
            elif kind == K_FUNC_PROTO:
                p += vlen * 8
            elif kind == K_VAR:
                p += 4
            elif kind == K_DATASEC:
                secs = []
                for _ in range(vlen):
                    vt, vo, vs = struct.unpack_from("<III", tsec, p); p += 12
                    secs.append((vt, vo, vs))
                t["secinfo"] = secs
            elif kind == K_DECL_TAG:
                p += 4
            # PTR/TYPEDEF/VOLATILE/CONST/RESTRICT/FUNC/FWD/FLOAT/TYPE_TAG: no extra
            self.types.append(t)

    def resolve(self, tid):
        """Follow transparent qualifiers/typedefs to the concrete type id."""
        seen = 0
        while tid and tid < len(self.types) and seen < 32:
            t = self.types[tid]
            if t and t["kind"] in _TRANSPARENT:
                tid = t["sz"]; seen += 1
            else:
                return tid
        return tid

    def size_of(self, tid):
        if tid in self._size_memo:
            return self._size_memo[tid]
        self._size_memo[tid] = 0            # cycle guard
        v = 0
        tid = self.resolve(tid)
        if tid and tid < len(self.types):
            t = self.types[tid]
            k = t["kind"]
            if k in (K_INT, K_FLOAT, K_STRUCT, K_UNION, K_ENUM, K_ENUM64):
                v = t["sz"]
            elif k == K_PTR:
                v = 8
            elif k == K_ARRAY:
                v = t["arr_n"] * self.size_of(t["arr_elem"])
        self._size_memo[tid] = v
        return v


def build_isf_types(btf):
    """Return (base_types, user_types, enums, name_of[tid])."""
    base_types = {
        "void":    {"size": 0, "signed": False, "kind": "void", "endian": "little"},
        "pointer": {"size": 8, "signed": False, "kind": "int",  "endian": "little"},
    }
    user_types, enums = {}, {}
    name_of = {0: "void"}

    def uniq(base, tid):
        return base if base else f"unnamed_{tid}"

    # First pass: assign a name to every named/anonymous aggregate + base type.
    for tid, t in enumerate(btf.types):
        if t is None:
            continue
        nm = btf.s(t["name_off"])
        k = t["kind"]
        if k == K_INT or k == K_FLOAT:
            name_of[tid] = nm or f"__anon_base_{tid}"
        elif k in (K_STRUCT, K_UNION, K_ENUM, K_ENUM64):
            name_of[tid] = uniq(nm, tid)
        elif k == K_FWD:
            name_of[tid] = nm or f"unnamed_{tid}"

    # Name anonymous aggregates after a typedef that references them (dwarf2json
    # behavior). A typedef'd anonymous struct like `typedef struct { u64 val; }
    # kernel_cap_t` must surface as user_type "kernel_cap_t" so Vol3 extensions
    # keyed on that name (get_capabilities(), etc.) attach — otherwise it stays
    # "unnamed_<tid>" and the plugin AttributeErrors.
    used_names = set(name_of.values())
    for tid, t in enumerate(btf.types):
        if t is None or t["kind"] != K_TYPEDEF:
            continue
        tdname = btf.s(t["name_off"])
        if not tdname or tdname in used_names:
            continue
        rid = btf.resolve(tid)
        if rid and rid < len(btf.types):
            rt = btf.types[rid]
            if rt and rt["kind"] in (K_STRUCT, K_UNION) and \
                    name_of.get(rid, "").startswith("unnamed_"):
                name_of[rid] = tdname
                used_names.add(tdname)

    def descriptor(tid, depth=0):
        if depth > 40 or not tid:
            return {"kind": "base", "name": "void"}
        rid = btf.resolve(tid)
        if not rid or rid >= len(btf.types):
            return {"kind": "base", "name": "void"}
        t = btf.types[rid]
        k = t["kind"]
        if k == K_INT or k == K_FLOAT:
            return {"kind": "base", "name": name_of.get(rid, "void")}
        if k == K_PTR:
            return {"kind": "pointer", "subtype": descriptor(t["sz"], depth + 1)}
        if k == K_ARRAY:
            return {"kind": "array", "count": t["arr_n"],
                    "subtype": descriptor(t["arr_elem"], depth + 1)}
        if k == K_STRUCT:
            return {"kind": "struct", "name": name_of[rid]}
        if k == K_UNION:
            return {"kind": "union", "name": name_of[rid]}
        if k in (K_ENUM, K_ENUM64):
            return {"kind": "enum", "name": name_of[rid]}
        if k == K_FWD:
            return {"kind": "struct", "name": name_of[rid]}
        if k in (K_FUNC, K_FUNC_PROTO):
            return {"kind": "function"}
        return {"kind": "base", "name": "void"}

    # base_types from INT/FLOAT
    for tid, t in enumerate(btf.types):
        if t is None:
            continue
        if t["kind"] == K_INT:
            enc = t["int_enc"]
            kind = "char" if (enc & 2) else ("bool" if (enc & 4) else "int")
            base_types[name_of[tid]] = {
                "size": t["sz"], "signed": bool(enc & 1),
                "kind": kind, "endian": "little"}
        elif t["kind"] == K_FLOAT:
            base_types[name_of[tid]] = {
                "size": t["sz"], "signed": True, "kind": "float", "endian": "little"}

    # enums
    ENB = {1: "unsigned char", 2: "short unsigned int",
           4: "unsigned int", 8: "long unsigned int"}
    for tid, t in enumerate(btf.types):
        if t is None or t["kind"] not in (K_ENUM, K_ENUM64):
            continue
        nm = name_of[tid]
        consts = {}
        for cn, cv in t.get("consts", []):
            cname = btf.s(cn)
            if cname:
                consts[cname] = cv
        cur = enums.get(nm)
        if cur and len(cur["constants"]) >= len(consts):
            continue
        enums[nm] = {"size": t["sz"], "base": ENB.get(t["sz"], "unsigned int"),
                     "constants": consts}

    # user_types (struct/union), with bitfield-aware offsets
    for tid, t in enumerate(btf.types):
        if t is None or t["kind"] not in (K_STRUCT, K_UNION):
            continue
        nm = name_of[tid]
        fields = {}
        anon_idx = 0
        for mn, mt, mo in t.get("members", []):
            fname = btf.s(mn)
            is_anon = not fname
            if is_anon:
                # Anonymous struct/union member. Vol3's _reduce_fields flattens
                # its fields into the parent iff the field carries "anonymous":
                # true (the field NAME is irrelevant); its type must reference a
                # real named user_type (descriptor() emits 'unnamed_<tid>', which
                # we register below). This is what makes mm_struct.pgd resolve.
                fname = f"unnamed_field_{anon_idx}"
                anon_idx += 1
            if t["kflag"]:
                bit_off = mo & 0xFFFFFF
                bit_len = (mo >> 24) & 0xFF
            else:
                bit_off = mo
                bit_len = 0
            if bit_len:  # bitfield
                base_bytes = btf.size_of(mt) or 4
                base_bits = base_bytes * 8
                byte_off = (bit_off // base_bits) * base_bytes
                bit_pos = bit_off - byte_off * 8
                fields[fname] = {
                    "offset": byte_off,
                    "type": {"kind": "bitfield", "bit_position": bit_pos,
                             "bit_length": bit_len, "type": descriptor(mt)}}
            else:
                fields[fname] = {"offset": bit_off // 8, "type": descriptor(mt)}
            if is_anon:
                fields[fname]["anonymous"] = True
        entry = {"kind": "struct" if t["kind"] == K_STRUCT else "union",
                 "size": t["sz"], "fields": fields}
        cur = user_types.get(nm)
        # on name collision keep the richer definition (defined > fwd/empty)
        if cur and (len(cur["fields"]) >= len(fields) and cur["size"] >= t["sz"]):
            continue
        user_types[nm] = entry

    return base_types, user_types, enums, name_of


# ---------------------------------------------------------------------------
# Stage 4 — bootstrap symbols (init_task by signature + banner + VMCOREINFO)
# ---------------------------------------------------------------------------

def phys_to_kern_va(phys, phys_base):
    """Kernel-image physical -> virtual (inverse of the linear __pa formula)."""
    return phys - phys_base + __START_KERNEL_map


def full_banner_bytes(img):
    """Return (banner_bytes_incl_newline, file_off) for the kernel .rodata banner."""
    best = None
    for foff in img.scan(b"Linux version "):
        img.f.seek(foff)
        raw = img.f.read(512)
        nl = raw.find(b"\n")
        if nl < 0:
            continue
        b = raw[:nl + 1]
        if b"gcc" in b or b"clang" in b or b"SMP" in b:
            return b, foff
        if best is None:
            best = (b, foff)
    return best if best else (b"", None)


def find_init_task(img, phys_base, comm_off, pid_off, stext_va):
    """Locate init_task by its 'swapper/0' comm signature, validated by pid==0.
    Returns its kernel VA, or None."""
    lo, hi = stext_va, stext_va + 128 * 1024 * 1024
    for needle in (b"swapper/0\x00", b"swapper\x00"):
        for foff in img.scan(needle):
            phys = img.file_to_phys(foff)
            if phys is None:
                continue
            comm_va = phys_to_kern_va(phys, phys_base)
            it_va = comm_va - comm_off
            if not (lo <= it_va <= hi):
                continue
            pid_phys = phys - (comm_off - pid_off)      # pid sits before comm
            pid = struct.unpack("<i", img.phys_read(pid_phys, 4))[0]
            if pid == 0:
                return it_va
    return None


# ---------------------------------------------------------------------------
# kallsyms — decode the kernel's built-in symbol table from the image
# ---------------------------------------------------------------------------

def _find_token_table(R):
    """Locate kallsyms_token_table/_token_index (self-validating): 256 u16 that
    are monotonic with small steps, starting at 0, indexing a NUL-separated token
    blob. Returns (token_table_start, token_index[256]) or (None, None)."""
    import numpy as np
    n = len(R)
    for align in (0, 1):
        m = (n - align) // 2
        u = np.frombuffer(R, dtype="<u2", count=m, offset=align)
        d = np.diff(u.astype(np.int64))
        good = (d >= 1) & (d <= 64)
        c = np.concatenate(([0], np.cumsum(good)))
        W = 255
        if len(c) <= W:
            continue
        wsum = c[W:] - c[:-W]
        starts = np.where((wsum == W) & (u[:len(wsum)] == 0))[0]
        for i in starts.tolist():
            p = align + i * 2
            if p < 1 or p + 512 > n:
                continue
            idx = struct.unpack_from("<256H", R, p)
            if idx[0] != 0 or idx[255] >= 8192 or R[p - 1] != 0:
                continue
            e = p - 1
            s = e
            while s > 0 and R[s - 1] != 0:
                s -= 1
            tt = s - idx[255]
            if tt < 0:
                continue
            if idx[1] >= 1 and (tt + idx[1] - 1 < 0 or R[tt + idx[1] - 1] != 0):
                continue
            return tt, list(idx)
    return None, None


def _find_names_end(R, tt):
    """kallsyms_markers is a monotonic u32[] ending just before the token table
    (tt), starting at markers[0]==0. Its start == names_end. Returns
    (names_end, marker_count) or (None, 0)."""
    def u32(p):
        return struct.unpack_from("<I", R, p)[0]
    e = tt
    while e >= 8 and u32(e - 4) == 0:      # strip padding between markers and tt
        e -= 4
    markers_end = e
    p = e - 4
    while p >= 4:
        if u32(p - 4) > u32(p):            # monotonicity broken (going back)
            break
        p -= 4
        if u32(p) == 0:                    # markers[0]
            break
    return p, (markers_end - p) // 4


def _kallsyms_bases(R, names_end, K):
    """kallsyms_num_syms sits just before kallsyms_names, preceded by
    relative_base (u64). Anchor on num_syms by value (~K*256) with a kernel-VA
    relative_base in front. Yields (names_start, relative_base, num, offsets)."""
    import numpy as np
    u32 = np.frombuffer(R, dtype="<u4", count=len(R) // 4)
    lo, hi = max(1, (K - 1) * 256), K * 256 + 256
    for pi in np.where((u32 >= lo) & (u32 <= hi))[0].tolist():
        P = pi * 4
        if P < 8:
            continue
        rb = struct.unpack_from("<Q", R, P - 8)[0]
        if not (0xFFFFFFFF80000000 <= rb <= 0xFFFFFFFFC0000000):
            continue
        num = int(u32[pi])
        off_start = P - 8 - num * 4
        if off_start < 0:
            continue
        for nsz in (4, 8):
            yield (P + nsz, rb, num, off_start)


def _decode_names(R, names_start, num, off_start, rb, tokens, percpu):
    """Walk kallsyms_names, expanding each token-compressed entry, and pair it
    with its address from kallsyms_offsets. Returns {name: runtime_va}."""
    syms = {}
    pos = names_start
    n = len(R)
    for i in range(num):
        if pos >= n:
            return None
        ln = R[pos]; pos += 1
        if ln & 0x80:                      # extended length (big-symbol kernels)
            ln = (ln & 0x7F) | (R[pos] << 7); pos += 1
        if pos + ln > n:
            return None
        parts = [tokens[R[pos + j]] for j in range(ln)]
        pos += ln
        full = b"".join(parts)
        name = full[1:].decode("ascii", "replace")   # full[0] = nm-style type char
        off = struct.unpack_from("<i", R, off_start + i * 4)[0]
        if percpu:
            addr = off if off >= 0 else (rb - 1 - off)
        else:
            addr = rb + (off & 0xFFFFFFFF)
        if name and name not in syms:
            syms[name] = addr
    return syms


def _names_landing(R, names_start, num):
    """Walk num name-entries from names_start; return the byte position after the
    last one (must equal names_end for a correct locate)."""
    pos, cnt, n = names_start, 0, len(R)
    while cnt < num and pos < n:
        ln = R[pos]; pos += 1
        if ln & 0x80:
            ln = (ln & 0x7F) | (R[pos] << 7); pos += 1
        pos += ln; cnt += 1
    return cnt, pos


def _read_kva(img, phys_base, va, n):
    """Read n bytes at a kernel linear-mapped virtual address."""
    return img.phys_read(kern_va_to_phys_linear(va, phys_base), n)


def _decode_names_arr(offs, names, num, rb, tokens, percpu):
    """Deterministic decode from separate kallsyms_offsets + kallsyms_names
    buffers (addresses come from the offsets array, not embedded)."""
    syms = {}
    pos, N = 0, len(names)
    for i in range(num):
        if pos >= N:
            return None
        ln = names[pos]; pos += 1
        if ln & 0x80:
            ln = (ln & 0x7F) | (names[pos] << 7); pos += 1
        if pos + ln > N:
            return None
        full = b"".join(tokens[names[pos + j]] for j in range(ln))
        pos += ln
        name = full[1:].decode("ascii", "replace")
        off = struct.unpack_from("<i", offs, i * 4)[0]
        if percpu:
            addr = off if off >= 0 else (rb - 1 - off)
        else:
            addr = rb + (off & 0xFFFFFFFF)
        if name and name not in syms:
            syms[name] = addr
    return syms


def decode_kallsyms_vmcore(img, vmc, phys_base, known_init_task):
    """Deterministic kallsyms decode when VMCOREINFO exports the table symbols
    (kernels ~5.19+ add kallsyms_* to VMCOREINFO). No heuristics: read each
    array at its exact address. Returns {name: runtime_va} or None."""
    need = ("kallsyms_names", "kallsyms_num_syms", "kallsyms_token_table",
            "kallsyms_token_index", "kallsyms_offsets", "kallsyms_relative_base")
    A = {}
    for s in need:
        v = vmc.get(f"SYMBOL({s})")
        if not v:
            return None
        A[s] = int(v, 16)
    num = struct.unpack("<I", _read_kva(img, phys_base, A["kallsyms_num_syms"], 4))[0]
    if not (1000 < num < 5_000_000):
        return None
    rb = struct.unpack("<Q", _read_kva(img, phys_base, A["kallsyms_relative_base"], 8))[0]
    offs = _read_kva(img, phys_base, A["kallsyms_offsets"], num * 4)
    tidx = struct.unpack("<256H", _read_kva(img, phys_base, A["kallsyms_token_index"], 512))
    ttbuf = _read_kva(img, phys_base, A["kallsyms_token_table"], tidx[255] + 256)
    tokens = []
    for t in range(256):
        o = tidx[t]; e = ttbuf.find(b"\x00", o)
        tokens.append(ttbuf[o:e if e >= 0 else o])
    names = _read_kva(img, phys_base, A["kallsyms_names"], num * 24 + 4096)
    for percpu in (True, False):
        syms = _decode_names_arr(offs, names, num, rb, tokens, percpu)
        if syms and syms.get("init_task") == known_init_task:
            syms["_meta"] = {"num_syms": num, "relative_base": rb,
                             "percpu": percpu, "distinct": len(syms),
                             "src": "vmcoreinfo"}
            return syms
    return None


def decode_kallsyms(R, known_init_task):
    """Decode the full kallsyms table from kernel-image bytes R. Located via the
    token table + markers, and doubly validated: the name walk must land exactly
    on names_end AND init_task must decode to its known runtime address.
    Returns {name: runtime_va} (+ a '_meta' entry) or None."""
    tt, tidx = _find_token_table(R)
    if tt is None:
        return None
    tokens = []
    for t in range(256):
        o = tt + tidx[t]
        e = R.find(b"\x00", o)
        tokens.append(R[o:e if e >= 0 else o])
    names_end, K = _find_names_end(R, tt)
    if not names_end or K < 2:
        return None
    for names_start, rb, num, off_start in _kallsyms_bases(R, names_end, K):
        cnt, land = _names_landing(R, names_start, num)
        if cnt != num or abs(land - names_end) > 8:
            continue
        for percpu in (True, False):
            syms = _decode_names(R, names_start, num, off_start, rb, tokens, percpu)
            if syms and syms.get("init_task") == known_init_task:
                syms["_meta"] = {"num_syms": num, "relative_base": rb,
                                 "percpu": percpu, "distinct": len(syms)}
                return syms
    return None


def field_abs_offset(user_types, sname, field, base=0, depth=0):
    """Absolute byte offset of `field` in struct `sname`, descending through
    anonymous (`unnamed_field_*`) members. None if not found."""
    st = user_types.get(sname)
    if not st or depth > 6:
        return None
    for fn, fv in st["fields"].items():
        if fn == field:
            return base + fv["offset"]
        if fn.startswith("unnamed_field_") and fv["type"].get("kind") in ("struct", "union"):
            r = field_abs_offset(user_types, fv["type"]["name"], field,
                                 base + fv["offset"], depth + 1)
            if r is not None:
                return r
    return None


def _ru64(img, phys):
    d = img.phys_read(phys, 8)
    return struct.unpack("<Q", d)[0] if len(d) == 8 else 0


# Non-percpu kernel globals that Vol3 linux plugins dereference via
# object_from_symbol(); each is a direct struct instance (not a pointer), so the
# symbol's type is exactly the named struct. Applied only if the BTF defines it.
KNOWN_SYMBOL_TYPES = {
    "init_task": "task_struct", "init_mm": "mm_struct",
    "init_files": "files_struct", "init_fs": "fs_struct",
    "init_nsproxy": "nsproxy", "init_net": "net",
    "init_pid_ns": "pid_namespace", "init_uts_ns": "uts_namespace",
    "init_user_ns": "user_namespace", "init_cred": "cred",
    "modules": "list_head", "net_namespace_list": "list_head",
    "mod_tree": "mod_tree_root", "tk_core": "tk_core",
    # additional direct-struct globals various plugins dereference
    "socket_file_ops": "file_operations",
    "sockfs_dentry_operations": "dentry_operations",
    "tty_drivers": "list_head",
    "keyboard_notifier_list": "atomic_notifier_head",
    "crashing_kernel_kexec_image": "kimage",
}

# Scalar globals dereferenced via object_from_symbol() (e.g. capabilities'
# cap_last_cap). Value = BTF base-type name; applied only if the ISF defines it.
KNOWN_SYMBOL_BASE_TYPES = {
    "cap_last_cap": "unsigned int", "pidhash_shift": "unsigned int",
    "log_buf_len": "unsigned int", "nr_kernel_pages": "long unsigned int",
    "module_addr_min": "long unsigned int", "module_addr_max": "long unsigned int",
}

# Globals that are POINTERS to a struct (e.g. `struct kset *module_kset`).
# object_from_symbol() needs the pointer type, not the bare struct — check_modules
# and tty_check dereference module_kset. Value = pointed-to struct name.
KNOWN_SYMBOL_POINTER_TYPES = {
    "module_kset": "kset",
}

# Linker section symbols (`extern char _text[]`, …). Vol3 reads their ADDRESS via
# object_from_symbol (module address-range checks, tty_check, etc.); dwarf2json
# types them as a zero-length char array, so match that.
KNOWN_SYMBOL_CHAR_ARRAYS = (
    "_text", "_etext", "_stext", "_end", "_sdata", "_edata",
    "__bss_start", "__init_begin", "__init_end", "__end_of_kernel_reserve",
)


def _bootstrap_symbols(img, vmc, phys_base, user_types, stext_va, it, syms):
    """Fallback when kallsyms can't be decoded: find just the handful of symbols
    the Vol3 Linux stacker needs (init_task/init_mm/init_files) by signature."""
    if it and "init_task" not in syms:
        syms["init_task"] = {"address": it}
    if it and "init_files" not in syms:
        it_phys = it - __START_KERNEL_map + phys_base
        files_off = field_abs_offset(user_types, "task_struct", "files")
        if files_off is not None:
            v = _ru64(img, it_phys + files_off)
            if v > __START_KERNEL_map:
                syms["init_files"] = {"address": v}
    if "init_mm" not in syms:
        sw = vmc.get("SYMBOL(swapper_pg_dir)") or vmc.get("SYMBOL(init_top_pgt)")
        pgd_off = field_abs_offset(user_types, "mm_struct", "pgd")
        if sw and pgd_off is not None:
            for foff in img.scan(struct.pack("<Q", int(sw, 16))):
                phys = img.file_to_phys(foff)
                if phys is None:
                    continue
                cand = phys_to_kern_va(phys, phys_base) - pgd_off
                if stext_va <= cand <= stext_va + 64 * 1024 * 1024:
                    syms["init_mm"] = {"address": cand}
                    break


def build_symbols(img, vmc, phys_base, user_types, stext_va, base_types=None):
    kaslr = int(vmc.get("KERNELOFFSET", "0"), 16)
    banner, boff = full_banner_bytes(img)

    # init_task by signature — needed as the cross-check that validates a kallsyms
    # decode, and as the pslist anchor if kallsyms can't be found.
    comm_off = field_abs_offset(user_types, "task_struct", "comm")
    pid_off = field_abs_offset(user_types, "task_struct", "pid")
    it = find_init_task(img, phys_base, comm_off, pid_off, stext_va)

    syms = {}
    used_kallsyms = False
    if it:
        # Prefer the deterministic VMCOREINFO-address decode (kernels ~5.19+);
        # fall back to the heuristic in-.rodata scan (e.g. mint.lime's 5.15).
        ks = decode_kallsyms_vmcore(img, vmc, phys_base, it)
        if not ks:
            stext_phys = stext_va - __START_KERNEL_map + phys_base
            R = img.phys_read(stext_phys, 48 * 1024 * 1024)
            ks = decode_kallsyms(R, it)              # {name: runtime_va}
        if ks:
            meta = ks.pop("_meta", {})
            used_kallsyms = True
            for name, addr in ks.items():
                syms[name] = {"address": addr}
            print(f"[kallsyms] decoded {len(syms)} symbols "
                  f"(num_syms={meta.get('num_syms')}, percpu={meta.get('percpu')}, "
                  f"src={meta.get('src', 'scan')})")

    # VMCOREINFO fills any gap (e.g. swapper_pg_dir / init_top_pgt) not in kallsyms.
    for k, v in vmc.items():
        if k.startswith("SYMBOL(") and k.endswith(")"):
            name = k[len("SYMBOL("):-1]
            try:
                syms.setdefault(name, {"address": int(v, 16)})
            except ValueError:
                pass

    if not used_kallsyms:
        _bootstrap_symbols(img, vmc, phys_base, user_types, stext_va, it, syms)

    # kallsyms gives addresses but no types; Vol3's object_from_symbol() REQUIRES
    # a type on any symbol it dereferences (lsmod casts `modules`, etc.). The
    # kernel BTF only emits VARs for percpu vars, so we attach types to the
    # well-known non-percpu globals Vol3 dereferences, using the struct name only
    # when the BTF actually defines it (guards against a mis-mapping).
    for name, tname in KNOWN_SYMBOL_TYPES.items():
        if name in syms and tname in user_types:
            syms[name]["type"] = {"kind": "struct", "name": tname}
    for name, bt in KNOWN_SYMBOL_BASE_TYPES.items():
        if name in syms and (base_types is None or bt in base_types):
            syms[name]["type"] = {"kind": "base", "name": bt}
    for name, tname in KNOWN_SYMBOL_POINTER_TYPES.items():
        if name in syms and tname in user_types:
            syms[name]["type"] = {"kind": "pointer",
                                  "subtype": {"kind": "struct", "name": tname}}
    for name in KNOWN_SYMBOL_CHAR_ARRAYS:
        if name in syms:
            syms[name]["type"] = {"kind": "array", "count": 0,
                                  "subtype": {"kind": "base", "name": "char"}}

    # taint_flags: Vol3's tainting reads the in-memory taint_flag[] only if the
    # symbol is present AND typed; kallsyms gives no type/length, and a from-gap
    # array read produced wrong taint chars. Dropping the symbol makes Vol3 fall
    # back to its built-in taint table (correct chars) — as older ISFs do.
    syms.pop("taint_flags", None)
    if boff is not None:
        bva = phys_to_kern_va(img.file_to_phys(boff), phys_base)
        syms["linux_banner"] = {
            "address": bva,
            "type": {"kind": "array", "count": len(banner),
                     "subtype": {"kind": "base", "name": "char"}},
            "constant_data": base64.b64encode(banner).decode("ascii")}

    # Vol3 ISFs store LINK-TIME addresses (Vol3 re-adds KASLR). Convert every
    # kernel-image (>= __START_KERNEL_map) symbol; leave percpu absolutes alone.
    if kaslr:
        for e in syms.values():
            if e.get("address", 0) >= __START_KERNEL_map:
                e["address"] -= kaslr

    return syms, (banner if boff is not None else b""), it


# ---------------------------------------------------------------------------
# Stage 5 — assemble + write the ISF
# ---------------------------------------------------------------------------

def assemble_isf(base_types, user_types, enums, symbols, banner, blob):
    h = hashlib.sha256(blob).hexdigest()
    # schema (metadata_nix_item) only permits kind in {dwarf, symtab, system-map}
    tsrc = {"kind": "dwarf", "name": "vmlinux-BTF-from-image",
            "hash_type": "sha256", "hash_value": h}
    ssrc = {"kind": "symtab", "name": "vmlinux-BTF-from-image",
            "hash_type": "sha256", "hash_value": h}
    return {
        "metadata": {
            "producer": {"name": "btf2isf", "version": "0.1"},
            "format": "6.2.0",
            "linux": {"symbols": [ssrc], "types": [tsrc]},
        },
        "base_types": base_types,
        "user_types": user_types,
        "enums": enums,
        "symbols": symbols,
    }


def build_isf(image_path, out_dir=None, verbose=True):
    """Build a Volatility3 Linux ISF from the BTF + kallsyms embedded in
    `image_path`. Writes <Distro>_<kernel>_btf.json.xz into `out_dir` (or the
    current directory) and returns its path, or None on failure — e.g. no
    VMCOREINFO, no embedded BTF (kernel built without CONFIG_DEBUG_INFO_BTF),
    or init_task not found. Importable so the resolver can call it directly."""
    log = (lambda *a, **k: print(*a, **k)) if verbose else (lambda *a, **k: None)

    img = Image(image_path)
    log(f"[image] {image_path}  size={img.size} ({img.size/1024/1024:.0f} MB)")
    log(f"[lime]  {len(img.ranges)} physical range(s)")

    vmc = find_vmcoreinfo(img)
    log(f"[vmcoreinfo] found={'yes' if vmc else 'NO'} "
        f"({len([k for k in vmc if not k.startswith('_')])} keys)")
    if not vmc:
        log("[!] No VMCOREINFO note — cannot derive kernel addresses.")
        return None

    banner = find_banner(img)
    log(f"[banner] {banner[:120]}")

    # NUMBER(phys_base) is printed signed (%ld) and can be negative; the linear
    # map arithmetic handles that. Guard against a missing/empty value.
    try:
        phys_base = int(vmc.get("NUMBER(phys_base)") or "0")
    except ValueError:
        phys_base = 0
    stext_va = int(vmc.get("SYMBOL(_stext)", "0"), 16)
    swapper_va = int(vmc.get("SYMBOL(swapper_pg_dir)",
                             vmc.get("SYMBOL(init_top_pgt)", "0")), 16)
    # flat VMware/QEMU dumps hide the kernel behind a <4 GB PCI hole; recover the
    # low/high split so every later phys read reaches high memory correctly.
    L = img.detect_vmware_hole(phys_base, stext_va, swapper_va)
    if L is not None:
        log(f"[hole] flat dump: PCI hole low_size=0x{L:x} -> {len(img.ranges)} ranges")
    dtb = kern_va_to_phys_linear(swapper_va, phys_base)
    log(f"[addr] phys_base=0x{phys_base:x}  DTB={'0x%x' % dtb if dtb else 'None'}")
    if dtb and stext_va:
        want = kern_va_to_phys_linear(stext_va, phys_base)
        got = PageWalk(img, dtb).translate(stext_va)
        log(f"[walk] _stext -> {'0x%x' % got if got else 'None'} "
            f"(want 0x{want:x})  {'MATCH' if got == want else 'MISMATCH'}")

    # --- extract the BTF blob ---
    blob, how, phys = extract_btf(img, phys_base, dtb)
    if not blob:
        log(f"[btf] extraction FAILED: {how}")
        log("[!] No embedded BTF (kernel built without CONFIG_DEBUG_INFO_BTF, "
            "e.g. Ubuntu < 5.8 / Azure 5.4). Falling back to the dbgsym route.")
        return None
    log(f"[btf] EXTRACTED {len(blob)} bytes ({len(blob)/1024/1024:.2f} MB) via {how}")

    # --- types + symbols ---
    btf = BTF(blob)
    base_types, user_types, enums, name_of = build_isf_types(btf)
    log(f"[isf] base_types={len(base_types)} user_types={len(user_types)} "
        f"enums={len(enums)}")
    symbols, banner_b, it_va = build_symbols(img, vmc, phys_base, user_types,
                                             stext_va, base_types)
    log(f"[sym] {len(symbols)} symbols total")
    if not it_va:
        log("[!] init_task not found — pslist could not walk. Aborting.")
        return None

    # --- assemble + write ---
    isf = assemble_isf(base_types, user_types, enums, symbols, banner_b, blob)
    kver = vmc.get("OSRELEASE", "unknown")
    # distro-neutral name derived from the banner (Vol3 matches by banner hash,
    # not filename, so this is purely for human readability).
    distro = "linux"
    # most-specific first: Kali/Ubuntu banners also mention "Debian" (gcc build).
    for tag in ("Kali", "Ubuntu", "Fedora", "CentOS", "Arch", "SUSE", "Debian"):
        if tag.lower() in banner.lower():
            distro = tag
            break
    out_name = f"{distro}_{kver}_btf.json.xz"
    out_path = os.path.join(out_dir, out_name) if out_dir else out_name
    with lzma.open(out_path, "wt", encoding="utf-8") as fo:
        json.dump(isf, fo)
    log(f"[isf] WROTE {out_path}  ({os.path.getsize(out_path)/1024/1024:.2f} MB)")
    return out_path


def main():
    # fast iteration path: build ISF types from an already-extracted .btf blob
    if len(sys.argv) > 2 and sys.argv[1] == "--from-btf":
        blob = open(sys.argv[2], "rb").read()
        btf = BTF(blob)
        print(f"[btf] parsed {len(btf.types)-1} types, "
              f"{len(btf.strs)} bytes of strings")
        bt, ut, en, _ = build_isf_types(btf)
        print(f"[isf] base_types={len(bt)} user_types={len(ut)} enums={len(en)}")
        ts = ut.get("task_struct")
        if ts:
            f = ts["fields"]
            print(f"[chk] task_struct size={ts['size']} fields={len(f)}")
            for fn in ("comm", "pid", "tgid", "tasks", "mm", "parent", "state",
                       "__state", "cred"):
                if fn in f:
                    print(f"        .{fn:8s} @ {f[fn]['offset']:>5}  "
                          f"{json.dumps(f[fn]['type'])[:70]}")
        # spot-check a couple more well-known structs
        for s in ("mm_struct", "list_head", "cred", "pid"):
            if s in ut:
                print(f"[chk] {s}: size={ut[s]['size']} fields={len(ut[s]['fields'])}")
        return

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("usage: btf2isf.py <memory-image>\n"
              "  Builds a Volatility3 Linux ISF from the BTF + kallsyms inside a\n"
              "  memory image (LiME or flat raw/VMware). Writes <Distro>_<kernel>_\n"
              "  btf.json.xz into the current directory.", file=sys.stderr)
        sys.exit(2)
    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"error: no such file: {path}", file=sys.stderr)
        sys.exit(1)
    out = build_isf(path, out_dir=None, verbose=True)
    sys.exit(0 if out else 1)


if __name__ == "__main__":
    main()
