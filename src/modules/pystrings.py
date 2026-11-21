"""Pure-Python replacements for GNU `strings`, `grep -c` and `dd | strings`.

Windows has no binutils, and Sysinternals strings.exe takes different flags,
so the toolkit carries its own implementation. Output matches GNU
`strings -a` (ASCII: printable 0x20-0x7e + TAB, one string per line) and
`strings -a -el` (UTF-16LE of the same character set).

Large images are split into segments scanned by worker processes; each
segment owns the strings that START inside it, so nothing is lost or
duplicated at segment boundaries and the output keeps file order.
"""

import os
import re
import shutil
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Callable, Iterator, List, Optional

CHUNK = 16 * 1024 * 1024
_PRINT = rb"[\x20-\x7e\t]"
_cache = {}


def _regex(min_len: int, unicode: bool):
    key = (min_len, unicode)
    if key not in _cache:
        pat = (rb"(?:" + _PRINT + rb"\x00){%d,}" if unicode
               else _PRINT + rb"{%d,}") % min_len
        _cache[key] = re.compile(pat)
    return _cache[key]


def _is_print(b: int) -> bool:
    return 0x20 <= b <= 0x7e or b == 0x09


def iter_strings_range(path, start: int = 0, end: Optional[int] = None,
                       min_len: int = 4, unicode: bool = False) -> Iterator[bytes]:
    """Yield strings (as ASCII bytes) whose first byte lies in [start, end)."""
    rx = _regex(min_len, unicode)
    keep = 2 * min_len + 2 if unicode else min_len + 1
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if end is None or end > size:
            end = size
        skip_at = None
        if start > 0:
            f.seek(start - (2 if unicode else 1))
            prev = f.read(2 if unicode else 1)
            if (unicode and len(prev) == 2 and _is_print(prev[0]) and prev[1] == 0) or \
               (not unicode and prev and _is_print(prev[0])):
                skip_at = start          # that run belongs to the previous segment
            elif unicode and len(prev) == 2 and _is_print(prev[1]):
                # v2.4: the border fell BETWEEN a character and its 0x00 byte. The run
                # that goes on at start+1 still belongs to the previous segment; it used
                # to be written a second time as a shorter string ("bob@example.org"
                # after "mailto:bob@example.org").
                nxt = f.read(1)
                if nxt == b"\x00":
                    skip_at = start + 1
        f.seek(start)
        buf_off, buf = start, b""
        while True:
            chunk = f.read(CHUNK)
            eof = not chunk
            buf += chunk
            last_end, pending = 0, None
            for m in rx.finditer(buf):
                if m.end() >= len(buf) and not eof:
                    pending = m.start()          # may continue in the next chunk
                    break
                a = buf_off + m.start()
                if a >= end:
                    return
                last_end = m.end()
                if a == skip_at:
                    continue
                s = m.group()
                yield s[::2] if unicode else s
            if eof:
                return
            cut = pending if pending is not None else max(last_end, len(buf) - keep)
            if pending is None and buf_off + len(buf) >= end + keep:
                return
            buf_off += cut
            buf = buf[cut:]


def _worker(args) -> str:
    path, start, end, min_len, unicode, part = args
    with open(part, "wb") as out:
        w = out.write
        for s in iter_strings_range(path, start, end, min_len, unicode):
            w(s)
            w(b"\n")
    return part


def _worker_both(args):
    """ASCII then UTF-16 strings of ONE segment. The second scan re-reads bytes the
    first one just pulled into the OS file cache, so the disk is read once."""
    path, start, end, min_len, part_a, part_u = args
    _worker((path, start, end, min_len, False, part_a))
    _worker((path, start, end, min_len, True, part_u))
    return part_a, part_u


def extract_both_to_files(image, out_ascii, out_unicode, min_len: int = 4,
                          workers: Optional[int] = None,
                          progress: Optional[Callable[[int, int], None]] = None):
    """`extract_to_file` for ASCII and UTF-16 in one pass over the image (v2.4).
    Output files are byte-identical to two separate `extract_to_file` calls: the
    same segment bounds and the same per-segment scanner are used. Returns
    (ascii_lines, unicode_lines)."""
    image = str(image)
    size = os.path.getsize(image)
    if workers is None:
        workers = max(1, min(8, (os.cpu_count() or 2) - 1))
    nseg = 1 if size < 64 * 1024 * 1024 else max(workers, size // (256 * 1024 * 1024))
    bounds = [size * i // nseg for i in range(nseg + 1)]
    tmpd = tempfile.mkdtemp(prefix="rb_strings_")
    jobs = [(image, bounds[i], bounds[i + 1], min_len,
             os.path.join(tmpd, f"a{i:05d}.txt"), os.path.join(tmpd, f"u{i:05d}.txt"))
            for i in range(nseg)]
    try:
        parts = []
        if nseg == 1 or workers == 1:
            for i, j in enumerate(jobs):
                parts.append(_worker_both(j))
                if progress:
                    progress(i + 1, nseg)
        else:
            try:
                with ProcessPoolExecutor(max_workers=workers) as ex:
                    for i, p in enumerate(ex.map(_worker_both, jobs)):
                        parts.append(p)
                        if progress:
                            progress(i + 1, nseg)
            except Exception:
                # v2.4 (seen live on mint.lime, PC short of memory): the worker processes
                # could not start / died ("process pool is not usable anymore") and the
                # run went on with EMPTY strings files. Scan in this process instead.
                parts = []
                for i, j in enumerate(jobs):
                    parts.append(_worker_both(j))
                    if progress:
                        progress(i + 1, nseg)
        counts = []
        for idx, output in ((0, out_ascii), (1, out_unicode)):
            n = 0
            with open(output, "wb") as out:
                for pp in parts:
                    with open(pp[idx], "rb") as fi:
                        while True:
                            b = fi.read(8 * 1024 * 1024)
                            if not b:
                                break
                            n += b.count(b"\n")
                            out.write(b)
            counts.append(n)
        return counts[0], counts[1]
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def extract_to_file(image, output, unicode: bool = False, min_len: int = 4,
                    workers: Optional[int] = None,
                    progress: Optional[Callable[[int, int], None]] = None) -> int:
    """Write every string of `image` to `output`; returns bytes written."""
    image = str(image)
    size = os.path.getsize(image)
    if workers is None:
        workers = max(1, min(8, (os.cpu_count() or 2) - 1))
    nseg = 1 if size < 64 * 1024 * 1024 else max(workers, size // (256 * 1024 * 1024))
    bounds = [size * i // nseg for i in range(nseg + 1)]
    tmpd = tempfile.mkdtemp(prefix="rb_strings_")
    jobs = [(image, bounds[i], bounds[i + 1], min_len, unicode,
             os.path.join(tmpd, f"part{i:05d}.txt")) for i in range(nseg)]
    try:
        if nseg == 1 or workers == 1:
            parts = []
            for i, j in enumerate(jobs):
                parts.append(_worker(j))
                if progress:
                    progress(i + 1, nseg)
        else:
            try:
                with ProcessPoolExecutor(max_workers=workers) as ex:
                    parts = []
                    for i, p in enumerate(ex.map(_worker, jobs)):
                        parts.append(p)
                        if progress:
                            progress(i + 1, nseg)
            except Exception:                 # broken pool: same job, one process (v2.4)
                parts = []
                for i, j in enumerate(jobs):
                    parts.append(_worker(j))
                    if progress:
                        progress(i + 1, nseg)
        with open(output, "wb") as out:
            for p in parts:
                with open(p, "rb") as fi:
                    shutil.copyfileobj(fi, out, 8 * 1024 * 1024)
        return os.path.getsize(output)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def strings_lines(path, min_len: int = 4, unicode: bool = False,
                  max_bytes: Optional[int] = None) -> List[str]:
    """All strings of a (small) file as text lines - `strings -a file`."""
    end = None if max_bytes is None else max_bytes
    return [s.decode("ascii", "replace")
            for s in iter_strings_range(path, 0, end, min_len, unicode)]


def scan_range_lines(path, offset: int, length: int, min_len: int = 4) -> List[str]:
    """`dd if=path skip=offset count=length | strings` equivalent."""
    return [s.decode("ascii", "replace")
            for s in iter_strings_range(path, offset, offset + length, min_len)]


def count_lines_containing(path, term: str, ignore_case: bool = True) -> int:
    """`grep -a -c [-i] term path` for a literal term (lines, not hits)."""
    needle = term.encode("utf-8", "ignore")
    if ignore_case:
        needle = needle.lower()
    if not needle:
        return 0
    count, carry = 0, b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                data, final = carry, True
            else:
                data = carry + chunk
                nl = data.rfind(b"\n")
                if nl < 0:
                    carry = data
                    continue
                data, carry, final = data[:nl + 1], data[nl + 1:], False
            hay = data.lower() if ignore_case else data
            pos, last_line = 0, -2
            while True:
                i = hay.find(needle, pos)
                if i < 0:
                    break
                ls = hay.rfind(b"\n", 0, i)
                if ls != last_line:
                    count += 1
                    last_line = ls
                le = hay.find(b"\n", i)
                if le < 0:
                    break
                pos = le + 1
            if final:
                return count
