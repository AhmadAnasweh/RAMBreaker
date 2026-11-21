"""IOC Checker (RAMBreaker v2): search a user-supplied IOC list everywhere.

Input : a text/CSV file with one IOC per line (optional "type,value" or
        "value,comment"); '#' starts a comment. Types are auto-detected:
        ipv4, ipv6, domain, url, email, md5, sha1, sha256, other (literal).
Search: 1. the RAW memory image  - ASCII and UTF-16LE, case-insensitive,
           Aho-Corasick multi-pattern, multi-process; reports physical offsets
        2. every Volatility plugin JSON - reports plugin, PID, process, field
        3. IOC/strings outputs already produced (iocs/*.json)
        4. hashes of dumped files (dumped_files/, dumped_processes/, vad dumps)
        5. optional per-process attribution of raw hits via StringHunter
           (VadYaraScan / VmaYaraScan) when a Volatility wrapper is given
Output: <out>/ioc_check/ioc_check.json, .csv and .txt
"""

import csv
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import ahocorasick  # pyahocorasick
except Exception:  # pragma: no cover
    ahocorasick = None

MAX_OFFSETS = 50          # stored per IOC per encoding
SEG = 256 * 1024 * 1024
CHUNK = 16 * 1024 * 1024

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)


def classify(v: str) -> str:
    s = v.strip()
    if re.match(r"^(?:https?|ftp)://", s, re.I):
        return "url"
    try:
        ip = ipaddress.ip_address(s)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if _HEX.match(s):
        return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(s), "other")
    if _EMAIL.match(s):
        return "email"
    if _DOMAIN.match(s):
        return "domain"
    return "other"


def _defang(s: str) -> str:
    """Undo common IOC defanging: hxxp, [.], (.), [:]"""
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    return (s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
             .replace("[:]", ":").replace("[@]", "@"))


def load_iocs(path: Path) -> List[Dict[str, str]]:
    out, seen = [], set()
    # type labels seen in TI exports (MISP, OpenCTI, CSV feeds)
    types = {"ipv4", "ipv6", "ip", "ip-src", "ip-dst", "ipv4-addr", "ipv6-addr", "domain",
             "domain-name", "hostname", "fqdn", "url", "uri", "url_http", "link", "email",
             "email-src", "email-dst", "email-addr", "md5", "sha1", "sha256", "sha512",
             "hash", "filename", "file", "string", "other", "mutex", "registry", "regkey"}
    header_first = {"type", "indicator_type", "ioc_type", "category", "kind"}
    header_second = {"value", "indicator", "ioc", "data", "observable"}
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in next(csv.reader([line]))]
            if len(parts) >= 2 and parts[0].lower() in header_first and \
                    parts[1].lower() in header_second:
                continue                                     # CSV header row
            if len(parts) == 1 and parts[0].lower() in header_second:
                continue
            if len(parts) >= 2 and parts[0].lower() in types:
                value, comment = parts[1], ",".join(parts[2:])
            else:
                value, comment = parts[0], ",".join(parts[1:])
            value = _defang(value)
            if not value or value.lower() in seen:
                continue
            seen.add(value.lower())
            out.append({"value": value, "type": classify(value), "comment": comment})
    return out


# ───────────────────────────── raw image scan ──────────────────────────────

def _build_automaton(terms: List[str]):
    A = ahocorasick.Automaton()
    for i, t in enumerate(terms):
        A.add_word(t, (i, len(t)))
    A.make_automaton()
    return A


_WORD = set("abcdefghijklmnopqrstuvwxyz0123456789-_")


def _boundary_ok(s: str, off: int, L: int, kind: str, step: int) -> bool:
    """Token-boundary check so '10.0.0.1' does not hit inside '110.0.0.12'
    and 'evil.com' does not hit inside 'notevil.com'. `step` is 1 for ASCII,
    2 for UTF-16LE (look at the character byte, skipping the NUL)."""
    if kind == "other":
        return True
    before = s[off - step] if off - step >= 0 else ""
    after = s[off + L] if off + L < len(s) else ""
    if kind == "ip":
        bad = set("0123456789")
        if before in bad or after in bad:
            return False
        if after == "." and off + L + step < len(s) and s[off + L + step] in bad:
            return False
        if before == "." and off - 2 * step >= 0 and s[off - 2 * step] in bad:
            return False
        return True
    # domain / email / url / hash: no word character glued on either side
    # (a leading '.' is fine for domains: sub.evil.com contains evil.com)
    if before and before in _WORD:
        return False
    if after and after in _WORD:
        return False
    return True


def _kind(t: str) -> str:
    c = classify(t)
    if c in ("ipv4", "ipv6"):
        return "ip"
    if c in ("domain", "email", "md5", "sha1", "sha256"):
        return "word"
    return "other"


def _scan_segment(args) -> Dict[int, Dict[str, list]]:
    """Worker: scan [start,end) of the image; terms already lower-cased.

    ASCII search on the latin-1 view of lower-cased bytes; UTF-16LE by
    searching the expanded form 'a\\x00b\\x00...' of every term."""
    path, start, end, terms = args
    kinds = [_kind(t) for t in terms]
    keys = list(terms) + ["\x00".join(t) + "\x00" for t in terms]
    n = len(terms)
    maxlen = max(len(k) for k in keys)
    res: Dict[int, Dict[str, list]] = {}
    if ahocorasick is not None:
        A = _build_automaton(keys)
        finder = lambda s: ((e - L + 1, i, L) for e, (i, L) in A.iter(s))
    else:  # slower fallback; overlapping matches of different terms may be missed
        rx = re.compile("|".join(re.escape(k) for k in sorted(keys, key=len, reverse=True)))
        idx = {k: i for i, k in enumerate(keys)}
        finder = lambda s: ((m.start(), idx[m.group()], len(m.group()))
                            for m in rx.finditer(s))
    stop = end + maxlen - 1          # read past the end: matches START before end
    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        carry = b""
        while pos < stop:
            data = f.read(min(CHUNK, stop - pos))
            if not data:
                break
            buf = carry + data
            base = pos - len(carry)
            s = buf.lower().decode("latin-1")
            for off, i, L in finder(s):
                if off + L <= len(carry):      # fully inside carry: seen last chunk
                    continue
                abs_off = base + off
                if abs_off >= end:             # belongs to the next segment
                    continue
                enc = "ascii" if i < n else "utf16le"
                ti = i if i < n else i - n
                if not _boundary_ok(s, off, L, kinds[ti], 1 if i < n else 2):
                    continue
                d = res.setdefault(ti, {"ascii": [], "utf16le": [], "count_ascii": 0,
                                        "count_utf16le": 0})
                d["count_" + enc] += 1
                if len(d[enc]) < MAX_OFFSETS:
                    d[enc].append(abs_off)
            pos += len(data)
            carry = buf[-(maxlen - 1):] if maxlen > 1 else b""
    return res


def scan_image(image: str, terms: List[str], workers: Optional[int] = None,
               progress=None) -> Dict[int, Dict[str, Any]]:
    size = os.path.getsize(image)
    workers = workers or max(1, min(6, (os.cpu_count() or 2) - 1))
    nseg = max(1, (size + SEG - 1) // SEG)
    bounds = [min(size, i * SEG) for i in range(nseg + 1)]
    low = [t.lower() for t in terms]
    jobs = [(image, bounds[i], bounds[i + 1], low) for i in range(nseg)]
    merged: Dict[int, Dict[str, Any]] = {}
    done = 0

    def merge(part):
        for ti, d in part.items():
            m = merged.setdefault(ti, {"ascii": [], "utf16le": [], "count_ascii": 0,
                                       "count_utf16le": 0})
            for enc in ("ascii", "utf16le"):
                m["count_" + enc] += d["count_" + enc]
                room = MAX_OFFSETS - len(m[enc])
                if room > 0:
                    m[enc].extend(d[enc][:room])

    if nseg == 1 or workers == 1:
        for j in jobs:
            merge(_scan_segment(j))
            done += 1
            if progress:
                progress(done, nseg)
    else:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            for part in ex.map(_scan_segment, jobs):
                merge(part)
                done += 1
                if progress:
                    progress(done, nseg)
    for m in merged.values():
        m["ascii"].sort()
        m["utf16le"].sort()
    return merged


# ─────────────────────────── plugin JSON / hashes ──────────────────────────

_PID_KEYS = ("PID", "Pid", "pid", "OwnerPid", "Owner Pid", "Process ID")
_PROC_KEYS = ("ImageFileName", "Process", "Name", "COMM", "Owner", "Comm")


def _walk_rows(obj):
    if isinstance(obj, list):
        for r in obj:
            if isinstance(r, dict):
                kids = r.get("__children")
                yield {k: v for k, v in r.items() if k != "__children"}
                if kids:
                    yield from _walk_rows(kids)
    elif isinstance(obj, dict):
        for k in ("rows", "data", "results", "values", "events", "findings"):
            if isinstance(obj.get(k), list):
                yield from _walk_rows(obj[k])
                return


def scan_json_outputs(od: Path, terms: List[str], limit: int = 200
                      ) -> Dict[int, List[Dict[str, Any]]]:
    low = [t.lower() for t in terms]
    A = None
    if ahocorasick is not None and low:
        A = _build_automaton(low)
    hits: Dict[int, List[Dict[str, Any]]] = {}
    files = sorted((od / "json").glob("*.json")) if (od / "json").is_dir() else []
    files += sorted(od.glob("*_vol2.json"))
    files += sorted((od / "iocs" / "json").glob("*.json")) if (od / "iocs" / "json").is_dir() else []
    for p in files:
        try:
            obj = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for row in _walk_rows(obj):
            for field, val in row.items():
                if val is None or isinstance(val, bool):
                    continue
                s = str(val).lower()
                if not s:
                    continue
                found = set(i for _, (i, _L) in A.iter(s)) if A else \
                    {i for i, t in enumerate(low) if t in s}
                for i in found:
                    lst = hits.setdefault(i, [])
                    if len(lst) < limit:
                        pid = next((row[k] for k in _PID_KEYS if k in row), None)
                        proc = next((row[k] for k in _PROC_KEYS if k in row), None)
                        lst.append({"source": "plugin", "plugin": p.stem, "field": field,
                                    "pid": pid, "process": proc,
                                    "value": str(val)[:300]})
    return hits


def hash_dumped_files(od: Path, wanted: Dict[str, int]) -> Dict[int, List[Dict[str, Any]]]:
    """Hash every dumped artefact and match against hash IOCs."""
    hits: Dict[int, List[Dict[str, Any]]] = {}
    if not wanted:
        return hits
    dirs = [od / d for d in ("dumped_files", "dumped_processes", "dumped_vad",
                             "vad_dumps", "procdump", "dumpfiles")]
    for d in dirs:
        if not d.is_dir():
            continue
        for f in d.rglob("*"):
            if not f.is_file() or f.stat().st_size > 2 * 1024 ** 3:
                continue
            h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
            try:
                with open(f, "rb") as fh:
                    for b in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                        for x in h.values():
                            x.update(b)
            except OSError:
                continue
            for name, x in h.items():
                i = wanted.get(x.hexdigest())
                if i is not None:
                    hits.setdefault(i, []).append({"source": "file_hash", "algo": name,
                                                   "file": str(f.relative_to(od))})
    return hits


# ─────────────────────────────── orchestration ─────────────────────────────

def run(image: Optional[str], output_dir: Path, ioc_file: Path,
        log: Optional[logging.Logger] = None, vol_wrapper=None,
        os_type: str = "windows", attribute_processes: bool = True,
        progress=None) -> Dict[str, Any]:
    log = log or logging.getLogger(__name__)
    od = Path(output_dir)
    iocs = load_iocs(Path(ioc_file))
    t0 = time.time()
    log.info("IOC checker: %d IOCs loaded from %s", len(iocs), ioc_file)
    terms = [i["value"] for i in iocs]
    hash_idx = {i["value"].lower(): n for n, i in enumerate(iocs)
                if i["type"] in ("md5", "sha1", "sha256")}

    raw: Dict[int, Dict[str, Any]] = {}
    if image and Path(image).is_file() and terms:
        log.info("IOC checker: scanning raw image %s (ASCII + UTF-16LE)...", image)
        t = time.time()
        raw = scan_image(image, terms, progress=progress)
        log.info("IOC checker: raw scan done in %.1fs, %d IOCs present in image",
                 time.time() - t, len(raw))
    js = scan_json_outputs(od, terms) if terms else {}
    hh = hash_dumped_files(od, hash_idx)

    attrib: Dict[str, List[Dict[str, Any]]] = {}
    present_terms = [terms[i] for i in raw]
    want_attr = bool(attribute_processes and vol_wrapper is not None and present_terms and image)
    if want_attr:
        # the per-process YARA scan can take > 1 h on a large image on a hard
        # disk; write the (final) presence result first so a timed-out or
        # interrupted attribution never loses it
        _write_outputs(od, *_assemble(iocs, raw, js, hh, attrib, t0, image, ioc_file,
                                      "running - presence results are final, process "
                                      "attribution (Volatility YARA scan) in progress"), log)
        attr_state = "done"
        try:
            from modules.string_hunt import StringHunter
            log.info("IOC checker: attributing %d present IOC(s) to processes "
                     "(Volatility YARA scan)...", len(present_terms))
            hunter = StringHunter(log)
            sh = hunter.hunt(image, od / "ioc_check" / "hunt", present_terms[:200],
                             vol_wrapper, os_type=os_type)
            for term, lst in (sh.get("by_term") or {}).items():
                attrib[term.lower()] = lst
            if getattr(hunter, "scan_error", None):
                attr_state = ("incomplete - " + hunter.scan_error)[:300]
        except Exception as e:
            log.warning("IOC checker: process attribution failed: %s", e)
            attr_state = f"failed - {e}"[:300]
    else:
        attr_state = "not run" + ("" if present_terms else " (no IOC present in the image)")
    summary, results = _assemble(iocs, raw, js, hh, attrib, t0, image, ioc_file, attr_state)
    _write_outputs(od, summary, results, log)
    return {"summary": summary, "results": results}


def _assemble(iocs, raw, js, hh, attrib, t0, image, ioc_file, attr_state):
    results = []
    for n, ioc in enumerate(iocs):
        r = raw.get(n, {})
        locs = list(js.get(n, [])) + list(hh.get(n, []))
        for h in attrib.get(ioc["value"].lower(), [])[:100]:
            if str(h.get("pid") or "0") in ("0", "", "None"):
                # layer-wide scan (macOS: Vol3 has no per-process YARA scanner):
                # the hit is real but NOT tied to a process - say so.
                locs.append({"source": "memory_scan", "pid": "-",
                             "process": "(not attributable: layer-wide scan)",
                             "offset": h.get("offset")})
                continue
            locs.append({"source": "process_memory", "pid": h.get("pid"),
                         "process": h.get("process"), "offset": h.get("offset")})
        count = r.get("count_ascii", 0) + r.get("count_utf16le", 0)
        results.append({
            **ioc, "found": bool(count or locs),
            "raw_hits_ascii": r.get("count_ascii", 0),
            "raw_hits_utf16le": r.get("count_utf16le", 0),
            "raw_offsets_ascii": [hex(o) for o in r.get("ascii", [])],
            "raw_offsets_utf16le": [hex(o) for o in r.get("utf16le", [])],
            "locations": locs,
            "processes": sorted({f"{l.get('process')}({l.get('pid')})" for l in locs
                                 if l.get("pid") is not None}),
        })
    found = [x for x in results if x["found"]]
    summary = {"iocs": len(iocs), "found": len(found), "not_found": len(iocs) - len(found),
               "duration_s": round(time.time() - t0, 1), "image": image,
               "ioc_file": str(ioc_file), "attribution": attr_state}
    return summary, results


def _write_outputs(od, summary, results, log):
    found = [x for x in results if x["found"]]
    outd = Path(od) / "ioc_check"
    outd.mkdir(parents=True, exist_ok=True)
    (outd / "ioc_check.json").write_text(json.dumps({"summary": summary, "results": results},
                                                    indent=2, default=str), encoding="utf-8")
    with open(outd / "ioc_check.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ioc", "type", "found", "raw_ascii", "raw_utf16le", "first_offsets",
                    "plugins", "processes", "comment"])
        for x in results:
            w.writerow([x["value"], x["type"], x["found"], x["raw_hits_ascii"],
                        x["raw_hits_utf16le"],
                        " ".join((x["raw_offsets_ascii"] + x["raw_offsets_utf16le"])[:5]),
                        " ".join(sorted({l.get("plugin") or l.get("source") for l in x["locations"]})),
                        " ".join(x["processes"][:10]), x["comment"]])
    with open(outd / "ioc_check.txt", "w", encoding="utf-8") as f:
        f.write(f"IOC CHECK: {summary['found']}/{summary['iocs']} IOCs found "
                f"({summary['duration_s']}s)\n")
        f.write(f"Process attribution: {summary.get('attribution', '')}\n\n")
        for x in found:
            f.write(f"[FOUND] {x['value']} ({x['type']}) raw ascii={x['raw_hits_ascii']} "
                    f"utf16={x['raw_hits_utf16le']}\n")
            offs = (x["raw_offsets_ascii"] + x["raw_offsets_utf16le"])[:5]
            if offs:
                f.write(f"        first offsets: {' '.join(offs)}\n")
            for l in x["locations"][:10]:
                f.write("        " + ", ".join(f"{k}={v}" for k, v in l.items()
                                               if v not in (None, ""))[:300] + "\n")
        f.write("\nNOT FOUND:\n")
        for x in results:
            if not x["found"]:
                f.write(f"  {x['value']} ({x['type']})\n")
    log.info("IOC checker: %d/%d found (%.1fs; attribution: %s) -> %s", summary["found"],
             summary["iocs"], summary["duration_s"], summary.get("attribution", ""), outd)
