#!/usr/bin/env python3
"""injection_correlator.py — correlate "injected memory" (malfind) with the
"module list" plugin to flag fileless code injection. Windows / Linux / macOS.

Runs two ways:
  * STANDALONE script — feed it two Volatility3 plugin outputs and it prints a
    color-coded report and exports JSON/CSV (see the CLI at the bottom, and the
    "HOW TO GENERATE INPUTS" note).
  * TOOLKIT module — RAMBreaker calls run_from_output_dir(output_dir, os_type) to
    read the already-extracted json/ and write injection_correlation.json (which
    the HTML report renders in its Injection tab).

DETECTION LOGIC (identical principle on all three OSes; only the plugin/field
names differ):
  * The injected-memory plugin (malfind) flags memory regions that are PRIVATE
    (not file-backed), EXECUTABLE (RWX / abnormal exec perms), and often carry an
    executable header (MZ / ELF / Mach-O) or shellcode.
  * The module-list plugin says whether that region is registered in the OS's
    normal loader tracking (PEB lists on Windows; a backing path in /proc/pid/maps
    on Linux; a dyld-registered image / mapped path on macOS). A region that
    exists but is absent from those lists = it was not loaded by the normal loader
    = strong reflective/manual-injection signal.
  * HIGH   = malfind hit  AND  a matching module-list entry (same PID + address)
             that is UNREGISTERED / has no backing path.
  * MEDIUM = malfind hit ALONE (no clear module-list correlation) — could be a
             technique that still uses the legit loader (LoadLibrary via a remote
             thread, ptrace, etc.). Worth flagging, less definitive.
  * LOW    = a module-list anomaly (unregistered executable region) with NO
             matching malfind hit.

OS-SPECIFIC QUIRKS worth knowing (see inline comments too):
  * Windows: malfind's "Start VPN"/"End VPN" columns actually hold FULL addresses
    in modern Vol3 (despite the "VPN" name), matching ldrmodules' "Base". If a
    build ever emits true page numbers, the matcher retries with a <<12 shift.
  * Windows ldrmodules: a base absent from all three lists (InLoad/InInit/InMem)
    is unlinked/hidden; an empty MappedPath means no backing file.
  * Linux/macOS have no PEB-style list — the proxy for "registered" is "the
    /proc maps (or vm regions) entry has a backing file path". An anonymous
    EXECUTABLE region (no path) is the anomaly.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── colour: prefer colorama, fall back to plain (rich optional, not required) ──
try:
    from colorama import Fore, Style, init as _cinit
    _cinit()
    _C = {"HIGH": Fore.RED + Style.BRIGHT, "MEDIUM": Fore.YELLOW,
          "LOW": Fore.CYAN, "HEAD": Fore.WHITE + Style.BRIGHT,
          "DIM": Style.DIM, "OK": Fore.GREEN, "R": Style.RESET_ALL}
except Exception:  # pragma: no cover - plain fallback
    _C = {k: "" for k in ("HIGH", "MEDIUM", "LOW", "HEAD", "DIM", "OK", "R")}

CONFIDENCE_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Executable-header magic bytes, in the byte order malfind's hexdump shows them.
HEADER_MAGICS: Dict[str, List[Tuple[str, bytes]]] = {
    "windows": [("MZ/PE", b"\x4d\x5a")],
    "linux":   [("ELF", b"\x7f\x45\x4c\x46")],
    "macos":   [("Mach-O", b"\xfe\xed\xfa\xce"), ("Mach-O", b"\xfe\xed\xfa\xcf"),
                ("Mach-O", b"\xce\xfa\xed\xfe"), ("Mach-O", b"\xcf\xfa\xed\xfe"),
                ("Mach-O(fat)", b"\xca\xfe\xba\xbe"), ("Mach-O(fat)", b"\xbe\xba\xfe\xca")],
}

_OS_ALIASES = {"mac": "macos", "osx": "macos", "darwin": "macos",
               "win": "windows", "windows": "windows", "linux": "linux",
               "macos": "macos"}


# ── small helpers ─────────────────────────────────────────────────────────────
def _norm_os(os_type: Optional[str]) -> Optional[str]:
    return _OS_ALIASES.get(str(os_type).strip().lower()) if os_type else None


def _gv(item: Dict, *keys, default=None):
    """Case-insensitive, alias-tolerant field lookup."""
    if not isinstance(item, dict):
        return default
    for k in keys:
        if k in item:
            return item[k]
    low = {str(k).lower(): k for k in item}
    for k in keys:
        if str(k).lower() in low:
            return item[low[str(k).lower()]]
    return default


def _to_int(v) -> Optional[int]:
    """Parse an address that may be int, '0x...' hex, or decimal string."""
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip().replace("L", "")
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except (ValueError, TypeError):
        try:
            return int(s, 16)
        except (ValueError, TypeError):
            return None


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return str(v).strip().lower() in ("true", "1", "yes", "y")


def _is_executable(protection: str) -> bool:
    p = (protection or "").lower()
    return "execute" in p or "x" in re.findall(r"[rwx-]{3,4}", p + " ")[0:1] and "x" in p


def detect_header(region: Dict, os_type: str) -> Tuple[bool, str]:
    """Look for an executable-file header in a malfind region's hexdump/notes.
    Returns (found, type_label)."""
    os_type = _norm_os(os_type) or "windows"
    # 1) an explicit note (some Vol3 builds print 'MZ header' in a Notes column)
    notes = str(_gv(region, "Notes", "Note", "Disasm", default="") or "").lower()
    if "mz header" in notes or ("mz" in notes and os_type == "windows"):
        return True, "MZ/PE"
    # 2) parse the first bytes out of the Hexdump string
    hexd = _gv(region, "Hexdump", "hexdump", "HexDump", default="")
    first = _first_bytes(str(hexd or ""))
    for label, magic in HEADER_MAGICS.get(os_type, []):
        if first.startswith(magic):
            return True, label
    return False, ""


def _first_bytes(hexdump: str, limit: int = 8) -> bytes:
    """Extract the first data bytes from a Vol3 hexdump string
    ('0xADDR\\t4d 5a 90 00 ...\\tMZ..'). Skips the leading offset token."""
    out = bytearray()
    for line in hexdump.splitlines():
        # drop a leading 0x.... offset if present, then grab hex byte pairs
        line = re.sub(r"^\s*0x[0-9a-fA-F]+\s*[:\t ]", " ", line)
        m = re.search(r"((?:\b[0-9a-fA-F]{2}\b[ \t]+){2,})", line)
        if m:
            for tok in m.group(1).split():
                out.append(int(tok, 16))
            if len(out) >= limit:
                break
    return bytes(out[:limit])


# ══════════════════════════════════════════════════════════════════════════════
# OS-SPECIFIC PARSERS  →  common schema
#   normalized injected region / module entry:
#   {pid, process_name, base_address, end_address, protection,
#    private_or_unbacked, header_signature_found, header_type,
#    registered_in_module_list, mapped_path, executable}
# All parsers feed the SAME correlation engine, so a 4th OS is just a new parser.
# ══════════════════════════════════════════════════════════════════════════════
def _blank(pid, name, start, end, prot) -> Dict[str, Any]:
    return {"pid": str(pid) if pid is not None else "",
            "process_name": str(name or ""),
            "base_address": _to_int(start), "end_address": _to_int(end),
            "protection": str(prot or ""),
            "private_or_unbacked": False, "header_signature_found": False,
            "header_type": "", "registered_in_module_list": True,
            "mapped_path": None, "executable": _is_executable(prot)}


def _group_vol2_malfind(rows: List[Dict]) -> List[Dict]:
    """Vol2 QUIRK: vol2 malfind renders as interleaved text fragments the toolkit
    stores as separate 'raw' rows — a "Process: X Pid: N Address: 0x..." header,
    then a "Vad Tag: .. Protection: .." line, a "Flags: .. PrivateMemory: N" line,
    and hexdump lines. Regroup consecutive fragments into one region per header."""
    regions, cur = [], None
    for r in rows:
        line = str(_gv(r, "raw", "Raw") or "").strip()
        if not line:
            continue
        mh = re.search(r"Process:\s*(\S+)\s+Pid:\s*(\d+)\s+Address:\s*(0x[0-9a-fA-F]+)", line)
        if mh:
            if cur:
                regions.append(cur)
            cur = {"Process": mh.group(1), "PID": mh.group(2), "Start": mh.group(3),
                   "Protection": "", "Hexdump": "", "PrivateMemory": True}
            continue
        if cur is None:
            continue
        mp = re.search(r"Protection:\s*(PAGE_\w+)", line)
        if mp and not cur["Protection"]:
            cur["Protection"] = mp.group(1)
        mpriv = re.search(r"PrivateMemory:\s*(\d)", line)
        if mpriv:
            cur["PrivateMemory"] = mpriv.group(1) == "1"
        if re.match(r"^0x[0-9a-fA-F]+\s", line):      # a hexdump line
            cur["Hexdump"] += line + "\n"
    if cur:
        regions.append(cur)
    return regions


def parse_windows(injected: List[Dict], modules: List[Dict]) -> Tuple[List, List]:
    # Vol2 text fallback: if the malfind rows are raw fragments, regroup them.
    if injected and all(("raw" in r or "Raw" in r) for r in injected if isinstance(r, dict)):
        injected = _group_vol2_malfind(injected)
    inj = []
    for r in injected or []:
        # NOTE: 'Start VPN'/'End VPN' hold full addresses in modern Vol3.
        e = _blank(_gv(r, "PID", "Pid"), _gv(r, "Process", "ImageFileName"),
                   _gv(r, "Start VPN", "Start", "Start Address", "StartVPN"),
                   _gv(r, "End VPN", "End", "End Address", "EndVPN"),
                   _gv(r, "Protection", "protection"))
        e["private_or_unbacked"] = _truthy(_gv(r, "PrivateMemory", "Private", default=True))
        e["header_signature_found"], e["header_type"] = detect_header(r, "windows")
        e["executable"] = _is_executable(e["protection"]) or True  # malfind hits are exec by definition
        inj.append(e)
    mods = []
    for m in modules or []:
        inload = _truthy(_gv(m, "InLoad", "InLoadOrderModuleList", default=True))
        ininit = _truthy(_gv(m, "InInit", "InInitializationOrderModuleList", default=True))
        inmem = _truthy(_gv(m, "InMem", "InMemoryOrderModuleList", default=True))
        path = _gv(m, "MappedPath", "Path", "FullDllName")
        e = _blank(_gv(m, "Pid", "PID"), _gv(m, "Process", "ImageFileName"),
                   _gv(m, "Base", "DllBase", "Start"), _gv(m, "End", "Size"),
                   _gv(m, "Protection", default=""))
        e["registered_in_module_list"] = bool(inload or ininit or inmem)
        e["mapped_path"] = str(path) if path and str(path).lower() not in ("", "none", "null") else None
        # a hidden/unlinked or unbacked entry is the module-list anomaly
        e["executable"] = True
        mods.append(e)
    return inj, mods


def _parse_unix_injected(injected, os_type):
    inj = []
    for r in injected or []:
        e = _blank(_gv(r, "PID", "Pid"), _gv(r, "Process", "Comm", "COMM", "Name"),
                   _gv(r, "Start", "Start Address", "Start VPN", "Vma Start"),
                   _gv(r, "End", "End Address", "End VPN", "Vma End"),
                   _gv(r, "Protection", "Flags", "Perms", "protection"))
        e["private_or_unbacked"] = True  # malfind by definition flags private exec
        e["header_signature_found"], e["header_type"] = detect_header(r, os_type)
        e["executable"] = True
        inj.append(e)
    return inj


def _parse_unix_modules(modules, os_type):
    """Linux proc.Maps / macOS proc_maps: a region is 'registered/backed' iff it
    has a file path. An executable region with no path is the anomaly."""
    mods = []
    for m in modules or []:
        prot = str(_gv(m, "Flags", "Protection", "Perms", "protection", default="") or "")
        path = _gv(m, "File Path", "Path", "Pathname", "Map Name", "File", "Inode Path")
        has_path = bool(path) and str(path).lower() not in ("", "none", "null", "0")
        e = _blank(_gv(m, "PID", "Pid"), _gv(m, "Process", "Comm", "COMM", "Name"),
                   _gv(m, "Start", "Start Address", "Vma Start"),
                   _gv(m, "End", "End Address", "Vma End"), prot)
        e["registered_in_module_list"] = has_path
        e["mapped_path"] = str(path) if has_path else None
        e["executable"] = _is_executable(prot) or ("x" in prot.lower())
        mods.append(e)
    return mods


def parse_linux(injected, modules):
    return _parse_unix_injected(injected, "linux"), _parse_unix_modules(modules, "linux")


def parse_macos(injected, modules):
    return _parse_unix_injected(injected, "macos"), _parse_unix_modules(modules, "macos")


_PARSERS = {"windows": parse_windows, "linux": parse_linux, "macos": parse_macos}


# ══════════════════════════════════════════════════════════════════════════════
# INPUT LOADING — JSON first, per-OS raw-text fallback
# ══════════════════════════════════════════════════════════════════════════════
def load_plugin_output(path: str) -> List[Dict[str, Any]]:
    """Load a Volatility3 plugin output. Tries JSON; falls back to a generic
    whitespace/tab table parser for raw text (not every plugin/Vol3 version
    renders clean JSON)."""
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    s = text.lstrip()
    if s[:1] in ("[", "{"):
        try:
            data = json.loads(s)
            return data if isinstance(data, list) else [data]
        except Exception:
            pass
    return _parse_text_table(text)


def _parse_text_table(text: str) -> List[Dict[str, Any]]:
    """Best-effort parser for Vol3 pretty/tab text: first non-empty line is the
    header; rows split on 2+ spaces or tabs."""
    lines = [l for l in text.splitlines() if l.strip()
             and not l.startswith(("Volatility", "Progress"))]
    if not lines:
        return []
    def cols(line):
        return [c.strip() for c in re.split(r"\t|\s{2,}", line.strip()) if c.strip()]
    header = cols(lines[0])
    rows = []
    for line in lines[1:]:
        c = cols(line)
        if len(c) >= 2:
            rows.append({header[i] if i < len(header) else f"col{i}": c[i]
                         for i in range(len(c))})
    return rows


def detect_os_from_data(injected: List[Dict], modules: List[Dict]) -> Optional[str]:
    """--auto: guess the OS from field-name fingerprints in the loaded data."""
    keys = set()
    for row in (injected or [])[:5] + (modules or [])[:5]:
        if isinstance(row, dict):
            keys |= {str(k).lower() for k in row}
    if {"inload", "ininit", "inmem"} & keys or "mappedpath" in keys or "start vpn" in keys:
        return "windows"
    if "file path" in keys or "inode" in keys or "comm" in keys or "vma start" in keys:
        return "linux"
    if "map name" in keys or {"perms"} & keys:
        return "macos"
    return None


# ══════════════════════════════════════════════════════════════════════════════
# CORRELATION ENGINE (shared across all OSes)
# ══════════════════════════════════════════════════════════════════════════════
def _overlap(a1, a2, b1, b2, tol: int) -> bool:
    if a1 is None or b1 is None:
        return False
    a2 = a2 if a2 is not None else a1
    b2 = b2 if b2 is not None else b1
    return (a1 - tol) <= (b2) and (b1 - tol) <= (a2)


def _match_module(inj: Dict, modules: List[Dict], tol: int) -> Optional[int]:
    """Find a module-list entry for the same PID whose address matches/overlaps.
    Retries with a <<12 page-shift to survive the Windows VPN quirk."""
    ib, ie = inj["base_address"], inj["end_address"]
    for shift in (0, 12):
        b = ib << shift if (shift and ib is not None) else ib
        e = ie << shift if (shift and ie is not None) else ie
        for i, m in enumerate(modules):
            if str(m["pid"]) != str(inj["pid"]):
                continue
            if b is not None and m["base_address"] is not None and b == m["base_address"]:
                return i
            if _overlap(b, e, m["base_address"], m["end_address"], tol):
                return i
    return None


def correlate(injected: List[Dict], modules: List[Dict], os_type: str,
              overlap_tolerance: int = 0) -> List[Dict[str, Any]]:
    """The shared classifier. Returns a list of findings, each with a
    'confidence' of HIGH / MEDIUM / LOW per the module docstring."""
    os_type = _norm_os(os_type) or "windows"
    findings: List[Dict[str, Any]] = []
    matched: set = set()

    for inj in injected:
        mi = _match_module(inj, modules, overlap_tolerance)
        merged = dict(inj)
        if mi is not None:
            matched.add(mi)
            m = modules[mi]
            merged["registered_in_module_list"] = m["registered_in_module_list"]
            merged["mapped_path"] = m["mapped_path"]
            unregistered = (not m["registered_in_module_list"]) or (not m["mapped_path"])
            merged["confidence"] = "HIGH" if unregistered else "MEDIUM"
            merged["evidence"] = ("malfind hit + module-list entry is "
                                  + ("UNREGISTERED/unbacked" if unregistered else "registered"))
        else:
            merged["confidence"] = "MEDIUM"
            merged["evidence"] = "malfind hit, no module-list correlation"
        merged["os"] = os_type
        merged["source"] = "injected"
        findings.append(merged)

    # LOW: module-list anomalies not already matched to a malfind hit. Require the
    # STRONG signal — executable, unregistered in the loader lists, AND unbacked
    # (no file path). This avoids the Windows System process, whose kernel modules
    # legitimately show all-False loader flags but DO have a mapped path.
    for i, m in enumerate(modules):
        if i in matched:
            continue
        anomaly = (m.get("executable")
                   and (not m["registered_in_module_list"])
                   and (not m["mapped_path"]))
        if anomaly:
            f = dict(m)
            f.update({"confidence": "LOW", "os": os_type, "source": "module",
                      "evidence": "unregistered/unbacked executable region, no malfind hit"})
            findings.append(f)

    findings.sort(key=lambda x: (-CONFIDENCE_ORDER.get(x["confidence"], 0),
                                 str(x["pid"]), x["base_address"] or 0))
    return findings


def summarize(findings: List[Dict], injected: List[Dict], modules: List[Dict],
              os_type: str, scanned_pids: int) -> Dict[str, Any]:
    by = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        by[f["confidence"]] = by.get(f["confidence"], 0) + 1
    return {"os": _norm_os(os_type), "processes_scanned": scanned_pids,
            "injected_regions": len(injected), "module_entries": len(modules),
            "findings_total": len(findings), "by_confidence": by}


# ══════════════════════════════════════════════════════════════════════════════
# REPORTING / EXPORT
# ══════════════════════════════════════════════════════════════════════════════
_COLUMNS = ["os", "pid", "process_name", "base_address", "protection",
            "header_signature_found", "registered_in_module_list", "mapped_path",
            "confidence"]


def _fmt_addr(v) -> str:
    return hex(v) if isinstance(v, int) else str(v or "")


def _row_view(f: Dict) -> Dict[str, str]:
    return {"os": f.get("os", ""), "pid": str(f.get("pid", "")),
            "process_name": f.get("process_name", ""),
            "base_address": _fmt_addr(f.get("base_address")),
            "protection": f.get("protection", ""),
            "header_signature_found": "T" if f.get("header_signature_found") else "F",
            "registered_in_module_list": "T" if f.get("registered_in_module_list") else "F",
            "mapped_path": f.get("mapped_path") or "-",
            "confidence": f.get("confidence", "")}


def print_report(findings: List[Dict], summary: Dict, use_color: bool = True):
    C = _C if use_color else {k: "" for k in _C}
    print(f"\n{C['HEAD']}== FILELESS-INJECTION CORRELATION =="
          f"  (OS: {summary['os']}){C['R']}")
    if not findings:
        print(f"  {C['OK']}No correlated injection findings.{C['R']}")
    else:
        hdr = ["CONF", "PID", "PROCESS", "BASE", "PROT", "HDR", "REG", "PATH"]
        print("  " + "  ".join(f"{C['HEAD']}{h}{C['R']}" for h in hdr))
        for f in findings:
            v = _row_view(f)
            col = C.get(v["confidence"], "")
            print(f"  {col}{v['confidence']:<6}{C['R']} {v['pid']:>6}  "
                  f"{v['process_name'][:18]:<18} {v['base_address']:<14} "
                  f"{v['protection'][:22]:<22} {v['header_signature_found']}  "
                  f"{v['registered_in_module_list']}   {(v['mapped_path'] or '-')[:40]}")
    b = summary["by_confidence"]
    print(f"\n  {C['DIM']}Processes scanned: {summary['processes_scanned']} · "
          f"injected regions: {summary['injected_regions']} · "
          f"module entries: {summary['module_entries']}{C['R']}")
    print(f"  Findings: {C['HIGH']}HIGH {b['HIGH']}{C['R']} · "
          f"{C['MEDIUM']}MEDIUM {b['MEDIUM']}{C['R']} · "
          f"{C['LOW']}LOW {b['LOW']}{C['R']}\n")


def export_json(findings, summary, path):
    Path(path).write_text(json.dumps(
        {"summary": summary,
         "findings": [{**{k: (_fmt_addr(f.get(k)) if k in ("base_address", "end_address")
                            else f.get(k)) for k in
                        ("os", "pid", "process_name", "base_address", "end_address",
                         "protection", "private_or_unbacked", "header_signature_found",
                         "header_type", "registered_in_module_list", "mapped_path",
                         "confidence", "evidence")}} for f in findings]},
        indent=2), encoding="utf-8")


def export_csv(findings, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_COLUMNS)
        w.writeheader()
        for f in findings:
            w.writerow(_row_view(f))


# ══════════════════════════════════════════════════════════════════════════════
# TOOLKIT ENTRY — read the already-extracted json/ and write the correlation file
# ══════════════════════════════════════════════════════════════════════════════
_MODULE_PATTERNS = {"windows": ["ldrmodules"], "linux": ["proc_Maps", "proc.maps", "elfs"],
                    "macos": ["proc_maps", "lsmod"]}


def run_from_output_dir(output_dir, os_type: str, logger=None) -> Dict[str, Any]:
    """RAMBreaker entry point: correlate malfind vs the module-list plugin from an
    existing json/ dir, write json/injection_correlation.json (+ a .txt in the run
    root). Returns the summary. Best-effort; never raises into the pipeline."""
    try:
        from utils.json_converter import load_json_by_pattern
    except Exception:
        def load_json_by_pattern(jd, pat):
            for p in sorted(Path(jd).glob(f"*{pat}*.json")):
                try:
                    d = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                    return d if isinstance(d, list) else [d]
                except Exception:
                    continue
            return []
    ot = _norm_os(os_type) or "windows"
    jd = Path(output_dir) / "json"
    injected_raw = load_json_by_pattern(jd, "malfind")
    modules_raw = []
    for pat in _MODULE_PATTERNS.get(ot, []):
        modules_raw = load_json_by_pattern(jd, pat)
        if modules_raw:
            break
    injected, modules = _PARSERS[ot](injected_raw, modules_raw)
    findings = correlate(injected, modules, ot)
    pids = {str(x["pid"]) for x in injected + modules if x.get("pid")}
    summary = summarize(findings, injected, modules, ot, len(pids))

    out = Path(output_dir)
    # JSON goes in json/ alongside every other report artifact (correlation,
    # network_map, timeline, …); the human-readable .txt stays in the run root
    # (matching network_map.txt / correlation_report.txt).
    json_dir = out / "json"
    json_dir.mkdir(parents=True, exist_ok=True)
    export_json(findings, summary, json_dir / "injection_correlation.json")
    _write_txt(findings, summary, out / "injection_correlation.txt")
    if logger:
        b = summary["by_confidence"]
        logger.info("Injection correlation: HIGH=%d MEDIUM=%d LOW=%d (from %d malfind, %d module entries)",
                    b["HIGH"], b["MEDIUM"], b["LOW"], len(injected), len(modules))
    return summary


def _write_txt(findings, summary, path):
    L = ["=" * 78, "  FILELESS-INJECTION CORRELATION REPORT",
         f"  OS: {summary['os']}   Processes scanned: {summary['processes_scanned']}",
         "  malfind (injected memory)  x  module-list (loader registration)",
         "  Confidence is an OBSERVATION, not a verdict — verify.",
         "=" * 78, "",
         f"  injected regions: {summary['injected_regions']}   "
         f"module entries: {summary['module_entries']}",
         f"  HIGH: {summary['by_confidence']['HIGH']}   "
         f"MEDIUM: {summary['by_confidence']['MEDIUM']}   "
         f"LOW: {summary['by_confidence']['LOW']}", ""]
    for f in findings:
        v = _row_view(f)
        L.append(f"  [{v['confidence']}] PID {v['pid']} {v['process_name']}  "
                 f"base={v['base_address']} prot={v['protection']} "
                 f"hdr={v['header_signature_found']} registered={v['registered_in_module_list']} "
                 f"path={v['mapped_path']}")
        if f.get("evidence"):
            L.append(f"        → {f['evidence']}")
    L += ["", "=" * 78, "  END OF REPORT", "=" * 78]
    Path(path).write_text("\n".join(L) + "\n", encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════
_HOWTO = """\
HOW TO GENERATE THE INPUTS (Volatility 3, JSON preferred):

  Windows:
    vol -r json -f mem.raw windows.malfind.Malfind      > malfind.json
    vol -r json -f mem.raw windows.ldrmodules.LdrModules > modules.json

  Linux (needs the matching ISF symbols installed):
    vol -r json -f mem.lime linux.malfind.Malfind   > malfind.json
    vol -r json -f mem.lime linux.proc.Maps          > modules.json   # or linux.elfs.Elfs

  macOS:
    vol -r json -f mem.raw mac.malfind.Malfind   > malfind.json
    vol -r json -f mem.raw mac.proc_maps.Maps     > modules.json   # or mac.lsmod.Lsmod

  Then:
    python3 injection_correlator.py --os windows \\
        --injected malfind.json --modules modules.json --export both
"""


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="injection_correlator.py",
        description="Correlate malfind (injected memory) with the module list to "
                    "flag fileless code injection. Windows / Linux / macOS.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=_HOWTO)
    ap.add_argument("--os", choices=["windows", "linux", "macos"],
                    help="OS the plugin outputs came from")
    ap.add_argument("--auto", action="store_true",
                    help="auto-detect the OS from the input field structure")
    ap.add_argument("--injected", "-i", required=True, metavar="FILE",
                    help="'injected memory' (malfind) plugin output (json or text)")
    ap.add_argument("--modules", "-m", required=True, metavar="FILE",
                    help="'module list' plugin output (json or text)")
    ap.add_argument("--pid", type=str, help="only report this PID")
    ap.add_argument("--min-confidence", choices=["HIGH", "MEDIUM", "LOW"],
                    default="LOW", help="only report at/above this confidence")
    ap.add_argument("--export", choices=["json", "csv", "both"],
                    help="also write injection_correlation.json/.csv")
    ap.add_argument("--out-dir", default=".", help="directory for --export files")
    ap.add_argument("--overlap-tolerance", type=int, default=0, metavar="BYTES",
                    help="address-match tolerance in bytes (default 0 = exact/overlap)")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    a = ap.parse_args(argv)

    injected_raw = load_plugin_output(a.injected)
    modules_raw = load_plugin_output(a.modules)

    os_type = _norm_os(a.os)
    if a.auto or not os_type:
        guessed = detect_os_from_data(injected_raw, modules_raw)
        if guessed:
            os_type = guessed
            print(f"{_C['DIM']}[auto] detected OS: {os_type}{_C['R']}")
    if not os_type:
        ap.error("could not determine OS — pass --os windows|linux|macos")

    injected, modules = _PARSERS[os_type](injected_raw, modules_raw)
    findings = correlate(injected, modules, os_type, a.overlap_tolerance)

    # filters
    if a.pid:
        findings = [f for f in findings if str(f["pid"]) == str(a.pid)]
    floor = CONFIDENCE_ORDER[a.min_confidence]
    findings = [f for f in findings if CONFIDENCE_ORDER[f["confidence"]] >= floor]

    pids = {str(x["pid"]) for x in injected + modules if x.get("pid")}
    summary = summarize(findings, injected, modules, os_type, len(pids))
    print_report(findings, summary, use_color=not a.no_color)

    if a.export:
        od = Path(a.out_dir); od.mkdir(parents=True, exist_ok=True)
        if a.export in ("json", "both"):
            export_json(findings, summary, od / "injection_correlation.json")
            print(f"  wrote {od / 'injection_correlation.json'}")
        if a.export in ("csv", "both"):
            export_csv(findings, od / "injection_correlation.csv")
            print(f"  wrote {od / 'injection_correlation.csv'}")
    return 0 if summary["by_confidence"]["HIGH"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
