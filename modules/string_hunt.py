"""
CresCent RAM Forensics Toolkit v6.0 — String Hunt

Searches a live memory image for user-specified strings and reports which
process virtual address space (VAD / VMA) contains each match.

Operates directly on the raw image — no pre-dumping required.
Also searches existing strings corpora (strings_ascii.txt / strings_unicode.txt)
as a fast supplementary pass.

Volatility plugin map:
  Vol3 Windows → windows.vadyarascan.VadYaraScan   (per-process VAD scan)
  Vol3 Linux   → linux.vmayarascan.VmaYaraScan     (per-process VMA scan)
  Vol3 Mac     → yarascan.YaraScan                  (physical memory scan)
  Vol2 any     → yarascan                           (per-process + kernel)
"""

import json
import logging
import re
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Vol3 plugin names by OS type
_VOL3_PLUGIN = {
    "windows": "windows.vadyarascan.VadYaraScan",
    "linux":   "linux.vmayarascan.VmaYaraScan",
    "mac":     "yarascan.YaraScan",
}

# Field-name aliases for different Vol3 plugin versions
_FIELD_PID     = ("PID", "Pid", "pid")
_FIELD_PROCESS = ("ImageFileName", "Process", "Name", "ImageName")
_FIELD_OFFSET  = ("Offset", "Address", "offset", "VA")
_FIELD_VALUE   = ("Value", "Data", "Bytes", "value")
_FIELD_RULE    = ("Rule", "rule")
_FIELD_COMP    = ("Component", "component", "Match")


def _gv(d: dict, *keys, default=""):
    for k in keys:
        if k in d:
            v = d[k]
            return v if v is not None else default
    return default


class StringHunter:
    """Search a memory image for arbitrary strings using Volatility YARA plugins."""

    def __init__(self, logger: logging.Logger):
        self.log = logger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def hunt(
        self,
        image: str,
        output_dir: Path,
        terms: List[str],
        vol_wrapper,
        os_type: str = "windows",
        pid_filter: Optional[List[int]] = None,
        case_insensitive: bool = True,
        wide: bool = True,
        timeout: int = 600,
    ) -> Dict[str, Any]:
        """
        Run a string hunt against *image*.

        Returns a results dict with keys:
          hits          — list of individual match records
          by_term       — {term: [hit, ...]}
          by_process    — {process_key: [hit, ...]}
          strings_hits  — {term: count} from grep of strings corpora
          scan_duration — float seconds
          plugin        — plugin name used
          total_hits    — int
          terms         — search terms list
        """
        self.log.info("String Hunt: %d term(s): %s", len(terms), terms)
        output_dir = Path(output_dir)
        jd = output_dir / "json"
        jd.mkdir(parents=True, exist_ok=True)

        yara_rule = _build_yara_rule(terms)
        term_map  = {f"$s{i}": t for i, t in enumerate(terms)}

        t0 = time.time()
        hits = self._run_vol_scan(
            image, output_dir, yara_rule, term_map,
            vol_wrapper, os_type, pid_filter,
            case_insensitive, wide, timeout,
        )
        duration = time.time() - t0

        plugin = _VOL3_PLUGIN.get(os_type, "windows.vadyarascan.VadYaraScan")
        if vol_wrapper.vol_version == "vol2":
            plugin = "yarascan"

        # Group results
        by_term: Dict[str, List] = {t: [] for t in terms}
        by_process: Dict[str, List] = {}
        for h in hits:
            t = h.get("search_term", "")
            if t in by_term:
                by_term[t].append(h)
            key = f"{h['pid']}:{h['process']}"
            by_process.setdefault(key, []).append(h)

        # Grep existing strings files for quick supplementary count
        strings_hits = self._grep_strings_files(output_dir, terms)

        results = {
            "terms":         terms,
            "hits":          hits,
            "by_term":       by_term,
            "by_process":    by_process,
            "strings_hits":  strings_hits,
            "total_hits":    len(hits),
            "scan_duration": round(duration, 1),
            "plugin":        plugin,
            "image":         image,
            "timestamp":     datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }

        self._write_json(results, jd)
        self._write_report(results, output_dir)
        return results

    # ------------------------------------------------------------------
    # Volatility scan dispatcher
    # ------------------------------------------------------------------

    def _run_vol_scan(
        self, image, output_dir, yara_rule, term_map,
        vol_wrapper, os_type, pid_filter,
        case_insensitive, wide, timeout,
    ) -> List[Dict]:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yar", delete=False, prefix="crescent_hunt_"
        ) as tf:
            tf.write(yara_rule)
            yara_path = tf.name

        try:
            if vol_wrapper.vol_version == "vol3":
                return self._scan_vol3(
                    image, output_dir, yara_path, term_map,
                    vol_wrapper, os_type, pid_filter,
                    case_insensitive, wide, timeout,
                )
            else:
                return self._scan_vol2(
                    image, output_dir, yara_path, term_map,
                    vol_wrapper, pid_filter, timeout,
                )
        finally:
            try:
                Path(yara_path).unlink(missing_ok=True)
            except Exception:
                pass

    def _scan_vol3(
        self, image, output_dir, yara_path, term_map,
        vol, os_type, pid_filter, insensitive, wide, timeout,
    ) -> List[Dict]:
        plugin = _VOL3_PLUGIN.get(os_type, "windows.vadyarascan.VadYaraScan")
        extra  = ["--yara-file", yara_path]
        if insensitive:
            extra.append("--insensitive")
        if wide:
            extra.append("--wide")
        if pid_filter:
            extra += ["--pid"] + [str(p) for p in pid_filter]

        jd = output_dir / "json"
        result = vol.run_plugin(image, plugin, output_dir,
                                extra_args=extra)
        if not result.get("success"):
            self.log.warning("VadYaraScan failed: %s", result.get("error", ""))
            # Try to parse anyway — there may be partial output
        out_file = Path(result.get("output_file", ""))
        if not out_file.is_file():
            return []
        try:
            raw = out_file.read_text(encoding="utf-8", errors="ignore").strip()
            # Strip progress lines (in case they leaked)
            lines = [l for l in raw.splitlines() if not l.startswith("Progress:")]
            raw = "\n".join(lines)
            # Find JSON start
            start = next((i for i, c in enumerate(raw) if c in "[{"), -1)
            if start == -1:
                return []
            data = json.loads(raw[start:])
        except Exception as exc:
            self.log.error("JSON parse of yarascan output: %s", exc)
            return []

        return _parse_vol3_hits(data, term_map)

    def _scan_vol2(
        self, image, output_dir, yara_path, term_map,
        vol, pid_filter, timeout,
    ) -> List[Dict]:
        extra = [f"--yara-file={yara_path}"]
        if pid_filter:
            extra += [f"--pid={p}" for p in pid_filter]

        result = vol.run_plugin(image, "yarascan", output_dir,
                                extra_args=extra)
        out_file = Path(result.get("output_file", ""))
        if not out_file.is_file():
            return []
        text = out_file.read_text(encoding="utf-8", errors="ignore")
        return _parse_vol2_hits(text, term_map)

    # ------------------------------------------------------------------
    # Strings-file grep (supplementary fast pass)
    # ------------------------------------------------------------------

    def _grep_strings_files(self, output_dir: Path, terms: List[str]) -> Dict[str, int]:
        hits: Dict[str, int] = {}
        candidates = [
            output_dir / "strings_ascii.txt",
            output_dir / "strings_unicode.txt",
        ]
        available = [p for p in candidates if p.is_file()]
        if not available:
            return hits

        for term in terms:
            count = 0
            for sf in available:
                try:
                    proc = subprocess.run(
                        ["grep", "-iac", term, str(sf)],
                        capture_output=True, text=True, timeout=30,
                    )
                    count += int(proc.stdout.strip() or 0)
                except Exception:
                    pass
            hits[term] = count
        return hits

    # ------------------------------------------------------------------
    # Output writers
    # ------------------------------------------------------------------

    def _write_json(self, results: Dict, jd: Path) -> Path:
        out = jd / "string_hunt.json"
        # Make it JSON-serialisable (drop non-serialisable objects)
        safe = {k: v for k, v in results.items()
                if k not in ("vol_wrapper",)}
        out.write_text(json.dumps(safe, indent=2, default=str),
                       encoding="utf-8")
        self.log.info("String Hunt JSON: %s", out)
        return out

    def _write_report(self, results: Dict, output_dir: Path) -> Path:
        out = output_dir / "string_hunt.txt"
        lines: List[str] = []
        w = lines.append

        w("=" * 72)
        w("  STRING HUNT RESULTS")
        w("=" * 72)
        w(f"  Image   : {results['image']}")
        w(f"  At      : {results['timestamp']}")
        w(f"  Engine  : {results['plugin']}")
        w(f"  Terms   : {len(results['terms'])} — "
          + ", ".join(f'"{t}"' for t in results['terms']))
        w(f"  Duration: {results['scan_duration']}s")
        w(f"  Total   : {results['total_hits']} hits")
        w("")

        for term in results["terms"]:
            term_hits = results["by_term"].get(term, [])
            w("─" * 72)
            w(f'  "{term}"  —  {len(term_hits)} hit(s)')
            w("─" * 72)
            if not term_hits:
                w("  (no matches)")
            else:
                # Deduplicate by (pid, process) to show summary first
                procs_seen: Dict[str, int] = {}
                for h in term_hits:
                    k = f"{h['pid']}:{h['process']}"
                    procs_seen[k] = procs_seen.get(k, 0) + 1
                w(f"  Found in {len(procs_seen)} process(es):")
                for pk, cnt in sorted(procs_seen.items(),
                                      key=lambda x: -x[1]):
                    pid_s, proc = pk.split(":", 1)
                    w(f"    PID {pid_s:>6s}  {proc:25s}  ({cnt} occurrence(s))")
                w("")
                w("  Hit detail (up to 50):")
                for h in term_hits[:50]:
                    decoded = h.get("decoded", "")[:48]
                    w(f"    PID {h['pid']:>6}  {h['process']:25s}"
                      f"  @ {h['offset']:>18}  │  {decoded}")
                if len(term_hits) > 50:
                    w(f"    ... and {len(term_hits) - 50} more hits (see JSON)")
            w("")

        if results["strings_hits"]:
            w("─" * 72)
            w("  STRINGS CORPUS SEARCH (strings_ascii.txt / strings_unicode.txt)")
            w("─" * 72)
            w("  NOTE: corpus search counts occurrences but has no process attribution.")
            w("")
            for term, count in results["strings_hits"].items():
                mark = "  " if count == 0 else "! "
                w(f"  {mark}\"{term}\"  →  {count} occurrence(s)")
            w("")

        w("=" * 72)
        out.write_text("\n".join(lines), encoding="utf-8")
        self.log.info("String Hunt report: %s", out)
        return out


# ------------------------------------------------------------------
# YARA rule builder
# ------------------------------------------------------------------

def _build_yara_rule(terms: List[str]) -> str:
    if not terms:
        raise ValueError("No search terms provided")
    string_defs = []
    for i, term in enumerate(terms):
        escaped = term.replace("\\", "\\\\").replace('"', '\\"')
        string_defs.append(f'        $s{i} = "{escaped}" ascii')
    return (
        "rule StringHunt {\n"
        "    meta:\n"
        '        description = "CresCent string hunt"\n'
        "    strings:\n"
        + "\n".join(string_defs) + "\n"
        "    condition:\n"
        "        any of them\n"
        "}\n"
    )


# ------------------------------------------------------------------
# Vol3 JSON output parser
# ------------------------------------------------------------------

def _parse_vol3_hits(data: Any, term_map: Dict[str, str]) -> List[Dict]:
    hits = []
    if not isinstance(data, list):
        data = [data] if isinstance(data, dict) else []

    for entry in data:
        if not isinstance(entry, dict):
            continue
        pid      = _gv(entry, *_FIELD_PID, default=0)
        process  = str(_gv(entry, *_FIELD_PROCESS, default="unknown")).strip()
        # Remove null bytes that appear in raw memory strings
        process  = process.rstrip("\x00")
        component = str(_gv(entry, *_FIELD_COMP, default=""))
        offset   = _gv(entry, *_FIELD_OFFSET, default=0)
        rule     = str(_gv(entry, *_FIELD_RULE, default="StringHunt"))
        hex_val  = str(_gv(entry, *_FIELD_VALUE, default=""))

        # Resolve the component back to the user's original search term
        search_term = term_map.get(component, component)

        # Decode hex bytes to printable string for context display
        decoded = _decode_hex(hex_val)

        # Normalise offset to hex string
        if isinstance(offset, int):
            offset_str = f"0x{offset:016x}"
        else:
            offset_str = str(offset)

        try:
            pid = int(pid)
        except (ValueError, TypeError):
            pid = 0

        hits.append({
            "pid":         pid,
            "process":     process,
            "component":   component,
            "search_term": search_term,
            "rule":        rule,
            "offset":      offset_str,
            "hex_bytes":   hex_val,
            "decoded":     decoded,
        })

    return hits


# ------------------------------------------------------------------
# Vol2 text output parser
# ------------------------------------------------------------------

# Vol2 yarascan text format:
#   Rule: <name>
#   Owner: Process <name> Pid <pid>
#   <offset>  <hex bytes>  <ascii>
#   (blank line separates hits)

_V2_RULE_RE  = re.compile(r"^Rule\s*:\s*(.+)", re.I)
_V2_OWNER_RE = re.compile(
    r"Owner\s*:\s*(?:Process\s+(.+?)\s+Pid\s+(\d+)|(.+))", re.I
)
_V2_OFFSET_RE = re.compile(r"^(0x[0-9a-fA-F]+)\s+((?:[0-9a-fA-F]{2}\s+)+)(.*)")


def _parse_vol2_hits(text: str, term_map: Dict[str, str]) -> List[Dict]:
    hits = []
    current_rule = ""
    current_pid = 0
    current_proc = "unknown"
    reverse_map = {v: k for k, v in term_map.items()}  # term → $sN

    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("Volatility") or line.startswith("*"):
            continue

        m = _V2_RULE_RE.match(line)
        if m:
            current_rule = m.group(1).strip()
            continue

        m = _V2_OWNER_RE.match(line)
        if m:
            if m.group(1):
                current_proc = m.group(1).strip()
                current_pid  = int(m.group(2))
            else:
                current_proc = m.group(3).strip()
                current_pid  = 0
            continue

        m = _V2_OFFSET_RE.match(line)
        if m:
            offset_str = m.group(1)
            hex_bytes  = m.group(2).strip()
            ascii_ctx  = m.group(3).strip()
            # Try to find which term matched
            search_term = _match_term_in_bytes(hex_bytes, term_map)
            hits.append({
                "pid":         current_pid,
                "process":     current_proc,
                "component":   reverse_map.get(search_term, ""),
                "search_term": search_term,
                "rule":        current_rule,
                "offset":      offset_str,
                "hex_bytes":   hex_bytes,
                "decoded":     ascii_ctx or _decode_hex(hex_bytes),
            })

    return hits


def _match_term_in_bytes(hex_bytes: str, term_map: Dict[str, str]) -> str:
    """Guess which search term produced this hex match by decoding the bytes."""
    decoded = _decode_hex(hex_bytes).lower()
    for term in term_map.values():
        if term.lower() in decoded:
            return term
    return list(term_map.values())[0] if term_map else ""


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _decode_hex(hex_str: str) -> str:
    """Convert a space-separated hex string to printable ASCII, replacing non-printables."""
    if not hex_str:
        return ""
    try:
        raw = bytes.fromhex(hex_str.replace(" ", ""))
        return "".join(
            chr(b) if 0x20 <= b < 0x7F else "."
            for b in raw
        )
    except ValueError:
        return hex_str
