"""CresCent RAM Forensics Toolkit v4.0 - JSON Converter Utilities"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def parse_vol2_table(text: str, plugin_name: str = "") -> List[Dict[str, Any]]:
    """Parse Volatility 2 text-table output into list of dicts."""
    lines = text.splitlines()
    if plugin_name in ("cmdscan", "consoles"):
        return _parse_block_format(lines)
    elif plugin_name == "cmdline":
        return _parse_cmdline(lines)
    elif plugin_name == "hashdump":
        return _parse_hashdump(lines)
    elif plugin_name in ("shellbags", "shimcache"):
        return _parse_special_table(lines)
    else:
        return _parse_std_table(lines)


def _parse_cmdline(lines):
    """Parse Vol2 cmdline output.

    Vol2 cmdline uses paired lines per process:
      '<Name> pid:  <PID>'
      'Command line : <args>'

    _parse_std_table mistakes the first process line for a header and produces
    wrong field names ("System pid:", "4") with 0 extractable PIDs. This
    dedicated parser yields {"Process", "PID", "CommandLine"} per entry.
    """
    _pid_re = re.compile(r'^(.+?)\s+pid:\s+(\d+)\s*$', re.I)
    _cmd_re = re.compile(r'^Command\s+line\s*:\s*(.*)', re.I)
    results = []
    pending = None  # (name, pid_str)
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("Volatility") or line.startswith("*"):
            continue
        m = _pid_re.match(line)
        if m:
            if pending:
                results.append({"Process": pending[0], "PID": pending[1], "CommandLine": ""})
            pending = (m.group(1).strip(), m.group(2))
            continue
        m2 = _cmd_re.match(line)
        if m2 and pending:
            results.append({"Process": pending[0], "PID": pending[1],
                            "CommandLine": m2.group(1).strip()})
            pending = None
            continue
        if pending:
            results.append({"Process": pending[0], "PID": pending[1], "CommandLine": ""})
            pending = None
    if pending:
        results.append({"Process": pending[0], "PID": pending[1], "CommandLine": ""})
    return results


def _parse_block_format(lines):
    results, cur = [], {}
    for line in lines:
        line = line.rstrip()
        # Skip Volatility banner lines and *** warning/error lines entirely —
        # distorm3 import failures would otherwise become the first "record".
        if not line or line.startswith("Volatility") or line.startswith("*"):
            if cur:
                results.append(cur)
                cur = {}
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            k, v = k.strip(), v.strip()
            if k and v:
                cur[k] = v
        elif line.strip().startswith(("0x", ">>")):
            cur.setdefault("Output", [])
            if isinstance(cur["Output"], list):
                cur["Output"].append(line.strip())
        elif line.strip() and cur:
            cur["raw"] = cur.get("raw", "") + ("\n" if "raw" in cur else "") + line.strip()
    if cur:
        results.append(cur)
    return results


def _parse_hashdump(lines):
    results = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Volatility") or line.startswith("-"):
            continue
        if ":" in line:
            p = line.split(":")
            if len(p) >= 4:
                results.append({"User": p[0], "RID": p[1], "LMHash": p[2],
                                "NTHash": p[3], "raw": line})
            else:
                results.append({"raw": line})
    return results


def _parse_special_table(lines):
    results, header = [], None
    for line in lines:
        line = line.rstrip()
        if not line or line.startswith("Volatility") or line.startswith("***"):
            continue
        if re.match(r"^[-=\s]+$", line.strip()) and "-" in line:
            continue
        if header is None and re.match(r"^[A-Za-z]", line):
            header = re.split(r"\s{2,}", line.strip())
            continue
        if header:
            parts = re.split(r"\s{2,}", line.strip())
            if parts:
                results.append({header[j] if j < len(header) else f"col_{j}": v
                                for j, v in enumerate(parts)})
        else:
            results.append({"raw": line.strip()})
    return results


def _parse_std_table(lines):
    """Parse Vol2 standard table output using column-width detection.

    Vol2 outputs fixed-width columns with a separator line like:
        Offset(V)          Name                    PID   PPID
        ------------------ -------------------- ------ ------
        0xfffffa80012a5040 System                    4      0

    Also handles headerless Linux output (e.g. linux_lsmod):
        ffffffffc0616500 binfmt_misc 20480
    """
    results = []
    header_line = None
    sep_line = None
    data_lines = []
    raw_lines = []  # All non-meta non-separator lines (for headerless fallback)

    for line in lines:
        line = line.rstrip()
        if not line or line.startswith("Volatility") or line.startswith("***"):
            continue
        # Separator lines: dashes/equals only
        if re.match(r"^[-=\s]+$", line.strip()) and "-" in line:
            if header_line and not sep_line:
                sep_line = line
            continue
        # Detect header line (starts with letter, has 2+ spaces between words)
        if header_line is None and re.match(r"^[A-Za-z]", line) and "  " in line:
            header_line = line
            continue
        if line.strip():
            raw_lines.append(line)
            if header_line is not None:
                data_lines.append(line)

    # Headerless format (e.g. linux_lsmod: no header, plain whitespace-separated)
    if not header_line:
        return [{"raw": l.strip()} for l in raw_lines if l.strip()]

    if not data_lines:
        # Header found but no data rows — return raw fallback
        return [{"raw": l.strip()} for l in raw_lines if l.strip()]

    # Determine column boundaries from the separator line
    if sep_line:
        col_spans = _find_column_spans(sep_line)
    else:
        col_spans = None

    if col_spans:
        # Extract header names using column spans
        headers = []
        for start, end in col_spans:
            h = header_line[start:end].strip() if start < len(header_line) else ""
            headers.append(h)

        # Parse each data line using the same column positions
        for line in data_lines:
            row = {}
            for i, (start, end) in enumerate(col_spans):
                val = line[start:end].strip() if start < len(line) else ""
                key = headers[i] if i < len(headers) and headers[i] else f"col_{i}"
                row[key] = val
            if any(v for v in row.values()):
                results.append(row)
    else:
        # Fallback: split by 2+ spaces
        header = re.split(r"\s{2,}", header_line.strip())
        for line in data_lines:
            parts = re.split(r"\s{2,}", line.strip())
            if header and parts:
                results.append({header[j] if j < len(header) else f"col_{j}": v
                                for j, v in enumerate(parts)})
            else:
                results.append({"raw": line.strip()})

    return results


def _find_column_spans(sep_line: str):
    """Find column start/end positions from a Vol2 separator line.

    Separator looks like: '---------- --------- ------ ------ ------'
    Each column is a run of dashes, separated by spaces.

    Uses exact dash boundaries. For each column except the last,
    extends only to the midpoint of the gap to the next column
    (captures right-aligned data without bleeding into the next column).
    Last column extends to end of line.
    """
    spans = []
    i = 0
    n = len(sep_line)
    while i < n:
        if sep_line[i] in (' ', '\t'):
            i += 1
            continue
        if sep_line[i] in ('-', '='):
            start = i
            while i < n and sep_line[i] in ('-', '='):
                i += 1
            end = i
            spans.append((start, end))
        else:
            i += 1

    if not spans:
        return None

    # For each column, extend slightly into the gap (but not past midpoint)
    adjusted = []
    for idx, (start, end) in enumerate(spans):
        if idx == 0:
            # First column: start from 0
            col_start = 0
        else:
            # Start from just after previous column's dash end
            prev_end = spans[idx - 1][1]
            col_start = prev_end  # Include the gap (spaces before this column)

        if idx < len(spans) - 1:
            # End at the start of next column's dashes
            next_start = spans[idx + 1][0]
            col_end = next_start
        else:
            # Last column extends to end of line
            col_end = 9999

        adjusted.append((col_start, col_end))

    return adjusted


def load_json_safe(path: Path) -> Any:
    """Load a JSON file with fallback strategies for progress lines, BOM, truncation."""
    try:
        content = path.read_text(encoding="utf-8-sig", errors="ignore").strip()
    except OSError:
        return []
    if not content:
        return []
    js = -1
    for i, ch in enumerate(content):
        if ch in "[{":
            js = i
            break
    if js == -1:
        return []
    content = content[js:]
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    for i in range(len(content) - 1, -1, -1):
        if content[i] in "]}":
            try:
                return json.loads(content[:i + 1])
            except json.JSONDecodeError:
                continue
    return []


def load_json_by_pattern(json_dir: Path, pattern: str) -> List[Dict[str, Any]]:
    """Search directory for a JSON file matching pattern and load it."""
    if not json_dir.is_dir():
        return []
    for f in sorted(json_dir.iterdir()):
        if pattern.lower() in f.name.lower() and f.suffix == ".json":
            data = load_json_safe(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return [data]
            return []
    return []


def convert_json_to_txt(json_dir: Path, txt_dir: Path) -> Tuple[int, int]:
    """Convert all JSON files in a directory to human-readable TXT."""
    txt_dir.mkdir(parents=True, exist_ok=True)
    ok = fail = 0
    for jp in sorted(json_dir.glob("*.json")):
        tp = txt_dir / jp.name.replace(".json", ".txt")
        try:
            data = load_json_safe(jp)
            if not data:
                continue
            with open(tp, "w", encoding="utf-8") as fh:
                _write_txt_item(fh, data)
            ok += 1
        except Exception:
            fail += 1
    return ok, fail


def _write_txt_item(fh, data, indent=0):
    pfx = "  " * (indent + 1)
    if isinstance(data, list):
        for item in data:
            _write_txt_item(fh, item, indent)
        return
    if isinstance(data, dict):
        for k, v in data.items():
            if k == "__children":
                continue
            if isinstance(v, dict):
                fh.write(f"{pfx}{k}:\n")
                _write_txt_item(fh, v, indent + 1)
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                fh.write(f"{pfx}{k}:\n")
                for sub in v[:10]:
                    _write_txt_item(fh, sub, indent + 1)
                if len(v) > 10:
                    fh.write(f"{pfx}  ... and {len(v) - 10} more\n")
            else:
                if isinstance(v, str):
                    v = v.strip().strip('"')
                fh.write(f"{pfx}{k}: {v}\n")
        fh.write("-" * 40 + "\n")
    else:
        fh.write(f"{pfx}{data}\n")
        fh.write("-" * 40 + "\n")
