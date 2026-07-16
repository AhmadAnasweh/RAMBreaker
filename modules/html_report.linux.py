"""
CresCent RAM Forensics Toolkit v4.0 - HTML Report Generator

JSON-only report generator.

Pages:
  1. Summary + device info + correlation + system_info
  2. Browser history + all plugin JSON files inside json/
  3. Process tree, built from JSON process data
  4. Graphical process map + network_map
  5. IOCs as compact browseable JSON tables
  6. Timeline
  7. Other JSON artifacts

Important:
  - Does not read strings_ascii.txt, strings_unicode.txt, or raw strings files.
  - Does not rely on process_tree.txt or any other TXT artifact.
  - Displays source file paths for the JSON data it uses.
  - Presents raw data and correlations only; it does not decide malicious/benign.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import traceback

from utils.json_converter import safe_js_json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class HTMLReportGenerator:
    """Generate an interactive, self-contained HTML report from CresCent JSON artifacts."""

    VERSION = "6.0-linux"
    MAX_EMBED_ROWS = 1500
    MAX_EMBED_STRING_CHARS = 600
    MAX_EMBED_DICT_KEYS = 80
    EMBED_ALL_JSON = False
    GREP_PORT = 8765

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self.stage = "init"
        self.errors: List[Dict[str, str]] = []

    def _set_stage(self, stage: str) -> None:
        self.stage = stage
        self.log.info("[stage] %s", stage)

    def _record_error(self, stage: str, path: Optional[Path], exc: Exception) -> None:
        item = {
            "stage": stage,
            "file": str(path) if path else "",
            "error": f"{type(exc).__name__}: {exc}",
        }
        self.errors.append(item)
        self.log.error("[error] stage=%s file=%s error=%s", item["stage"], item["file"], item["error"])
        self.log.debug("Traceback for recovered error:\n%s", traceback.format_exc())

    def generate(self, output_dir: Path) -> Path:
        od = Path(output_dir).expanduser().resolve()
        self._set_stage("validate output directory")
        if not od.exists():
            raise FileNotFoundError(f"Output directory does not exist: {od}")
        if not od.is_dir():
            raise NotADirectoryError(f"Output path is not a directory: {od}")

        html_path = od / "report.html"
        self._set_stage("collect JSON data")
        data = self._collect_data(od)
        data["collection_errors"] = self.errors

        self._set_stage("build HTML")
        html = self._build_html(data, od)

        self._set_stage("write report.html")
        html_path.write_text(html, encoding="utf-8")
        self.log.info("HTML report: %s (%d bytes)", html_path, len(html))
        return html_path

    # ------------------------------------------------------------------
    # JSON collection helpers
    # ------------------------------------------------------------------

    def _collect_data(self, od: Path) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "output_dir": str(od),
            "builder_version": self.VERSION,
            "sources": {},
            "root_json": {},
            "plugins": [],
            "named": {},
            "iocs": {},
            "other_json": {},
            "notes": [
                "This report is JSON-only. TXT/string artifacts are intentionally excluded.",
                "The process trees and graphs are built from JSON process rows and PID/PPID fields.",
                "Command lines are read from cmdline JSON rows when present.",
                "Network rows are read from network plugin JSON rows when present.",
                "Encoding IOC categories are intentionally excluded from the HTML report only: base64, hex, encoded, encoding, blob.",
            ],
        }

        root_targets = {
            "system_info":     "json/system_info.json",
            "correlation":     "json/correlation_report.json",
            "injection":       "json/injection_correlation.json",
            "browser":         "iocs/json/browser_history.json",
            "network_map":     "json/network_map.json",
            "registry":        "json/registry_report.json",
            "timeline":        "json/timeline.json",
            "evtx":            "json/evtx_report.json",
            "comms":           "json/comms_report.json",
            "popular_files":   "iocs/json/popular_files.json",
            "scheduled_tasks": "iocs/json/scheduled_tasks.json",
        }
        self._set_stage("load root JSON artifacts")
        for key, rel in root_targets.items():
            p = self._find_path_ci(od, rel)
            if p and p.is_file() and self._is_allowed_json_file(p):
                obj = self._load_json(p)
                if obj is not None:
                    data["root_json"][key] = obj
                    data["sources"][key] = self._rel(od, p)

        # Convenience aliases for pages.
        data["system_info"]     = data["root_json"].get("system_info", {})
        data["correlation"]     = data["root_json"].get("correlation", {})
        data["injection"]       = data["root_json"].get("injection", {})
        data["browser"]         = data["root_json"].get("browser", {})
        data["network_map"]     = data["root_json"].get("network_map", {})
        data["timeline"]        = data["root_json"].get("timeline", [])
        data["registry"]        = data["root_json"].get("registry", {})
        data["evtx"]            = data["root_json"].get("evtx", {})
        data["comms"]           = data["root_json"].get("comms", {})
        data["popular_files"]   = data["root_json"].get("popular_files", {})
        data["scheduled_tasks"] = data["root_json"].get("scheduled_tasks", {})

        # All Volatility plugin JSON files inside json/.
        self._set_stage("load plugin JSON files from json/")
        jd = od / "json"
        if jd.is_dir():
            for p in sorted(jd.glob("*.json"), key=lambda x: x.name.lower()):
                if not self._is_allowed_json_file(p):
                    continue
                obj = self._load_json(p)
                if obj is None:
                    continue
                rows = self._normalize_rows(obj)
                rec = {
                    "name": p.stem,
                    "file": self._rel(od, p),
                    "row_count": len(rows),
                    "rows": rows,
                    "raw": obj,
                }
                data["plugins"].append(rec)
                data["sources"][f"plugin:{p.stem}"] = self._rel(od, p)

            # Named plugin shortcuts, case-insensitive filename keyword matching.
            for key in (
                "pslist", "pstree", "psscan", "cmdline", "netscan", "netstat",
                "connscan", "connections", "sockscan", "sockets", "malfind", "svcscan",
                "dlllist", "filescan", "handles", "ldrmodules", "hivelist", "userassist",
                "shimcache", "shellbags", "mftscan", "vadinfo", "hashdump", "getsids", "envars",
                "sockstat", "bash", "lsmod", "lsof", "psaux", "mountinfo", "mount",
                "library_list", "elfs", "check_syscall", "ifconfig", "ip_addr", "ip_Addr", "proc_Maps",
                # Shell command evidence
                "cmdscan", "consoles", "printkey", "svcscan",
                # macOS
                "mac_pslist", "mac_bash", "mac_netstat", "mac_lsof",
            ):
                found = self._first_plugin(data["plugins"], key)
                if found:
                    data["named"][key] = {
                        "file": found["file"],
                        "row_count": found["row_count"],
                        "rows": found["rows"],
                    }

        # IOC JSON only: iocs/json/*.json and iocs/ioc_results.json. No ioc_*.txt.
        self._set_stage("load IOC JSON files from iocs/json/")
        ioc_dir = od / "iocs" / "json"
        if ioc_dir.is_dir():
            for p in sorted(ioc_dir.glob("*.json"), key=lambda x: x.name.lower()):
                if not self._is_allowed_json_file(p):
                    continue
                obj = self._load_json(p)
                if obj is None:
                    continue
                rows = self._normalize_rows(obj)
                name = p.stem.replace("ioc_", "")
                if self._is_encoding_ioc_name(name):
                    self.log.info("[iocs] excluded encoding IOC category from HTML report: %s (%s)", name, self._rel(od, p))
                    continue
                data["iocs"][name] = {
                    "file": self._rel(od, p),
                    "row_count": len(rows),
                    "rows": rows,
                    "raw": obj,
                }
                data["sources"][f"ioc:{name}"] = self._rel(od, p)

        # Any other root-level JSON artifacts not already assigned. Exclude strings-like JSON by name.
        self._set_stage("load other root-level JSON files")
        used_files = set(data["sources"].values())
        for p in sorted(od.glob("*.json"), key=lambda x: x.name.lower()):
            if not self._is_allowed_json_file(p):
                continue
            rel = self._rel(od, p)
            if rel in used_files:
                continue
            obj = self._load_json(p)
            if obj is None:
                continue
            rows = self._normalize_rows(obj)
            data["other_json"][p.stem] = {
                "file": rel,
                "row_count": len(rows),
                "rows": rows,
                "raw": obj,
            }
            data["sources"][f"other:{p.stem}"] = rel

        self._set_stage("calculate report counts")
        data["counts"] = self._counts(data)
        return data

    def _counts(self, data: Dict[str, Any]) -> Dict[str, int]:
        named = data.get("named", {})
        network_total = sum(named.get(k, {}).get("row_count", 0) for k in (
            "netscan", "netstat", "connscan", "connections", "sockscan", "sockets", "sockstat"))
        ioc_total = sum(v.get("row_count", 0) for v in data.get("iocs", {}).values())
        timeline_rows = len(self._normalize_rows(data.get("timeline")))
        pf = data.get("popular_files", {})
        st = data.get("scheduled_tasks", {})
        return {
            "plugins":        len(data.get("plugins", [])),
            "processes":      named.get("pslist", {}).get("row_count", 0),
            "psscan":         named.get("psscan", {}).get("row_count", 0),
            "network_rows":   network_total,
            "malfind":        named.get("malfind", {}).get("row_count", 0),
            "services":       named.get("svcscan", {}).get("row_count", 0),
            "files_scanned":  pf.get("total_files_scanned", 0) if isinstance(pf, dict) else 0,
            "ioc_tables":     len(data.get("iocs", {})),
            "ioc_rows":       ioc_total,
            "timeline_rows":  timeline_rows,
            "task_findings":  st.get("total_findings", 0) if isinstance(st, dict) else 0,
            "other_json":     len(data.get("other_json", {})),
        }

    def _first_plugin(self, plugins: List[Dict[str, Any]], keyword: str) -> Optional[Dict[str, Any]]:
        key = keyword.lower()
        matches = [p for p in plugins if key in p.get("name", "").lower()]
        if not matches:
            return None
        # Prefer exact-ish plugin names and non-vol2 only as tie breaker by shorter names.
        matches.sort(key=lambda p: ("_vol2" in p.get("name", "").lower(), len(p.get("name", "")), p.get("name", "").lower()))
        return matches[0]

    def _is_allowed_json_file(self, p: Path) -> bool:
        n = p.name.lower()
        # Explicitly avoid strings/ascii/unicode artifacts. This prevents huge string material crashing the page.
        banned = ("strings", "ascii", "unicode")
        return p.suffix.lower() == ".json" and not any(b in n for b in banned)

    def _is_encoding_ioc_name(self, name: str) -> bool:
        """Return True for IOC categories that should not be embedded in the HTML report.

        This does not delete or modify extractor output on disk. It only hides these
        IOC categories from report data: base64, hex, encoded/encoding, blobs.
        """
        n = str(name or "").lower()
        blocked = (
            "base64",
            "hex",
            "encoding",
            "encoded",
            "blob",
        )
        return any(x in n for x in blocked)

    def _find_path_ci(self, base: Path, rel: str) -> Optional[Path]:
        cur = base
        for part in Path(rel).parts:
            if not cur.exists() or not cur.is_dir():
                return None
            exact = cur / part
            if exact.exists():
                cur = exact
                continue
            found = None
            for child in cur.iterdir():
                if child.name.lower() == part.lower():
                    found = child
                    break
            if found is None:
                return None
            cur = found
        return cur

    def _rel(self, base: Path, p: Path) -> str:
        try:
            return str(p.relative_to(base)).replace("\\", "/")
        except Exception:
            return str(p)

    def _load_json(self, p: Path) -> Any:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore").strip()
            if not text:
                return None
            # Volatility output can contain progress lines before JSON. Cut to first object/array.
            starts = [i for i in (text.find("{"), text.find("[")) if i >= 0]
            if starts:
                text = text[min(starts):]
            return json.loads(text)
        except Exception as e:
            self._record_error(f"load JSON while {self.stage}", p, e)
            return None

    def _normalize_rows(self, obj: Any) -> List[Dict[str, Any]]:
        if obj is None:
            return []
        if isinstance(obj, list):
            return [x if isinstance(x, dict) else {"value": x} for x in obj]
        if isinstance(obj, dict):
            for key in ("rows", "Rows", "data", "Data", "items", "results", "records", "values"):
                val = obj.get(key)
                if isinstance(val, list):
                    return self._normalize_rows(val)

            columns = obj.get("columns") or obj.get("Columns")
            rows = obj.get("rows") or obj.get("Rows")
            if isinstance(columns, list) and isinstance(rows, list):
                names: List[str] = []
                for c in columns:
                    if isinstance(c, dict):
                        names.append(str(c.get("name") or c.get("Name") or c.get("title") or c))
                    else:
                        names.append(str(c))
                out: List[Dict[str, Any]] = []
                for row in rows:
                    if isinstance(row, dict):
                        out.append(row)
                    elif isinstance(row, list):
                        out.append({names[i] if i < len(names) else f"col_{i}": row[i] for i in range(len(row))})
                    else:
                        out.append({"value": row})
                return out

            # Tree-grid-like nested object.
            if isinstance(obj.get("children"), list):
                out: List[Dict[str, Any]] = []
                def walk(node: Any) -> None:
                    if isinstance(node, dict):
                        row = {k: v for k, v in node.items() if k != "children"}
                        if row:
                            out.append(row)
                        for ch in node.get("children", []) or []:
                            walk(ch)
                walk(obj)
                return out

            return [obj]
        return [{"value": obj}]

    # ------------------------------------------------------------------
    # HTML payload safety
    # ------------------------------------------------------------------

    def _slim_for_html(self, obj: Any, depth: int = 0, key: str = "") -> Any:
        """Return the HTML payload.

        Normal mode creates a browser-safer copy by limiting rows/strings and
        skipping duplicate raw JSON blobs.

        Danger mode (--embed-all-json) embeds the collected JSON as-is: all rows,
        full string values, all dict keys, and raw JSON blobs. This can create a
        huge report.html and may freeze the browser/VM, but it is useful when the
        investigator explicitly wants everything inside the single HTML file.
        """
        if self.EMBED_ALL_JSON:
            return obj
        if depth > 8:
            return "<depth limit reached>"
        if isinstance(obj, str):
            if len(obj) > self.MAX_EMBED_STRING_CHARS:
                return obj[:self.MAX_EMBED_STRING_CHARS] + f"... <truncated {len(obj) - self.MAX_EMBED_STRING_CHARS} chars>"
            return obj
        if isinstance(obj, (int, float, bool)) or obj is None:
            return obj
        if isinstance(obj, list):
            original_len = len(obj)
            limited = obj[: self.MAX_EMBED_ROWS]
            out = [self._slim_for_html(x, depth + 1, key) for x in limited]
            if original_len > self.MAX_EMBED_ROWS:
                out.append({
                    "_crescent_note": f"HTML preview truncated: showing {self.MAX_EMBED_ROWS} of {original_len} rows",
                    "_full_count": original_len,
                })
            return out
        if isinstance(obj, dict):
            out: Dict[str, Any] = {}
            for i, (k, v) in enumerate(obj.items()):
                if str(k) == "raw":
                    # Vol2 text output is stored as {'raw': '<line>'} and IS the
                    # data (malfind/svcscan/hashdump/...). Keep it (string-capped)
                    # instead of blanking it; row cap + string cap prevent bloat.
                    out["raw"] = self._slim_for_html(v, depth + 1, "raw")
                    continue
                if i >= self.MAX_EMBED_DICT_KEYS:
                    out["_crescent_note"] = f"Object truncated after {self.MAX_EMBED_DICT_KEYS} keys"
                    break
                out[str(k)] = self._slim_for_html(v, depth + 1, str(k))
            return out
        return str(obj)

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def _build_html(self, data: Dict[str, Any], od: Path) -> str:
        if self.EMBED_ALL_JSON:
            self._set_stage("prepare FULL JSON payload (--embed-all-json danger mode)")
            print("[!] DANGER MODE: embedding ALL loaded JSON rows/raw blobs into report.html", flush=True)
            print("[!] This may create a huge HTML file and can freeze Firefox/Chrome/Kali.", flush=True)
        else:
            self._set_stage("prepare browser-safe JSON payload")
        slim_data = self._slim_for_html(data)
        if self.EMBED_ALL_JSON:
            self.log.info("[payload] FULL JSON embed enabled: no row/string/key/raw truncation")
        else:
            self.log.info("[payload] rows per table capped at %d; strings capped at %d chars; raw blobs omitted",
                          self.MAX_EMBED_ROWS, self.MAX_EMBED_STRING_CHARS)

        self._set_stage("serialize HTML JSON payload")
        js_data = safe_js_json(slim_data)
        self.log.info("[payload] embedded JSON size: %.2f MB", len(js_data.encode("utf-8")) / (1024 * 1024))

        template = HTML_TEMPLATE
        template = template.replace("__TITLE__", f"CresCent JSON Report - {od.name}")
        template = template.replace("__DATA__", js_data)
        return template


HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>__TITLE__</title>
<style>
*{box-sizing:border-box}html,body{margin:0;height:100%}body{background:#05070b;color:#d7dde8;font-family:Segoe UI,system-ui,-apple-system,Arial,sans-serif;font-size:14px}.header{padding:18px 26px;background:#090d14;border-bottom:1px solid #1f2937}.header h1{margin:0;color:#f3f6fb;font-size:22px;font-weight:650}.sub{margin-top:5px;color:#8b97a8;font-size:12px}.tabs{display:flex;gap:4px;overflow-x:auto;background:#0d1320;border-bottom:1px solid #253044;padding:0 12px}.tab{padding:12px 15px;color:#9aa7b8;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;font-size:13px}.tab:hover{background:#111a2b;color:#e5e7eb}.tab.active{background:#05070b;color:#7dd3fc;border-bottom-color:#7dd3fc}.badge{display:inline-block;margin-left:7px;padding:1px 7px;border-radius:999px;background:#1f2937;color:#cbd5e1;font-size:11px}.page{display:none;padding:18px 24px}.page.active{display:block}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin-bottom:14px}.card{background:#0b101a;border:1px solid #233047;border-radius:10px;padding:14px;margin-bottom:14px;box-shadow:0 8px 30px rgba(0,0,0,.18)}.card h2,.card h3{margin:0 0 10px;color:#eaf2ff}.card h2{font-size:17px}.card h3{font-size:14px}.stat{background:#080c13;border:1px solid #263247;border-radius:10px;padding:14px}.stat .n{font-size:24px;font-weight:700;color:#7dd3fc}.stat .l{font-size:12px;color:#94a3b8;margin-top:4px}.source{font-family:Consolas,Menlo,monospace;font-size:11px;color:#a5b4fc;background:#111827;border:1px solid #334155;border-radius:999px;padding:2px 7px;display:inline-block;margin:2px}.note{color:#94a3b8;line-height:1.45}.search{width:100%;max-width:720px;background:#05070b;color:#e5e7eb;border:1px solid #334155;border-radius:8px;padding:10px 12px;margin:0 0 12px}.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}.btn{background:#111827;border:1px solid #334155;color:#dbeafe;border-radius:7px;padding:8px 10px;cursor:pointer}.btn:hover{background:#172033;border-color:#4b5563}table{width:100%;border-collapse:collapse;font-size:12px;background:#070a10}th,td{border-bottom:1px solid #182235;padding:8px 9px;text-align:left;vertical-align:top}th{position:sticky;top:0;background:#111827;color:#bfdbfe;cursor:pointer;z-index:2}td{max-width:620px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}td.wrap{white-space:normal;word-break:break-word}.tablewrap{max-height:68vh;overflow:auto;border:1px solid #1f2937;border-radius:8px}.pill{display:inline-block;border-radius:999px;padding:2px 8px;font-size:11px;margin:2px;background:#1f2937;color:#cbd5e1}.pill.blue{background:#0c2741;color:#7dd3fc}.pill.green{background:#0d3322;color:#86efac}.pill.amber{background:#332a0d;color:#facc15}.pill.red{background:#3a1212;color:#fca5a5}.pill.purple{background:#251341;color:#c4b5fd}pre{background:#05070b;border:1px solid #1f2937;border-radius:8px;padding:12px;max-height:55vh;overflow:auto;color:#cbd5e1;white-space:pre-wrap;word-break:break-word;font-family:Consolas,Menlo,monospace;font-size:12px}.two{display:grid;grid-template-columns:minmax(280px,420px) 1fr;gap:14px}.plugin-list{max-height:76vh;overflow:auto}.plugin-item{padding:9px 10px;border-bottom:1px solid #1f2937;cursor:pointer}.plugin-item:hover,.plugin-item.active{background:#111827}.empty{padding:28px;text-align:center;color:#64748b;border:1px dashed #334155;border-radius:8px}.mini-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}.ioc-card{max-height:360px;display:flex;flex-direction:column}.ioc-card .tablewrap{max-height:260px}.json-kv{display:grid;grid-template-columns:220px 1fr;gap:6px 12px}.json-kv div:nth-child(odd){color:#94a3b8}.json-kv div:nth-child(even){color:#e5e7eb;word-break:break-word}.tree-node{margin-left:25px;border-left:1px solid #334155;padding-left:13px}.tree-root{margin-left:0;border-left:0}.tree-label{display:inline-flex;align-items:center;gap:7px;padding:6px 8px;border-radius:6px;cursor:pointer;margin:2px 0}.tree-label:hover{background:#111827}.tree-toggle{width:17px;color:#94a3b8}.tree-name{font-weight:650;color:#e5e7eb}.tree-pid{font-family:Consolas,monospace;color:#7dd3fc}.tree-cmd,.tree-net{margin-left:60px;font-family:Consolas,monospace;font-size:11px;color:#a7b0c0;max-width:1100px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.tree-net{color:#86efac}.tree-children.collapsed{display:none}.graph-shell{background:#02040a;border:1px solid #233047;border-radius:10px;overflow:hidden}.graph-toolbar{padding:10px;background:#0b101a;border-bottom:1px solid #233047}.graph-viewport{height:76vh;overflow:auto;position:relative;background:#ffffff;cursor:default;user-select:none}.graph-viewport.panning{cursor:grabbing}.graph-canvas{position:relative;min-width:2200px;min-height:1200px;transform-origin:0 0}.graph-svg{position:absolute;left:0;top:0;pointer-events:none;overflow:visible}.g-node{position:absolute;width:420px;min-height:132px;color:#111827;font-size:12px;z-index:5}.g-main{display:flex;gap:10px;align-items:flex-start;background:rgba(255,255,255,.96);padding:12px 14px;border-radius:10px;border:1px solid rgba(148,163,184,.45);box-shadow:0 4px 18px rgba(15,23,42,.10)}.hex{width:34px;height:38px;clip-path:polygon(25% 5%,75% 5%,100% 50%,75% 95%,25% 95%,0 50%);background:#64748b;box-shadow:0 1px 3px rgba(0,0,0,.25);flex:0 0 auto}.hex.cmd{background:#475569}.hex.net{background:#ef4444}.hex.both{background:#f97316}.g-title{font-weight:800;color:#334155;letter-spacing:.02em;white-space:nowrap}.g-meta{color:#64748b;font-size:11px;white-space:nowrap}.g-cmd{font-family:Consolas,monospace;font-size:10px;color:#475569;margin-top:5px;white-space:normal;overflow-wrap:anywhere;word-break:break-word;line-height:1.25;max-height:none;overflow:visible}.g-net{font-family:Consolas,monospace;font-size:10px;color:#991b1b;margin-top:5px;white-space:normal;overflow-wrap:anywhere;word-break:break-word;line-height:1.25;max-height:none;overflow:visible}.g-source{font-size:9px;color:#64748b;margin-top:6px;white-space:normal;overflow-wrap:anywhere;line-height:1.25}.g-node.dim{opacity:.28;filter:grayscale(.65)}.g-node.match{z-index:50;filter:none;opacity:1}.g-node.match .g-main{outline:3px solid #0284c7;outline-offset:5px;border-radius:10px;background:rgba(255,255,255,.98)}.g-node.current .g-main{outline:4px solid #f97316;box-shadow:0 0 0 8px rgba(249,115,22,.22);border-radius:10px}.graph-hit-count{color:#bfdbfe;font-size:12px;padding:8px 10px}.modal{position:fixed;inset:0;background:rgba(0,0,0,.76);z-index:9999;display:flex;align-items:center;justify-content:center;padding:22px}.modal.hidden{display:none!important}.modal-box{width:min(1500px,96vw);height:min(900px,92vh);background:#07101d;border:1px solid #334155;border-radius:12px;box-shadow:0 25px 80px rgba(0,0,0,.55);display:flex;flex-direction:column}.modal-head{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 14px;border-bottom:1px solid #233047}.modal-title{font-size:16px;font-weight:700;color:#eaf2ff}.modal-body{padding:12px;overflow:auto}.ioc-card{cursor:pointer}.ioc-card:hover{border-color:#4b5563;background:#0e1624}.hidden{display:none!important}.grep-box{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.grep-input{flex:1;min-width:320px}.grep-status{color:#94a3b8;font-size:12px}.grep-path{font-family:Consolas,monospace;color:#93c5fd}.grep-line{font-family:Consolas,monospace;color:#cbd5e1;white-space:pre-wrap;word-break:break-word}.grep-hit{background:#312e81;color:#fff;padding:0 2px;border-radius:2px}@media(max-width:900px){.two{grid-template-columns:1fr}.graph-viewport{height:65vh}}
.gsearch{display:flex;gap:8px;align-items:center;margin-top:12px;flex-wrap:wrap}.gsearch input{flex:1;min-width:260px;max-width:620px;background:#05070b;color:#e5e7eb;border:1px solid #334155;border-radius:8px;padding:9px 12px;font-size:13px}.gsearch input:focus{outline:none;border-color:#7dd3fc;box-shadow:0 0 0 3px rgba(125,211,252,.15)}.gsearch .btn{padding:7px 10px}.gsearch .gstat{color:#94a3b8;font-size:12px;min-width:72px;white-space:nowrap}.gchips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.gchip{background:#0c2741;color:#7dd3fc;border:1px solid #14405f;border-radius:999px;padding:3px 10px;font-size:12px;cursor:pointer}.gchip:hover{background:#123a56}.gchip b{color:#bae6fd}mark.ghit{background:#fde047;color:#111827;border-radius:2px;padding:0 1px}mark.ghit.gcur{background:#fb923c;color:#111827;outline:2px solid #fdba74}
</style>
</head>
<body>
<div class="header"><h1>CresCent JSON Investigator Report</h1><div class="sub" id="headSub"></div><div class="gsearch"><input id="gsearch" type="search" placeholder="Search everything across all tabs  (  /  focus  &middot;  Enter next  &middot;  Shift+Enter prev  &middot;  Esc clear )" autocomplete="off" spellcheck="false"><button class="btn" onclick="gsNav(-1)" title="Previous match (Shift+Enter)">&#9650;</button><button class="btn" onclick="gsNav(1)" title="Next match (Enter)">&#9660;</button><span class="gstat" id="gstat"></span></div><div class="gchips" id="gchips"></div></div>
<div class="tabs" id="tabs"></div>
<div id="pages"></div>
<script>
const D=__DATA__;
const PAGES=[
  ['summary','Summary + Device',pageSummary],
  ['correlation','Correlation',pageCorrelation],
  ['injection','Injection',pageInjection],
  ['browser','Browser + Plugins',pageBrowserPlugins],
  ['tree','Process Tree',pageTree],
  ['graph','Process Graph + Network',pageGraph],
  ['iocs','IOCs',pageIocs],
  ['timeline','Timeline',pageTimeline],
  ['commands','Shell Commands',pageShellCommands],
  ['files','Popular Files',pagePopularFiles],
  ['tasks','Scheduled Tasks',pageScheduledTasks],
  ['registry','Registry',pageRegistry],
  ['other','Other JSON',pageOther]
];
function pageInjection(el){
  const inj=D.injection||{},findings=(inj.findings||[]),b=((inj.summary||{}).by_confidence)||{};
  let h='<div class="card"><h2>Fileless-Injection Correlation</h2>'+sourceTag('injection',D.sources&&D.sources.injection)
   +'<p class="note">malfind (injected memory) &times; module-list (loader registration). '
   +'HIGH = an injected region that is unregistered/unbacked in the loader lists; MEDIUM = an injected region alone; '
   +'LOW = an unregistered executable region with no malfind hit. Observations, not verdicts &mdash; verify.</p>';
  if(!findings.length){h+='<div class="empty">No injected regions correlated (needs a full run with malfind + the module-list plugin: ldrmodules / proc.Maps).</div></div>';el.innerHTML=h;return;}
  h+='<div class="grid">'
   +'<div class="stat"><div class="n">'+esc(b.HIGH||0)+'</div><div class="l">HIGH confidence</div></div>'
   +'<div class="stat"><div class="n">'+esc(b.MEDIUM||0)+'</div><div class="l">MEDIUM</div></div>'
   +'<div class="stat"><div class="n">'+esc(b.LOW||0)+'</div><div class="l">LOW</div></div></div>';
  h+=makeTable(findings,'injTbl',['confidence','pid','process_name','base_address','protection','header_signature_found','registered_in_module_list','mapped_path','evidence'],3000);
  h+='</div>';el.innerHTML=h;
}
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function norm(s){return String(s??'').toLowerCase()}
function rows(obj){if(!obj)return[];if(Array.isArray(obj))return obj.map(x=>typeof x==='object'&&x!==null?x:{value:x});if(typeof obj==='object'){for(const k of ['rows','Rows','data','Data','items','results','records','values'])if(Array.isArray(obj[k]))return rows(obj[k]);return [obj]}return[{value:obj}]}
function gv(o,...names){if(!o||typeof o!=='object')return'';const keys=Object.keys(o);const lm={};keys.forEach(k=>lm[k.toLowerCase()]=k);for(const n of names){const k=lm[String(n).toLowerCase()];if(k!==undefined&&o[k]!==undefined&&o[k]!==null)return o[k]}for(const n of names){const needle=String(n).toLowerCase();for(const k of keys){if(k.toLowerCase().includes(needle)&&o[k]!==undefined&&o[k]!==null)return o[k]}}return''}
function pidVal(o){return String(gv(o,'PID','Pid','pid','Process ID','OwnerPid','Owner Pid')).trim()}
function ppidVal(o){return String(gv(o,'PPID','Ppid','ppid','InheritedFromUniqueProcessId','Parent PID')).trim()}
function procName(o){return String(gv(o,'ImageFileName','Name','Process','process_name','Image','Owner','COMM','Comm')).trim()}
function columns(rs,max=10){const c={};rs.slice(0,200).forEach(r=>Object.keys(r||{}).forEach(k=>c[k]=(c[k]||0)+1));return Object.entries(c).sort((a,b)=>b[1]-a[1]).slice(0,max).map(x=>x[0])}
function isNoiseRow(r){if(!r||typeof r!=='object')return false;var v=r.raw!==undefined?r.raw:(r.value!==undefined?r.value:null);return typeof v==='string'&&/^\*\*\*\s/.test(v);}
function maskHashRow(r){if(r&&typeof r==='object'&&typeof r.raw==='string'){var m=r.raw.match(/^([^:\s]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32})/);if(m)return {raw:m[1]+':'+m[2]+':'+m[3].slice(0,4)+'\u2026'+m[3].slice(-4)+':'+m[4].slice(0,4)+'\u2026'+m[4].slice(-4)+':::'};}return r;}
function makeTable(rs,id,cols=null,limit=2000){rs=rows(rs).filter(function(r){return !isNoiseRow(r)});cols=cols||columns(rs);if(!rs.length)return'<div class="empty">No JSON rows found.</div>';let h=`<input class="search" placeholder="Search this table..." oninput="filterTable('${id}',this.value)"><div class="tablewrap"><table id="${id}"><thead><tr>`;cols.forEach((c,i)=>h+=`<th onclick="sortTable('${id}',${i})">${esc(c)}</th>`);h+='</tr></thead><tbody>';rs.slice(0,limit).forEach(r=>{h+='<tr>';cols.forEach(c=>{let v=r?.[c];if(v===undefined)v='';if(typeof v==='object')v=JSON.stringify(v);h+=`<td class="wrap" title="${esc(v)}">${esc(v)}</td>`});h+='</tr>'});h+='</tbody></table></div>';if(rs.length>limit)h+=`<div class="note">Showing ${limit} of ${rs.length} rows.</div>`;return h}
function filterTable(id,q){q=norm(q);document.querySelectorAll(`#${id} tbody tr`).forEach(tr=>tr.style.display=norm(tr.textContent).includes(q)?'':'none')}
function sortTable(id,i){const t=document.getElementById(id),tb=t.tBodies[0],rs=[...tb.rows],asc=t.dataset.sort!==String(i)+'a';rs.sort((a,b)=>{let x=a.cells[i]?.textContent||'',y=b.cells[i]?.textContent||'';let nx=parseFloat(x),ny=parseFloat(y);let r=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});return asc?r:-r});rs.forEach(r=>tb.appendChild(r));t.dataset.sort=String(i)+(asc?'a':'d')}
function sourceTag(label,path){return path?`<span class="source">${esc(label)} → ${esc(path)}</span>`:''}
function init(){document.getElementById('headSub').innerHTML=`Generated: ${esc(D.generated)} | Source: <code>${esc(D.output_dir)}</code> | JSON-only; strings/ascii excluded`;const tabs=document.getElementById('tabs'),pages=document.getElementById('pages');PAGES.forEach((p,i)=>{const b=document.createElement('div');b.className='tab'+(i?'':' active');b.textContent=p[1];b.onclick=()=>showPage(p[0]);tabs.appendChild(b);const d=document.createElement('div');d.id='page-'+p[0];d.className='page'+(i?'':' active');pages.appendChild(d);p[2](d)});}
function showPage(id){[...document.querySelectorAll('.tab')].forEach((t,i)=>t.classList.toggle('active',PAGES[i][0]===id));[...document.querySelectorAll('.page')].forEach(p=>p.classList.toggle('active',p.id==='page-'+id));}
function flatObj(o,prefix='',out={}){if(!o||typeof o!=='object'||Array.isArray(o)){out[prefix||'value']=o;return out}for(const [k,v] of Object.entries(o)){const key=prefix?prefix+'.'+k:k;if(v&&typeof v==='object'&&!Array.isArray(v))flatObj(v,key,out);else out[key]=Array.isArray(v)?v.join(', '):v}return out}
function pageSummary(el){const c=D.counts||{},si=D.system_info||{},corr=D.correlation||{};let h='<div class="grid">';for(const [k,v] of Object.entries(c))h+=`<div class="stat"><div class="n">${esc(v)}</div><div class="l">${esc(k)}</div></div>`;h+='</div>';h+='<div class="card"><h2>Device / system_info.json</h2>'+sourceTag('system_info',D.sources?.system_info);const kv=flatObj(si);h+='<div class="json-kv">';Object.entries(kv).slice(0,80).forEach(([k,v])=>{h+=`<div>${esc(k)}</div><div>${esc(v)}</div>`});h+='</div></div>';const sum=corr.summary||{};h+='<div class="card"><h2>Correlation Summary</h2>'+sourceTag('correlation',D.sources?.correlation);if(Object.keys(sum).length){h+='<div class="json-kv">';Object.entries(sum).forEach(([k,v])=>{h+=`<div>${esc(k)}</div><div>${esc(v)}</div>`});h+='</div><p class="note" style="margin-top:10px">Open the <b>Correlation</b> tab for full details.</p>'}else{h+='<p class="note">No correlation data. Run the correlate step first.</p>'}h+='</div>';h+='<div class="card"><h2>Source index</h2>'+makeTable(Object.entries(D.sources||{}).map(([Key,File])=>({Key,File})),'srcTbl',['Key','File'],3000)+'</div>';el.innerHTML=h}
function makeJsonPreview(obj,id){const rs=rows(obj);if(rs.length>1)return makeTable(rs,id,null,600);return `<pre>${esc(JSON.stringify(obj,null,2).slice(0,120000))}</pre>`}
function pageCorrelation(el){
  const corr=D.correlation||{},sum=corr.summary||{},named=D.named||{};
  let h='';
  const smap=[['total_processes','Total Processes'],['network_processes','With Network'],['malfind','Malfind Hits'],['external_connections','External Conns'],['services','Services'],['hashes','Hashes'],['bash_entries','Bash History'],['kernel_modules','Kernel Modules'],['hidden_modules','Hidden Modules']];
  h+='<div class="grid">';smap.forEach(([k,l])=>{if(sum[k]!==undefined)h+=`<div class="stat"><div class="n">${esc(sum[k])}</div><div class="l">${esc(l)}</div></div>`});h+='</div>';
  h+='<p class="note">Cross-referenced observations. Raw command history (bash / cmdscan / consoles) is on the <b>Shell Commands</b> tab; the full connection list is on the <b>Process Graph + Network</b> tab.</p>';
  const shortConns=(arr,n)=>{arr=arr||[];const parts=arr.slice(0,n).map(c=>{c=String(c);return c.length>72?c.slice(0,72)+'…':c});return parts.join(' | ')+(arr.length>n?` … +${arr.length-n} more`:'')};
  const np=corr.network_processes||[];if(np.length){h+=`<div class="card"><h2>Processes with Network Connections <span class="badge">${np.length}</span></h2>`;h+=makeTable(np.map(p=>({PID:p.pid,Name:p.name,PPID:p.ppid,Command:(p.cmdline||'').slice(0,120),Connections:shortConns(p.connections,3),Malfind:p.malfind?'⚠ YES':''})),'corrNetTbl',['PID','Name','PPID','Command','Connections','Malfind'],3000);h+='</div>'}
  let mf=corr.malfind||[];const mfStruct=mf.some(r=>r&&(r.pid||r.address||r.name));if(!mfStruct){const nm=(named.malfind&&named.malfind.rows)||[];if(rows(nm).length)mf=nm;}if(rows(mf).length){h+=`<div class="card"><h2>Malfind Detections <span class="badge" style="background:#3a1212;color:#fca5a5">${rows(mf).length}</span></h2>`;h+=(mfStruct?'':'<p class="note">Vol2 raw output (unparsed lines).</p>')+makeTable(mf,'corrMfTbl',mfStruct?['pid','name','address','protection']:null,2000);h+='</div>'}
  const ip=corr.interest_processes||[];if(ip.length){h+=`<div class="card"><h2>Processes of Interest <span class="badge" style="background:#332a0d;color:#facc15">${ip.length}</span></h2>`;h+=makeTable(ip.map(p=>({PID:p.pid,Name:p.name,PPID:p.ppid,Command:(p.cmdline||'').slice(0,120),Connections:shortConns(p.connections,3),Malfind:p.malfind?'⚠ YES':''})),'corrIpTbl',['PID','Name','PPID','Command','Connections','Malfind'],2000);h+='</div>'}
  const ext=corr.external_connections||[];if(ext.length){h+=`<div class="card"><h2>External Connections <span class="badge">${ext.length}</span></h2>`;h+=makeTable(ext.map(c=>({PID:c.pid,Name:c.name,Connection:c.connection})),'corrExtTbl',['PID','Name','Connection'],3000);h+='</div>'}
  const lsmod=corr.kernel_modules||[];if(lsmod.length){h+=`<div class="card"><h2>Loaded Kernel Modules <span class="badge">${lsmod.length}</span></h2>`;h+=makeTable(lsmod,'corrModTbl',null,2000);h+='</div>'}
  const hmod=corr.hidden_modules||[];if(hmod.length){h+=`<div class="card"><h2>Hidden / Suspicious Modules <span class="badge" style="background:#3a1212;color:#fca5a5">${hmod.length}</span></h2>`;h+=makeTable(hmod,'corrHidTbl',null,1000);h+='</div>'}
  let svcs=corr.services||[];if(!rows(svcs).filter(r=>!isNoiseRow(r)).length){const ns=(named.svcscan&&named.svcscan.rows)||[];if(rows(ns).length)svcs=ns;}if(rows(svcs).filter(r=>!isNoiseRow(r)).length){h+=`<div class="card"><h2>Services <span class="badge">${rows(svcs).filter(r=>!isNoiseRow(r)).length}</span></h2>`;h+=makeTable(svcs,'corrSvcTbl',null,3000);h+='</div>'}
  let hashes=corr.hashes||[];if(!rows(hashes).filter(r=>!isNoiseRow(r)).length){const nh=(named.hashdump&&named.hashdump.rows)||[];if(rows(nh).length)hashes=nh;}hashes=rows(hashes).map(maskHashRow);const hn=hashes.filter(r=>!isNoiseRow(r)).length;if(hn){h+=`<div class="card"><h2>Password Hashes <span class="note">(masked — full values in json/hashdump*.json)</span> <span class="badge">${hn}</span></h2>`;h+=makeTable(hashes,'corrHashTbl',null,2000);h+='</div>'}
  const sb=corr.shellbags||[];if(sb.length){h+=`<div class="card"><h2>Shellbags <span class="badge">${sb.length}</span></h2>`;h+=makeTable(sb,'corrSbTbl',null,2000);h+='</div>'}
  const sc=corr.shimcache||[];if(sc.length){h+=`<div class="card"><h2>Shimcache <span class="badge">${sc.length}</span></h2>`;h+=makeTable(sc,'corrScTbl',null,2000);h+='</div>'}
  el.innerHTML=h||'<div class="empty">No correlation data found. Run the correlate step first.</div>'
}
function pageBrowserPlugins(el){let h='<div class="two"><div class="card plugin-list"><h2>Plugin JSON files inside json/</h2><input class="search" placeholder="Filter plugin names..." oninput="filterPlugins(this.value)"><div id="pluginList">';(D.plugins||[]).forEach((p,i)=>{h+=`<div class="plugin-item ${i?'':'active'}" data-name="${esc(p.name)}" onclick="openPlugin(${i})"><b>${esc(p.name)}</b><br><span class="note">${esc(p.file)} • ${esc(p.row_count)} rows</span></div>`});h+='</div></div><div class="card"><h2 id="pluginTitle">Browser history</h2><div id="pluginBody"></div></div></div>';el.innerHTML=h;openBrowser()}
function openBrowser(){const body=document.getElementById('pluginBody');if(!body)return;document.getElementById('pluginTitle').innerHTML='Browser history '+sourceTag('browser',D.sources?.browser);body.innerHTML=makeJsonPreview(D.browser||{},'browserTbl')}
function openPlugin(i){document.querySelectorAll('.plugin-item').forEach((x,idx)=>x.classList.toggle('active',idx===i));const p=(D.plugins||[])[i];document.getElementById('pluginTitle').innerHTML=esc(p.name)+' '+sourceTag('plugin',p.file);document.getElementById('pluginBody').innerHTML=makeTable(p.rows||[],'pluginRows'+i,null,1500)}
function filterPlugins(q){q=norm(q);document.querySelectorAll('.plugin-item').forEach(x=>x.style.display=norm(x.dataset.name+' '+x.textContent).includes(q)?'':'none')}
function processBundle(){function flatPt(ns){const r=[];(ns||[]).forEach(n=>{r.push(n);flatPt(n.__children||[]).forEach(x=>r.push(x))});return r}const psRaw=rows(D.named?.pslist?.rows);const ps=psRaw.length?psRaw:flatPt(rows(D.named?.pstree?.rows));const cmdRows=rows(D.named?.cmdline?.rows);const cmdMap={};cmdRows.forEach(r=>{const p=pidVal(r);if(p)cmdMap[p]=String(gv(r,'Args','args','CommandLine','Command Line','Cmdline','cmdline'))});rows(D.named?.psaux?.rows).forEach(r=>{const p=pidVal(r);if(p&&!cmdMap[p]){const a=String(gv(r,'Arguments','Args','args','ARGS')||'');if(a)cmdMap[p]=a;}});const netKeys=['netscan','netstat','connscan','connections','sockscan','sockets','sockstat'];const netMap={};const netRows=[];netKeys.forEach(k=>rows(D.named?.[k]?.rows).forEach(r=>{const p=pidVal(r);const item={source:k,source_file:D.named?.[k]?.file||'',pid:p,proto:String(gv(r,'Proto','Protocol','proto','Type')),local:String(gv(r,'LocalAddr','Local Address','LocalAddress','Local','Source Addr','SrcAddr','Source IP')||'')+(gv(r,'LocalPort','Local Port','Source Port','SrcPort')?':'+gv(r,'LocalPort','Local Port','Source Port','SrcPort'):''),remote:String(gv(r,'ForeignAddr','Foreign Address','RemoteAddr','Remote Address','Foreign','Dest Addr','DstAddr','Dest IP')||'')+(gv(r,'ForeignPort','Foreign Port','RemotePort','Remote Port','Dest Port','DstPort')?':'+gv(r,'ForeignPort','Foreign Port','RemotePort','Remote Port','Dest Port','DstPort'):''),state:String(gv(r,'State','state'))};netRows.push(item);if(p)(netMap[p]=netMap[p]||[]).push(item)}));const procs={};ps.forEach(r=>{const p=pidVal(r);if(!p||procs[p])return;procs[p]={pid:p,ppid:ppidVal(r),name:procName(r)||'(unknown)',threads:String(gv(r,'Threads','threads','ThreadCount')),create:String(gv(r,'CreateTime','Create Time','Time')),cmd:cmdMap[p]||'',nets:netMap[p]||[],source_file:D.named?.pslist?.file||'',cmd_source:cmdMap[p]?(D.named?.cmdline?.file||''):''}});const children={},roots=[];Object.values(procs).forEach(p=>{if(p.ppid&&procs[p.ppid]&&p.ppid!==p.pid)(children[p.ppid]=children[p.ppid]||[]).push(p.pid);else roots.push(p.pid)});Object.keys(children).forEach(k=>children[k].sort((a,b)=>(parseInt(a)||0)-(parseInt(b)||0)));roots.sort((a,b)=>(parseInt(a)||0)-(parseInt(b)||0));return{procs,children,roots,netRows}}
function pageTree(el){const B=processBundle();function node(pid,depth=0){const p=B.procs[pid];if(!p)return'';const ch=B.children[pid]||[];let h=`<div class="tree-node ${depth?'':'tree-root'}" data-search="${esc([p.name,p.pid,p.ppid,p.cmd,p.nets.map(n=>n.remote).join(' ')].join(' '))}"><div class="tree-label" onclick="toggleTree(this)"><span class="tree-toggle">${ch.length?'▼':''}</span><span class="tree-pid">${esc(p.pid)}</span><span class="tree-name">${esc(p.name)}</span><span class="pill blue">PPID ${esc(p.ppid||'?')}</span><span class="pill">thr ${esc(p.threads||'?')}</span>${sourceTag('pslist',p.source_file)}</div>`;if(p.cmd)h+=`<div class="tree-cmd">command: ${esc(p.cmd)} ${sourceTag('command',p.cmd_source)}</div>`;if(p.nets.length)h+=`<div class="tree-net">net: ${p.nets.slice(0,4).map(n=>esc(`${n.proto} ${n.local} → ${n.remote} ${n.state}`)).join(' | ')} ${p.nets.map(n=>sourceTag(n.source,n.source_file)).join('')}</div>`;if(ch.length){h+='<div class="tree-children">';ch.forEach(c=>h+=node(c,depth+1));h+='</div>'}return h+'</div>'}let h='<div class="toolbar"><input class="search" id="treeSearch" placeholder="Search PID, process, command, or connection..." oninput="filterTree(this.value)"><button class="btn" onclick="expandTree(true)">Expand all</button><button class="btn" onclick="expandTree(false)">Collapse all</button></div><div class="card"><h2>JSON process tree</h2>'+sourceTag('pslist',D.named?.pslist?.file)+sourceTag('command',D.named?.cmdline?.file);B.roots.forEach(r=>h+=node(r));h+='</div>';el.innerHTML=h}
function toggleTree(label){const c=label.parentElement.querySelector(':scope > .tree-children');const t=label.querySelector('.tree-toggle');if(c){c.classList.toggle('collapsed');t.textContent=c.classList.contains('collapsed')?'▶':'▼'}}
function expandTree(open){document.querySelectorAll('.tree-children').forEach(c=>c.classList.toggle('collapsed',!open));document.querySelectorAll('.tree-toggle').forEach(t=>{if(t.textContent)t.textContent=open?'▼':'▶'})}
function filterTree(q){q=norm(q);document.querySelectorAll('#page-tree .tree-node').forEach(n=>n.style.display=!q||norm(n.dataset.search).includes(q)?'':'none')}
let graphScale=1;
function pageGraph(el){const B=processBundle();let h='<div class="graph-shell"><div class="graph-toolbar toolbar"><input class="search" id="graphSearch" placeholder="Search graph process / PID / command / connection..." oninput="filterGraph(this.value)"><button class="btn" onclick="nextGraphMatch()">Next match</button><button class="btn" onclick="clearGraphSearch()">Clear search</button><span class="graph-hit-count" id="graphHitCount"></span><button class="btn" onclick="zoomGraph(.85)">Zoom out</button><button class="btn" onclick="zoomGraph(1.15)">Zoom in</button><button class="btn" onclick="resetGraph()">Reset</button><button class="btn" onclick="fitGraph()">Fit graph</button><button class="btn" onclick="centerFirstRoot()">Root</button><button class="btn" onclick="showNetOnly()">Only with connections</button><button class="btn" onclick="showAllGraph()">Show all</button><span class="note">Left-click and drag inside the white graph area to pan. Mouse wheel zooms toward your cursor. Use Fit graph to see the whole map.</span></div><div class="graph-viewport" id="graphViewport" tabindex="0" title="Left-drag to pan. Mouse wheel to zoom. + / - / 0 shortcuts work here."><div class="graph-canvas" id="graphCanvas"><svg class="graph-svg" id="graphSvg"></svg><div id="graphNodes"></div></div></div></div><div class="card"><h2>network_map.json</h2>'+sourceTag('network_map',D.sources?.network_map)+makeJsonPreview(D.network_map||{},'networkMapTable')+'</div>';el.innerHTML=h;drawGraph(B);enableGraphNavigation()}
function drawGraph(B){
const procs=B.procs,children=B.children,roots=B.roots;
const pos={},subtreeW={},nodeW=420,baseNodeH=132,hGap=90,vGap=360,rootGap=170;
function estimateHeight(p){
  const cmdLines=Math.max(1, Math.ceil((String(p.cmd||'').length||0)/48));
  const netLines=Math.max(0, Math.min(4, (p.nets||[]).length));
  const srcLines=1 + Math.ceil((String(p.source_file||'').length + String(p.cmd_source||'').length)/70);
  return baseNodeH + (cmdLines*12) + (netLines*14) + (srcLines*8);
}
function calcWidth(pid){
  const ch=children[pid]||[];
  if(!ch.length){subtreeW[pid]=nodeW+hGap; return subtreeW[pid];}
  let total=0;
  ch.forEach((c,idx)=>{ total += calcWidth(c); if(idx<ch.length-1) total += hGap; });
  subtreeW[pid]=Math.max(nodeW+hGap,total);
  return subtreeW[pid];
}
function place(pid,depth,left){
  const width=subtreeW[pid]||calcWidth(pid);
  const ch=children[pid]||[];
  const p=procs[pid];
  const center=left + width/2;
  pos[pid]={x:center-(nodeW/2), y:60+(depth*vGap), h:estimateHeight(p)};
  if(ch.length){
    let cursor=left;
    ch.forEach((c,idx)=>{ place(c,depth+1,cursor); cursor += subtreeW[c] + (idx<ch.length-1 ? hGap : 0); });
  }
}
roots.forEach(r=>calcWidth(r));
let cursor=80;
roots.forEach((r,idx)=>{ place(r,0,cursor); cursor += subtreeW[r] + rootGap; });
function collectDesc(pid, out=[]){ out.push(pid); (children[pid]||[]).forEach(c=>collectDesc(c,out)); return out; }
const descCache={};
function moveSubtree(pid,dx){ (descCache[pid]||(descCache[pid]=collectDesc(pid,[]))).forEach(id=>{ if(pos[id]) pos[id].x += dx; }); }
function overlap(a,b){ return !(a.x+nodeW+hGap <= b.x || b.x+nodeW+hGap <= a.x || a.y+a.h+50 <= b.y || b.y+b.h+50 <= a.y); }
let changed=true, guard=0;
while(changed && guard<12){
  changed=false; guard++;
  const ids=Object.keys(pos).sort((a,b)=> (pos[a].y-pos[b].y) || (pos[a].x-pos[b].x));
  for(let i=0;i<ids.length;i++){
    for(let j=i+1;j<ids.length;j++){
      const ia=ids[i], ib=ids[j], a=pos[ia], b=pos[ib];
      if(Math.abs(a.y-b.y) > vGap-30 && !overlap(a,b)) continue;
      if(overlap(a,b)){
        const push=(a.x+nodeW+hGap)-b.x;
        if(push>0){ moveSubtree(ib, push+25); changed=true; }
      }
    }
  }
}
const svg=document.getElementById('graphSvg'),nodes=document.getElementById('graphNodes'),canvas=document.getElementById('graphCanvas');
let maxX=0,maxY=0,lines='';
Object.values(procs).forEach(p=>{const po=pos[p.pid];if(!po)return;maxX=Math.max(maxX,po.x+nodeW+150);maxY=Math.max(maxY,po.y+po.h+160);(children[p.pid]||[]).forEach(c=>{const co=pos[c];if(co){const sy=po.y+Math.max(42, Math.min(po.h-20, 52)); lines+=`<path d="M ${po.x+24} ${sy} C ${po.x+170} ${sy+90}, ${co.x-105} ${co.y-70}, ${co.x+24} ${co.y+20}" fill="none" stroke="#94a3b8" stroke-width="1.4"/>`;}})});
canvas.style.width=Math.max(2200,maxX)+'px';canvas.style.height=Math.max(1200,maxY)+'px';svg.setAttribute('width',Math.max(2200,maxX));svg.setAttribute('height',Math.max(1200,maxY));svg.innerHTML=lines;
let html='';
Object.values(procs).forEach(p=>{const po=pos[p.pid];if(!po)return;const hasCmd=!!p.cmd,hasNet=p.nets.length>0;const cls=hasCmd&&hasNet?'both':hasNet?'net':hasCmd?'cmd':'';const nets=p.nets.slice(0,4).map(n=>`${n.proto||''} ${n.local||''} → ${n.remote||''} ${n.state||''}`).join('<br>');html+=`<div class="g-node" data-hasnet="${hasNet?'1':'0'}" data-search="${esc([p.name,p.pid,p.ppid,p.cmd,p.nets.map(n=>n.remote).join(' ')].join(' '))}" style="left:${po.x}px;top:${po.y}px;min-height:${po.h}px"><div class="g-main"><div class="hex ${cls}"></div><div><div class="g-title">${esc(p.name).toUpperCase()}</div><div class="g-meta">PID ${esc(p.pid)} • PPID ${esc(p.ppid||'?')}</div>${hasCmd?`<div class="g-cmd">${esc(p.cmd)}</div>`:''}${hasNet?`<div class="g-net">${nets}</div>`:''}<div class="g-source">${esc(p.source_file)}${p.cmd_source?' | '+esc(p.cmd_source):''}${hasNet?' | network JSON':''}</div></div></div></div>`});
nodes.innerHTML=html
}
function setGraphScale(newScale, ev){
  const vp=document.getElementById('graphViewport')||document.querySelector('.graph-viewport');
  const canvas=document.getElementById('graphCanvas');
  if(!vp||!canvas)return;
  const oldScale=graphScale;
  newScale=Math.max(.25,Math.min(2.5,newScale));
  const rect=vp.getBoundingClientRect();
  const cx=ev ? (ev.clientX-rect.left) : vp.clientWidth/2;
  const cy=ev ? (ev.clientY-rect.top) : vp.clientHeight/2;
  const beforeX=(vp.scrollLeft+cx)/oldScale;
  const beforeY=(vp.scrollTop+cy)/oldScale;
  graphScale=newScale;
  canvas.style.transform=`scale(${graphScale})`;
  vp.scrollLeft=Math.max(0,beforeX*graphScale-cx);
  vp.scrollTop=Math.max(0,beforeY*graphScale-cy);
}
function zoomGraph(f){setGraphScale(graphScale*f)}
function resetGraph(){const vp=document.getElementById('graphViewport');setGraphScale(1);if(vp){vp.scrollTo({left:0,top:0,behavior:'smooth'});}}
function fitGraph(){
  const vp=document.getElementById('graphViewport'),canvas=document.getElementById('graphCanvas');
  if(!vp||!canvas)return;
  const w=parseFloat(canvas.style.width||canvas.scrollWidth||1400),h=parseFloat(canvas.style.height||canvas.scrollHeight||800);
  const s=Math.max(.25,Math.min(1.4,Math.min((vp.clientWidth-40)/w,(vp.clientHeight-40)/h)));
  setGraphScale(s);
  vp.scrollTo({left:0,top:0,behavior:'smooth'});
}
function centerFirstRoot(){const n=document.querySelector('.g-node');if(n)focusGraphMatch(n)}
function enableGraphNavigation(){
  const vp=document.getElementById('graphViewport')||document.querySelector('.graph-viewport');
  if(!vp||vp.dataset.panReady==='1')return;
  vp.dataset.panReady='1';
  let dragging=false,startX=0,startY=0,startLeft=0,startTop=0;
  vp.addEventListener('mousedown',e=>{
    if(e.button!==0)return;
    if(e.target.closest('input,button,.modal'))return;
    e.preventDefault();
    dragging=true;
    startX=e.clientX;startY=e.clientY;
    startLeft=vp.scrollLeft;startTop=vp.scrollTop;
    vp.classList.add('panning');
    vp.focus({preventScroll:true});
  });
  window.addEventListener('mousemove',e=>{
    if(!dragging)return;
    e.preventDefault();
    vp.scrollLeft=startLeft-(e.clientX-startX);
    vp.scrollTop=startTop-(e.clientY-startY);
  });
  window.addEventListener('mouseup',()=>{if(dragging){dragging=false;vp.classList.remove('panning');}});
  vp.addEventListener('wheel',e=>{
    e.preventDefault();
    setGraphScale(graphScale*(e.deltaY<0?1.12:.89),e);
  },{passive:false});
  vp.addEventListener('keydown',e=>{
    if(e.key==='+'||e.key==='='){e.preventDefault();zoomGraph(1.15)}
    else if(e.key==='-'||e.key==='_'){e.preventDefault();zoomGraph(.85)}
    else if(e.key==='0'){e.preventDefault();resetGraph()}
    else if(e.key==='Home'){e.preventDefault();centerFirstRoot()}
    else if(e.key==='ArrowLeft'){vp.scrollLeft-=80}
    else if(e.key==='ArrowRight'){vp.scrollLeft+=80}
    else if(e.key==='ArrowUp'){vp.scrollTop-=80}
    else if(e.key==='ArrowDown'){vp.scrollTop+=80}
  });
}
let graphMatches=[];let graphMatchIndex=-1;
function focusGraphMatch(n){if(!n)return;document.querySelectorAll('.g-node').forEach(x=>x.classList.remove('current'));n.classList.add('current');const vp=document.querySelector('.graph-viewport');const x=parseFloat(n.style.left||'0')*graphScale;const y=parseFloat(n.style.top||'0')*graphScale;vp.scrollTo({left:Math.max(0,x-vp.clientWidth/2+125),top:Math.max(0,y-vp.clientHeight/2+60),behavior:'smooth'});}
function filterGraph(q){q=norm(q);const nodes=[...document.querySelectorAll('.g-node')];graphMatches=[];graphMatchIndex=-1;nodes.forEach(n=>{const ok=!q||norm(n.dataset.search).includes(q);n.classList.toggle('dim',!!q&&!ok);n.classList.toggle('match',!!q&&ok);n.classList.remove('current');if(q&&ok)graphMatches.push(n)});const c=document.getElementById('graphHitCount');if(c)c.textContent=q?(graphMatches.length+' match'+(graphMatches.length===1?'':'es')+' — non-matches are dimmed, not hidden'):'';if(graphMatches.length){graphMatchIndex=0;focusGraphMatch(graphMatches[0]);}}
function nextGraphMatch(){if(!graphMatches.length)return;graphMatchIndex=(graphMatchIndex+1)%graphMatches.length;focusGraphMatch(graphMatches[graphMatchIndex]);const c=document.getElementById('graphHitCount');if(c)c.textContent=graphMatches.length+' matches — viewing '+(graphMatchIndex+1)+'/'+graphMatches.length;}
function clearGraphSearch(){const s=document.getElementById('graphSearch');if(s)s.value='';graphMatches=[];graphMatchIndex=-1;document.querySelectorAll('.g-node').forEach(n=>n.classList.remove('dim','match','current','hidden'));const c=document.getElementById('graphHitCount');if(c)c.textContent='';}
function showNetOnly(){clearGraphSearch();document.querySelectorAll('.g-node').forEach(n=>n.classList.toggle('hidden',n.dataset.hasnet!=='1'))}
function showAllGraph(){clearGraphSearch();document.querySelectorAll('.g-node').forEach(n=>n.classList.remove('hidden'))}
function pageIocs(el){const iocs=D.iocs||{};const keys=Object.keys(iocs).sort();if(!keys.length){el.innerHTML='<div class="empty">No IOC JSON files found under iocs/json/ or iocs/ioc_results.json.</div>';return}let h='<input class="search" placeholder="Search IOC tables..." oninput="filterIocCards(this.value)"><p class="note">Click any IOC card to open the full embedded table in a large viewer.</p><div class="mini-grid">';keys.forEach((k,i)=>{const item=iocs[k];h+=`<div class="card ioc-card" data-ioc="${esc(k)} ${esc(item.file)}" onclick="openIocFull(${i})"><h3>${esc(k)} <span class="badge">${esc(item.row_count)}</span></h3>${sourceTag('source',item.file)}<div class="note">Preview below. Click to view the whole embedded table.</div>${makeTable(item.rows||[], 'iocTbl'+i, null, 80)}</div>`});h+='</div><div id="iocModal" class="modal hidden" onclick="closeIocModal(event)"><div class="modal-box" onclick="event.stopPropagation()"><div class="modal-head"><div class="modal-title" id="iocModalTitle">IOC table</div><button class="btn" onclick="closeIocModal()">Close</button></div><div class="modal-body" id="iocModalBody"></div></div></div>';el.innerHTML=h}
function openIocFull(i){const keys=Object.keys(D.iocs||{}).sort();const k=keys[i];const item=(D.iocs||{})[k];if(!item)return;const m=document.getElementById('iocModal'),title=document.getElementById('iocModalTitle'),body=document.getElementById('iocModalBody');title.innerHTML=esc(k)+' <span class="badge">'+esc(item.row_count)+'</span> '+sourceTag('source',item.file);body.innerHTML=makeTable(item.rows||[], 'iocFullTbl'+i, null, 999999);m.classList.remove('hidden');const search=body.querySelector('.search');if(search)search.focus();}
function closeIocModal(ev){if(ev&&ev.target&&ev.target.id!=='iocModal')return;const m=document.getElementById('iocModal');if(m)m.classList.add('hidden')}
function filterIocCards(q){q=norm(q);document.querySelectorAll('.ioc-card').forEach(c=>c.style.display=norm(c.textContent+' '+c.dataset.ioc).includes(q)?'':'none')}
function pageTimeline(el){el.innerHTML='<div class="card"><h2>timeline.json</h2>'+sourceTag('timeline',D.sources?.timeline)+makeJsonPreview(D.timeline||[], 'timelineTbl')+'</div>'}

function pageShellCommands(el){
  const named=D.named||{};
  let h='<div class="card"><h2>Shell Commands &amp; Command History</h2>';
  h+='<p class="note">Bash history (Linux/macOS), Windows command-line args, cmdscan/consoles output, and process arguments (psaux). Raw observations only.</p></div>';

  const sections=[
    {key:'bash',       label:'Bash History (Linux/macOS)',    cols:['PID','Process','Command','History','CommandHistory','Hist'],  src:'bash'},
    {key:'cmdline',    label:'Process Commands (Args)',        cols:['PID','Process','ImageFileName','Args','Arguments','CommandLine','CmdLine'], src:'command'},
    {key:'cmdscan',    label:'Windows CmdScan (console cmds)', cols:['PID','Process','CommandHistory','Command','CommandHistoryProcess'], src:'cmdscan'},
    {key:'consoles',   label:'Windows Consoles Output',       cols:['PID','Process','CommandHistory','Output','Command'], src:'consoles'},
    {key:'psaux',      label:'Process Arguments (Linux/macOS)', cols:['PID','PPID','Name','Process','Arguments','Comm','Args'], src:'psaux'},
  ];

  sections.forEach((s,i)=>{
    const p=named[s.key];
    if(!p||!p.row_count){
      h+=`<div class="card"><h3>${esc(s.label)}</h3><div class="empty">No data (plugin not present or produced no output).</div></div>`;
      return;
    }
    h+=`<div class="card"><h3>${esc(s.label)} <span class="badge">${esc(p.row_count)}</span></h3>`;
    h+=sourceTag(s.src,p.file);
    const rs=rows(p.rows||[]);
    // Pick best columns: prefer the defined cols but only those actually present
    const present=new Set(Object.keys(Object.assign({},...rs.slice(0,20).filter(r=>r))));
    const useCols=s.cols.filter(c=>present.has(c));
    const finalCols=useCols.length?useCols:columns(rs,8);
    h+=makeTable(rs,'shellTbl'+i,finalCols,3000);
    h+='</div>';
  });
  el.innerHTML=h;
}

function pagePopularFiles(el){
  const pf=D.popular_files||{};
  const src=D.sources?.popular_files||'';
  let h='<div class="card"><h2>Popular Locations File Scan</h2>';
  h+=sourceTag('popular_files',src);
  if(!pf||!Object.keys(pf).length){h+='<div class="empty">No popular_files.json found. Run Popular Files scan ([19] in menu) after extraction.</div></div>';el.innerHTML=h;return;}
  const os=pf.os_heuristic||'?';
  const total=pf.total_files_scanned||0;
  const sus=(pf.suspicious_paths||[]).length;
  const execs=(pf.executables_in_user_dirs||[]).length;
  h+=`<div class="grid">`;
  h+=`<div class="stat"><div class="n">${esc(total)}</div><div class="l">Files Scanned</div></div>`;
  h+=`<div class="stat"><div class="n">${esc(sus)}</div><div class="l">Suspicious Paths</div></div>`;
  h+=`<div class="stat"><div class="n">${esc(execs)}</div><div class="l">Execs in User Dirs</div></div>`;
  h+=`<div class="stat"><div class="n">${esc(os.toUpperCase())}</div><div class="l">OS Detected</div></div>`;
  h+='</div></div>';

  // Bucket summary
  const buckets=pf.bucket_summary||{};
  const bkeys=Object.keys(buckets).sort((a,b)=>(buckets[b].count||0)-(buckets[a].count||0));
  if(bkeys.length){
    h+='<div class="card"><h2>Files by Location</h2>';
    h+='<p class="note">Click a row to expand filenames. Default system files (desktop.ini, $NTFS metadata, etc.) are filtered out.</p>';
    h+='<div class="tablewrap"><table id="pfBucketTbl"><thead><tr><th>Location</th><th>Total</th><th>Filtered</th><th>File Names</th><th>Top Extensions</th></tr></thead><tbody>';
    bkeys.forEach((k,i)=>{
      const b=buckets[k];
      const clean=b.clean_count||0;
      const names=(b.top_filenames||[]);
      const extStr=Object.entries(b.top_extensions||{}).slice(0,5).map(([e,c])=>`${esc(e)}:${c}`).join('  ');
      const rowId='pfRow'+i;
      const namePreview=names.slice(0,5).map(n=>`<span class="pill">${esc(n)}</span>`).join('');
      const nameRest=names.length>5?`<span id="${rowId}rest" style="display:none">${names.slice(5).map(n=>`<span class="pill">${esc(n)}</span>`).join('')}</span><span class="pill blue" style="cursor:pointer" onclick="pfToggle('${rowId}')">+${names.length-5} more</span>`:'';
      h+=`<tr><td><b>${esc(k)}</b></td><td>${b.count}</td><td>${clean}</td><td>${namePreview}${nameRest}</td><td><code style="font-size:11px">${extStr}</code></td></tr>`;
    });
    h+='</tbody></table></div>';
    h+='</div>';
  }

  // Suspicious paths
  if(sus>0){
    h+='<div class="card"><h2>Suspicious File Locations</h2>';
    h+=makeTable(pf.suspicious_paths||[],'pfSusTbl',['reason','path','ext_class','source'],2000);
    h+='</div>';
  }

  // Executables in user dirs
  if(execs>0){
    h+='<div class="card"><h2>Executables in User Directories</h2>';
    h+=makeTable(pf.executables_in_user_dirs||[],'pfExecTbl',['path','filename','ext_class','source'],2000);
    h+='</div>';
  }
  el.innerHTML=h;
}

function pageScheduledTasks(el){
  const st=D.scheduled_tasks||{};
  const src=D.sources?.scheduled_tasks||'';
  let h='<div class="card"><h2>Scheduled Tasks / Cron / Launchd</h2>';
  h+=sourceTag('scheduled_tasks',src);
  if(!st||!Object.keys(st).length){h+='<div class="empty">No scheduled_tasks.json found. Run Scheduled Tasks scan ([17] in menu) after extraction.</div></div>';el.innerHTML=h;return;}
  const total=st.total_findings||0;
  const reg=(st.registry_tasks||[]).length;
  const files=(st.file_tasks||[]).length;
  const procs=(st.task_processes||[]).length;
  const sus=(st.suspicious_commands||[]).length;
  const cron=(st.linux_cron||[]).length;
  const launchd=(st.mac_launchd||[]).length;
  h+=`<div class="grid">`;
  h+=`<div class="stat"><div class="n">${total}</div><div class="l">Total Findings</div></div>`;
  h+=`<div class="stat"><div class="n">${reg}</div><div class="l">Registry Tasks (Win)</div></div>`;
  h+=`<div class="stat"><div class="n">${cron}</div><div class="l">Cron Evidence (Lin)</div></div>`;
  h+=`<div class="stat"><div class="n">${launchd}</div><div class="l">Launchd Evidence (Mac)</div></div>`;
  h+='</div></div>';

  const sections=[
    ['Windows Registry Tasks', st.registry_tasks||[], ['source','key','value','matched_path','name','count','last','note']],
    ['Task Files (Win)', st.file_tasks||[], ['os','source','path','type','pid','process','offset']],
    ['Scheduler Processes (All OS)', st.task_processes||[], ['os','pid','ppid','name','display','state','cmdline','binary']],
    ['Suspicious Task Commands', st.suspicious_commands||[], ['pid','cmdline','matched_pattern']],
    ['Linux Cron / AT Evidence', st.linux_cron||[], ['source','pid','command','variable','value','matched_pattern']],
    ['macOS Launchd Evidence', st.mac_launchd||[], ['source','os','pid','process','path','type','command','variable','value','matched_pattern']],
  ];
  sections.forEach(([title,data,cols],i)=>{
    if(!data||!data.length){
      h+=`<div class="card"><h2>${esc(title)} <span class="badge">0</span></h2><div class="empty">None found.</div></div>`;
      return;
    }
    h+=`<div class="card"><h2>${esc(title)} <span class="badge">${data.length}</span></h2>`;
    h+=makeTable(data,'stTbl'+i,cols,1500);
    h+='</div>';
  });
  el.innerHTML=h;
}

function pageRegistry(el){
  const reg=D.registry||{};
  const src=D.sources?.registry||'';
  let h='<div class="card"><h2>Registry Explorer</h2>';
  h+=sourceTag('registry_report',src);
  if(!reg||!Object.keys(reg).length){h+='<div class="empty">No registry_report.json found. Run Registry ([10] in menu).</div></div>';el.innerHTML=h;return;}

  // Summary stats
  const summ=reg.summary||{};
  h+='<div class="grid">';
  for(const [k,v] of Object.entries(summ))h+=`<div class="stat"><div class="n">${esc(v)}</div><div class="l">${esc(k)}</div></div>`;
  h+='</div></div>';

  // Persistence indicators
  const pers=reg.persistence||[];
  if(pers.length){
    h+=`<div class="card"><h2>Persistence Indicators <span class="badge">${pers.length}</span></h2>`;
    h+=makeTable(pers,'regPersTbl',['key','hive','key_path','value_name','type','data','last_write'],2000);
    h+='</div>';
  }

  // Key tree
  const tree=reg.key_tree||{};
  const hives=Object.keys(tree);
  if(hives.length){
    h+='<div class="card"><h2>Registry Key Tree (printkey)</h2>';
    h+='<p class="note">Hive → Key Path → Value Name [Type] = Data  (MemProcFS-style hierarchy)</p>';
    hives.forEach((hive,hi)=>{
      h+=`<details style="margin:8px 0"><summary style="cursor:pointer;font-weight:700;color:#7dd3fc">${esc(hive)}</summary>`;
      const keys=tree[hive]||{};
      const kArr=Object.entries(keys).sort((a,b)=>a[0].localeCompare(b[0]));
      h+='<div style="font-family:Consolas,monospace;font-size:12px;padding:8px 0">';
      kArr.slice(0,300).forEach(([kp,vals])=>{
        h+=`<div style="color:#a5b4fc;margin:4px 0 2px 8px">├─ ${esc(kp)}</div>`;
        (vals||[]).forEach(v=>{
          const lw=v.last_write?` <span style="color:#64748b">← ${esc(v.last_write)}</span>`:'';
          h+=`<div style="margin:1px 0 1px 32px;color:#cbd5e1">│ └─ <b>${esc(v.value_name)}</b> <span style="color:#86efac">[${esc(v.type)}]</span> = <span style="color:#fef08a">${esc(String(v.data||'').slice(0,200))}</span>${lw}</div>`;
        });
      });
      if(kArr.length>300)h+=`<div style="color:#64748b;margin:4px 8px">... and ${kArr.length-300} more keys</div>`;
      h+='</div></details>';
    });
    h+='</div>';
  }

  // Services
  const svcs=reg.services||[];
  if(svcs.length){
    h+=`<div class="card"><h2>Windows Services <span class="badge">${svcs.length}</span></h2>`;
    h+=makeTable(svcs,'regSvcTbl',['name','display','state','start','type','pid','binary'],2000);
    h+='</div>';
  }

  // Hives
  if((reg.hives||[]).length){
    h+=`<div class="card"><h2>Registry Hives <span class="badge">${reg.hives.length}</span></h2>`;
    h+=makeTable(reg.hives,'regHiveTbl',null,500);
    h+='</div>';
  }

  // UserAssist
  const ua=reg.userassist||[];
  if(ua.length){
    h+=`<div class="card"><h2>UserAssist (Execution History) <span class="badge">${ua.length}</span></h2>`;
    h+=makeTable(ua,'regUaTbl',null,1500);
    h+='</div>';
  }

  // ShellBags
  const sb=reg.shellbags||[];
  if(sb.length){
    h+=`<div class="card"><h2>ShellBags (Folder Access) <span class="badge">${sb.length}</span></h2>`;
    h+=makeTable(sb,'regSbTbl',null,1500);
    h+='</div>';
  }

  // ShimCache
  const sc=reg.shimcache||[];
  if(sc.length){
    h+=`<div class="card"><h2>ShimCache (App History) <span class="badge">${sc.length}</span></h2>`;
    h+=makeTable(sc,'regScTbl',null,1500);
    h+='</div>';
  }
  el.innerHTML=h;
}

function pageOther(el){let h='<div class="card"><h2>Other JSON artifacts</h2><p class="note">Root JSON artifacts not already displayed, plus EVTX and comms. Registry is on its own tab. Strings/ascii files are not included.</p></div>';const blocks=[];for(const [k,v] of Object.entries(D.other_json||{}))blocks.push([k,v.file,v.rows||v.raw]);for(const k of ['evtx','comms'])if(D.root_json?.[k])blocks.push([k,D.sources?.[k],D.root_json[k]]);if(!blocks.length)h+='<div class="empty">No additional JSON artifacts found.</div>';blocks.forEach((b,i)=>{h+=`<div class="card"><h2>${esc(b[0])}</h2>${sourceTag('source',b[1])}${makeJsonPreview(b[2], 'otherTbl'+i)}</div>`});el.innerHTML=h}
function pfToggle(id){const el=document.getElementById(id+'rest');if(el){el.style.display=el.style.display==='none'?'':'none';}}
/* ---- Global cross-tab search (highlight + jump; all pages render up-front) ---- */
var gsMatches=[],gsIdx=-1,gsTimer=null,gsCapped=false;
function gsClear(){document.querySelectorAll('mark.ghit').forEach(function(m){var p=m.parentNode;if(p){p.replaceChild(document.createTextNode(m.textContent),m);p.normalize();}});gsMatches=[];gsIdx=-1;gsCapped=false;var gc=document.getElementById('gchips');if(gc)gc.innerHTML='';var st=document.getElementById('gstat');if(st)st.textContent='';}
function gsRun(q){gsClear();q=String(q||'').trim();if(q.length<2)return;var ql=q.toLowerCase(),cap=3000,perPage={};for(var pi=0;pi<PAGES.length&&!gsCapped;pi++){var pg=PAGES[pi],cont=document.getElementById('page-'+pg[0]);if(!cont)continue;var walker=document.createTreeWalker(cont,NodeFilter.SHOW_TEXT,{acceptNode:function(n){if(!n.nodeValue||n.nodeValue.toLowerCase().indexOf(ql)<0)return NodeFilter.FILTER_REJECT;var p=n.parentNode;if(!p)return NodeFilter.FILTER_REJECT;var tag=p.nodeName;if(tag==='SCRIPT'||tag==='STYLE'||tag==='MARK')return NodeFilter.FILTER_REJECT;if(p.closest&&p.closest('.graph-canvas'))return NodeFilter.FILTER_REJECT;return NodeFilter.FILTER_ACCEPT;}}),nodes=[],n;while(n=walker.nextNode())nodes.push(n);for(var ni=0;ni<nodes.length&&!gsCapped;ni++){var node=nodes[ni],txt=node.nodeValue,low=txt.toLowerCase(),idx=0,pos,frag=document.createDocumentFragment(),any=false;while((pos=low.indexOf(ql,idx))>=0){if(pos>idx)frag.appendChild(document.createTextNode(txt.slice(idx,pos)));var mk=document.createElement('mark');mk.className='ghit';mk.textContent=txt.slice(pos,pos+q.length);frag.appendChild(mk);gsMatches.push(mk);perPage[pg[0]]=(perPage[pg[0]]||0)+1;any=true;idx=pos+q.length;if(gsMatches.length>=cap){gsCapped=true;break;}}if(any){if(idx<txt.length)frag.appendChild(document.createTextNode(txt.slice(idx)));node.parentNode.replaceChild(frag,node);}}}var gc=document.getElementById('gchips');if(gc){var ch='';PAGES.forEach(function(pg){var c=perPage[pg[0]];if(c)ch+='<span class="gchip" onclick="gsGoto(\''+pg[0]+'\')">'+esc(pg[1])+' <b>'+c+'</b></span>';});gc.innerHTML=ch;}if(gsMatches.length){gsFocus(0);}else{var st=document.getElementById('gstat');if(st)st.textContent='no matches';}}
function gsFocus(i){if(!gsMatches.length)return;gsMatches.forEach(function(m){m.classList.remove('gcur');});gsIdx=((i%gsMatches.length)+gsMatches.length)%gsMatches.length;var m=gsMatches[gsIdx];m.classList.add('gcur');var pg=m.closest?m.closest('.page'):null;if(pg&&!pg.classList.contains('active'))showPage(pg.id.replace('page-',''));if(m.scrollIntoView)m.scrollIntoView({block:'center',inline:'center'});var st=document.getElementById('gstat');if(st)st.textContent=(gsIdx+1)+' / '+gsMatches.length+(gsCapped?'+':'');}
function gsNav(d){if(gsMatches.length)gsFocus(gsIdx+d);}
function gsGoto(id){for(var i=0;i<gsMatches.length;i++){var p=gsMatches[i].closest?gsMatches[i].closest('.page'):null;if(p&&p.id==='page-'+id){gsFocus(i);return;}}}
function initGlobalSearch(){var box=document.getElementById('gsearch');if(!box)return;box.addEventListener('input',function(){clearTimeout(gsTimer);gsTimer=setTimeout(function(){gsRun(box.value);},250);});box.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();if(!gsMatches.length)gsRun(box.value);else gsNav(e.shiftKey?-1:1);}else if(e.key==='Escape'){box.value='';gsClear();box.blur();}});document.addEventListener('keydown',function(e){var t=e.target,tag=t&&t.nodeName,typing=tag==='INPUT'||tag==='TEXTAREA'||(t&&t.isContentEditable);if((e.key==='/'||((e.ctrlKey||e.metaKey)&&(e.key==='k'||e.key==='K')))&&!typing){e.preventDefault();box.focus();box.select();}});}
init();
initGlobalSearch();
</script>
</body>
</html>
'''

# ------------------------------------------------------------------
# Direct command-line runner with visible error handling
# ------------------------------------------------------------------

def _build_cli_logger(debug_log: Path, verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("crescent_html_report")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s")

    fh = logging.FileHandler(debug_log, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(sh)
    return logger


def _print_preflight(output_dir: Path) -> None:
    print(f"[*] Output directory : {output_dir}")
    print(f"[*] Exists           : {output_dir.exists()}")
    print(f"[*] Is directory     : {output_dir.is_dir()}")
    print(f"[*] json/ exists     : {(output_dir / 'json').is_dir()}")
    print(f"[*] iocs/json exists : {(output_dir / 'iocs' / 'json').is_dir()}")



def _grep_search(root: Path, query: str, max_results: int = 5000, max_line_chars: int = 1200) -> Dict[str, Any]:
    """Case-insensitive recursive grep implemented in Python.

    Ignores generated HTML reports (*.html) so the report does not search itself.
    """
    q = query.lower()
    results: List[Dict[str, Any]] = []
    files_scanned = 0
    files_skipped = 0
    files_with_matches = set()
    if not q:
        return {"query": query, "matches": 0, "files_scanned": 0, "files_skipped": 0, "files_with_matches": 0, "results": []}

    ignored_dirs = {"__pycache__", ".git", ".cache"}
    for p in root.rglob("*"):
        try:
            if p.is_dir():
                continue
            if any(part in ignored_dirs for part in p.parts):
                files_skipped += 1
                continue
            name = p.name.lower()
            # Do not search generated reports or browser output. User explicitly asked to ignore HTML report.
            if name.endswith(".html") or name in {"html_report_debug.log"}:
                files_skipped += 1
                continue
            if not p.is_file():
                files_skipped += 1
                continue
            # Skip obvious binary dumps by sampling for NUL bytes. Text artifacts and JSON still pass.
            try:
                sample = p.open("rb").read(4096)
                if b"\x00" in sample:
                    files_skipped += 1
                    continue
            except Exception:
                files_skipped += 1
                continue
            files_scanned += 1
            rel = str(p.relative_to(root))
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    if q in line.lower():
                        files_with_matches.add(rel)
                        clean = line.rstrip("\r\n")
                        if len(clean) > max_line_chars:
                            clean = clean[:max_line_chars] + " ...[truncated]"
                        results.append({"file": rel, "line": lineno, "text": clean})
                        if len(results) >= max_results:
                            return {
                                "query": query,
                                "matches": len(results),
                                "files_scanned": files_scanned,
                                "files_skipped": files_skipped,
                                "files_with_matches": len(files_with_matches),
                                "truncated": True,
                                "results": results,
                            }
        except Exception:
            files_skipped += 1
            continue
    return {
        "query": query,
        "matches": len(results),
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "files_with_matches": len(files_with_matches),
        "truncated": False,
        "results": results,
    }


def _serve_grep(root: Path, port: int, max_results: int) -> int:
    root = root.resolve()

    class GrepHandler(BaseHTTPRequestHandler):
        def _json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:
            self._json(200, {"ok": True})

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/ping":
                self._json(200, {"ok": True, "root": str(root)})
                return
            if parsed.path != "/api/grep":
                self._json(404, {"error": "not found"})
                return
            qs = parse_qs(parsed.query)
            q = (qs.get("q") or [""])[0]
            if not q.strip():
                self._json(400, {"error": "missing q parameter"})
                return
            payload = _grep_search(root, q, max_results=max_results)
            self._json(200, payload)

        def log_message(self, fmt: str, *args: Any) -> None:
            print("[grep-server] " + (fmt % args), flush=True)

    server = None
    bind_err = None
    for candidate in range(port, port + 10):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", candidate), GrepHandler)
            if candidate != port:
                print(f"[!] Port {port} busy, falling back to {candidate}")
            port = candidate
            break
        except OSError as e:
            bind_err = e
            continue
    if server is None:
        print(f"[x] Could not bind any port in {port}..{port + 9}: {bind_err}")
        return 1
    print(f"[+] Grep backend running: http://127.0.0.1:{port}")
    print(f"[+] Grep root           : {root}")
    print("[+] Grep backend started. Press Ctrl+C here to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Grep backend stopped")
    finally:
        server.server_close()
    return 0

def cli(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="RUNME DEBUG: Generate CresCent report.html from a CresCent output directory, with visible debug errors."
    )
    parser.add_argument("output_dir", nargs="?", help="CresCent output directory, for example /home/kali/Desktop/DESKTOP-...")
    parser.add_argument("--debug-log", help="Path to write debug log. Default: <output_dir>/html_report_debug.log")
    parser.add_argument("--verbose", action="store_true", help="Print verbose stage messages")
    parser.add_argument("--max-embed-rows", type=int, default=1500,
                        help="Max rows embedded per JSON table/list in report.html. Default: 1500")
    parser.add_argument("--embed-all-json", action="store_true",
                        help="DANGER: embed all loaded JSON data into report.html. Disables row/string/key limits and includes raw JSON blobs. May freeze the browser/VM.")
    parser.add_argument("--max-string-chars", type=int, default=600,
                        help="Max characters per embedded string value. Default: 600")
    parser.add_argument("--serve-grep", action="store_true", help="After creating report.html, start a local grep backend")
    parser.add_argument("--grep-port", type=int, default=8765, help="Local grep backend port. Default: 8765")
    parser.add_argument("--grep-max-results", type=int, default=5000, help="Maximum grep matches returned to the browser. Default: 5000")
    args = parser.parse_args(argv)

    if not args.output_dir:
        parser.print_help()
        print("\n[!] Missing output_dir. Example:")
        print("    python html_report_graph_grep_alljson_v6.py /home/kali/Desktop/DESKTOP-72F9L8O-20260519-234552/ --serve-grep")
        return 2

    output_dir = Path(args.output_dir).expanduser().resolve()
    debug_log = Path(args.debug_log).expanduser().resolve() if args.debug_log else output_dir / "html_report_debug.log"
    debug_log.parent.mkdir(parents=True, exist_ok=True)
    logger = _build_cli_logger(debug_log, args.verbose)

    print("[+] CresCent HTML report generator starting")
    _print_preflight(output_dir)
    print(f"[*] Debug log        : {debug_log}")

    gen = HTMLReportGenerator(logger)
    gen.EMBED_ALL_JSON = bool(args.embed_all_json)
    if gen.EMBED_ALL_JSON:
        # These are not used in all-json mode, but set them high for clarity in logs/debugging.
        gen.MAX_EMBED_ROWS = 10**12
        gen.MAX_EMBED_STRING_CHARS = 10**12
        gen.MAX_EMBED_DICT_KEYS = 10**12
        print("[!] --embed-all-json enabled: row/string/key limits are disabled", flush=True)
        print("[*] Encoding IOC categories remain excluded from the HTML report", flush=True)
    else:
        gen.MAX_EMBED_ROWS = max(50, args.max_embed_rows)
        gen.MAX_EMBED_STRING_CHARS = max(80, args.max_string_chars)
    gen.GREP_PORT = args.grep_port
    try:
        report = gen.generate(output_dir)
        print(f"[+] Report created   : {report}")
        if gen.errors:
            print(f"[!] Recovered errors : {len(gen.errors)}")
            print("    Some JSON files failed to load but the report was still created.")
            print("    See debug log for exact file/stage details.")
            for e in gen.errors[:10]:
                print(f"    - stage={e['stage']} file={e['file']} error={e['error']}")
            if len(gen.errors) > 10:
                print(f"    ... {len(gen.errors) - 10} more errors in log")
        else:
            print("[+] No JSON loading errors detected")
        if args.serve_grep:
            return _serve_grep(output_dir, args.grep_port, max(1, args.grep_max_results))
        else:
            print("[*] Report created without an embedded directory grep page")
        return 0
    except Exception as e:
        print("\n[!] HTML report generation FAILED")
        print(f"[!] Stage : {gen.stage}")
        print(f"[!] Error : {type(e).__name__}: {e}")
        print(f"[!] Log   : {debug_log}")
        print("\nTraceback:")
        traceback.print_exc()
        logger.error("Fatal failure at stage=%s: %s: %s", gen.stage, type(e).__name__, e)
        logger.debug("Fatal traceback:\n%s", traceback.format_exc())
        return 1


if __name__ == "__main__":
    # Loud entry marker: if you do not see this line, you are not running this patched file.
    print(f"[ENTRY] executing {Path(__file__).resolve()}", flush=True)
    raise SystemExit(cli())
