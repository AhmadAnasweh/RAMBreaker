"""Per-plugin retry (RAMBreaker v2.3).

Reads a finished (or stopped) case folder and works out, for every plugin of
that run, whether it finished, failed, timed out, was skipped because a plugin
it depends on failed, or never ran. The GUI uses this to put a retry button
next to each plugin that needs one; the `retry` CLI command re-runs the chosen
plugins and then rebuilds every plugin-derived analysis step and the report.

Everything here reads only the case folder (json/, SUMMARY.txt); nothing
touches the memory image.
"""

import importlib.util
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# Failure markers in a JSON file left by an older run (same list as the extractor's
# resume check: such a file is not a result).
_BAD_MARKERS = ("unsatisfied requirement", "traceback (most recent call last)",
                "volatility.framework.exceptions",
                "a translation layer requirement was not fulfilled",
                "a symbol table requirement was not fulfilled", "exception: ")

# Analysis steps that run after the plugins and the plugin outputs each one reads
# (substrings of the json file name, as the steps' load_json_by_pattern calls use).
# The HTML report reads every plugin; it is always rebuilt.
STEPS: List[Dict[str, Any]] = [
    {"label": "System information", "keys": ("windows_info_", "envars", "getsids", "hashdump", "pslist")},
    {"label": "Process tree", "keys": ("pslist", "pstree", "psscan", "psaux", "cmdline")},
    {"label": "Network map", "keys": ("netscan", "netstat", "sockstat", "lsof", "pslist", "connscan",
                                      "connections", "sockets", "sockscan")},
    {"label": "Suspicious-process analysis", "keys": ("pslist", "pstree", "psscan", "psaux", "cmdline",
                                                     "windows_info_")},
    {"label": "Command-line analysis + MITRE ATT&CK", "keys": ("cmdline", "cmdscan", "consoles", "malfind",
                                                              "pslist", "pstree", "psaux", "svcscan", "bash")},
    {"label": "Correlation", "keys": ("cmdline", "cmdscan", "connections", "connscan", "consoles", "hashdump",
                                      "malfind", "netscan", "netstat", "pslist", "psscan", "pstree", "psaux",
                                      "shellbags", "shimcache", "sockets", "sockscan", "svcscan", "sockstat",
                                      "lsof", "bash")},
    {"label": "Fileless-injection correlation", "keys": ("malfind", "dlllist", "ldrmodules", "proc_maps",
                                                        "library_list", "elfs")},
    {"label": "Popular files", "keys": ("filescan", "mftscan", "enumerate_files", "lsof", "pagecache")},
    {"label": "Scheduled tasks", "keys": ("bash", "cmdline", "cmdscan", "consoles", "enumerate_files", "envars",
                                          "filescan", "lsof", "printkey", "psaux", "pslist", "pstree",
                                          "svcscan", "userassist")},
    {"label": "Registry analysis", "keys": ("hivelist", "hivescan", "printkey", "shellbags", "shimcache",
                                            "svcscan", "userassist"), "os": "windows"},
    {"label": "Timeline", "keys": ("cmdline", "lsof", "mftscan", "pagecache", "psaux", "pslist", "shimcache",
                                   "sockstat", "svcscan", "userassist", "netscan", "netstat")},
    {"label": "Sigma rules", "keys": ("pslist", "pstree", "cmdline", "netscan", "netstat", "printkey",
                                      "dlllist", "psaux", "bash", "sockstat")},
]

# Steps that also read plugin outputs but are NOT redone by a retry (slow, or
# they need the image again); the confirm dialog names them.
NOT_REDONE = ("strings / IOC / e-mail / browser scan (does not use plugin output)",
              "your IOC-list check", "EVTX file dump (Full DFIR)", "threat intel")

NEEDS_RETRY = ("failed", "timeout", "skipped", "not run")
LABEL = {"done": "done", "empty": "done (no rows)", "failed": "failed", "timeout": "timed out",
         "skipped": "skipped (dependency)", "not run": "not run"}


def _ext_module(os_type: str):
    name = {"linux": "extractor.linux", "mac": "extractor.mac"}.get(os_type or "", "extractor.windows")
    path = Path(__file__).parent / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_MOD_CACHE: Dict[str, Any] = {}


def ext_module(os_type: str):
    k = os_type or "windows"
    if k not in _MOD_CACHE:
        _MOD_CACHE[k] = _ext_module(k)
    return _MOD_CACHE[k]


def expected_json(plugin: str) -> str:
    return plugin.replace(".", "_") + ".json" if "." in plugin else plugin + "_vol2.json"


def engine_of(plugin: str) -> str:
    return "vol3" if "." in plugin else "vol2"


def short_name(plugin: str) -> str:
    """Same rule as the extractors' _short_name (dependency keys)."""
    p = plugin.lower()
    for pre in ("windows.", "linux.", "mac."):
        if p.startswith(pre):
            p = p[len(pre):]
    parts = p.split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def read_summary(od: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for line in (Path(od) / "SUMMARY.txt").read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip().lower()
                if k in ("image", "os", "mode", "volatility", "profile", "duration") and k not in out:
                    out[k] = v.strip()
    except OSError:
        pass
    return out


def _timeouts(jd: Path) -> Dict[str, Dict[str, Any]]:
    try:
        return {d.get("plugin"): d for d in json.loads((jd / "_timeouts.json").read_text(encoding="utf-8"))
                if isinstance(d, dict)}
    except (OSError, ValueError):
        return {}


def run_plugin_list(od: Path) -> List[str]:
    """Plugins the case's run was meant to execute: the extractor list for its
    engine/OS/mode, plus Vol2 extras and any other plugin with output on disk."""
    od = Path(od)
    jd = od / "json"
    s = read_summary(od)
    os_type = (s.get("os") or "windows").lower()
    ver = "vol2" if "vol2" in (s.get("volatility") or "").lower() else "vol3"
    mode = s.get("mode") or "full"
    try:
        mod = ext_module(os_type)
        plugs = mod.PLUGINS.get(f"{ver}-{os_type}-{mode}") or mod.PLUGINS.get(f"{ver}-{os_type}-full", "")
        plugs = plugs.split()
        known = {expected_json(p): p for v in mod.PLUGINS.values() for p in v.split()}
        for p in getattr(mod, "VOL2_EXCLUSIVE", "").split() + getattr(mod, "VOL2_XP_ONLY", "").split():
            known.setdefault(expected_json(p), p)
    except Exception:
        plugs, known = [], {}
    seen = set(plugs)
    if jd.is_dir():
        for f in sorted(jd.iterdir()):
            n = f.name[:-len(".error")] if f.name.endswith(".json.error") else f.name
            if not n.endswith(".json") or n.startswith("_"):
                continue
            p = known.get(n)
            if p is None and n.endswith("_vol2.json"):
                p = n[:-len("_vol2.json")]
            if p and p not in seen:
                plugs.append(p)
                seen.add(p)
    return plugs


def clean_error(err: str) -> str:
    """The useful part of a stored error: drop Volatility banners and progress lines."""
    keep = [l.strip() for l in (err or "").splitlines()
            if l.strip() and not l.lstrip().startswith("Progress:")
            and not re.match(r"Volatility (3 )?(Foundation )?(Volatility )?Framework", l.strip())]
    return " | ".join(keep)[:300] or "failed"


def _limit_from(err: str) -> Optional[int]:
    m = re.search(r"Timeout after (\d+)\s*s", err or "")
    return int(m.group(1)) if m else None


def case_plugin_states(od: Path) -> List[Dict[str, Any]]:
    """One row per plugin of the case: plugin, engine, state (see LABEL), label,
    error, last_limit_s (the limit it was killed at, for timeouts), parent (for
    'skipped': the failed plugin it depends on)."""
    od = Path(od)
    jd = od / "json"
    s = read_summary(od)
    os_type = (s.get("os") or "windows").lower()
    tos = _timeouts(jd)
    rows: List[Dict[str, Any]] = []
    for p in run_plugin_list(od):
        jp = jd / expected_json(p)
        ep = Path(str(jp) + ".error")
        r: Dict[str, Any] = {"plugin": p, "engine": engine_of(p), "error": "", "last_limit_s": None,
                             "parent": None}
        if ep.exists():
            try:
                err = ep.read_text(encoding="utf-8", errors="ignore").strip()
            except OSError:
                err = "failed"
            to = tos.get(p)
            if to or err.startswith("Timeout"):
                r["state"] = "timeout"
                r["last_limit_s"] = (to or {}).get("retry_timeout_s") or _limit_from(err)
            else:
                r["state"] = "failed"
            r["error"] = clean_error(err)
        elif jp.exists():
            try:
                size = jp.stat().st_size
                with open(jp, "rb") as fh:          # plugin JSONs can be hundreds of MB
                    head = fh.read(2000).decode("utf-8", "ignore").lower()
            except OSError:
                size, head = 0, ""
            if any(m in head for m in _BAD_MARKERS):
                r["state"], r["error"] = "failed", "output contains a Volatility error"
            elif p in tos:
                r["state"] = "timeout"
                r["last_limit_s"] = tos[p].get("retry_timeout_s")
            else:
                r["state"] = "done" if size > 10 else "empty"
        else:
            r["state"] = "not run"
        rows.append(r)
    # 'not run' because a parent failed -> 'skipped (dependency)'
    try:
        deps = ext_module(os_type).DEPENDENCIES
    except Exception:
        deps = {}
    bad = {short_name(r["plugin"]): r["plugin"] for r in rows if r["state"] in ("failed", "timeout")}
    for r in rows:
        if r["state"] != "not run":
            continue
        sn = short_name(r["plugin"])
        for parent, children in deps.items():
            if sn in children and parent in bad:
                r["state"], r["parent"] = "skipped", bad[parent]
                break
    for r in rows:
        r["label"] = LABEL.get(r["state"], r["state"])
    return rows


def dependents(plugin: str, rows: List[Dict[str, Any]]) -> List[str]:
    """Plugins of the case that were skipped (or never ran) because `plugin` failed."""
    return [r["plugin"] for r in rows if r.get("parent") == plugin]


def affected_steps(plugins: List[str], os_type: str) -> List[str]:
    names = [expected_json(p).lower() for p in plugins]
    out = []
    for st in STEPS:
        if st.get("os") and st["os"] != (os_type or "windows"):
            continue
        if any(k.lower() in n for n in names for k in st["keys"]):
            out.append(st["label"])
    return out


def parse_spec(spec: str) -> List[Dict[str, Any]]:
    """'windows.netscan.NetScan:1800,windows.netstat.NetStat:auto,timers:0' ->
    [{plugin, timeout}] with timeout None = calibrated model, 0 = no limit."""
    out = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        p, _, t = part.partition(":")
        t = t.strip().lower()
        out.append({"plugin": p.strip(),
                    "timeout": None if t in ("", "auto") else max(0, int(t))})
    return out


def make_spec(items: List[Dict[str, Any]]) -> str:
    return ",".join(f"{i['plugin']}:{'auto' if i.get('timeout') is None else int(i['timeout'])}"
                    for i in items)
