"""Run-health assessment — turn silent extraction failures into loud, labelled ones.

A forensics report that is *quietly incomplete* is worse than one that crashes:
an empty Processes tab looks the same as a clean system. This module inspects a
finished extraction's ``json/`` directory and produces:

  * a **process corroboration** check (pslist vs psscan vs pstree) that catches
    the Bug-#10 signature — pslist empty while psscan finds processes;
  * an **empty-key-plugin** check (network / files produced nothing);
  * a **failure taxonomy** classifying each failed plugin from the local log;
  * a **health banner** appended to SUMMARY.txt and a structured
    ``run_health.json`` for downstream use.

It is fully self-contained (reads only the output directory + the local log,
never the image) and every classification rule is a pure, unit-testable
function. See ``claude context/FUTURE_CRASH_REPORTING.md`` for the log-signature
cheat-sheet these rules encode.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from utils.json_converter import load_json_by_pattern
except Exception:  # pragma: no cover - fallback if imported standalone
    def load_json_by_pattern(json_dir: Path, pattern: str):
        hits = sorted(Path(json_dir).glob(f"*{pattern}*.json"))
        for p in hits:
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                return data if isinstance(data, list) else [data]
            except Exception:
                continue
        return []


# Severity ordering (worst first) — drives the overall status.
CRITICAL, WARN, OK = "critical", "warning", "ok"

# Per-OS plugins whose emptiness is a red flag, grouped by the report tab they
# feed. If *every* plugin in a group returns nothing, that tab is silently empty.
KEY_PLUGINS: Dict[str, Dict[str, List[str]]] = {
    "windows": {"process": ["pslist", "psscan", "pstree"],
                "network": ["netscan", "netstat"],
                "files":   ["filescan"]},
    "linux":   {"process": ["pslist", "psscan", "pstree"],
                "network": ["sockstat"],
                "files":   ["pagecache"]},
    "mac":     {"process": ["pslist", "psscan", "pstree"],
                "network": ["netstat"],
                "files":   ["list_files"]},
}


# --------------------------------------------------------------------------- #
# Pure, unit-testable classifiers
# --------------------------------------------------------------------------- #
# Plugins whose failure is documented and expected (not a real bug). Keyed by
# the short plugin name that appears in the log; see the cheat-sheet.
EXPECTED_NONBUG_PLUGINS = {
    "connections": "XP-era plugin on a modern Windows image (use netscan)",
    "connscan":    "XP-era plugin on a modern Windows image (use netscan)",
    "sockets":     "XP-era plugin on a modern Windows image (use netscan)",
    "sockscan":    "XP-era plugin on a modern Windows image (use netscan)",
    "sockstat":    "often times out on VMware .vmem Linux — expected",
    "mac.bash":    "mac.bash is unreliable on some images",
}


def classify_failure(text: str, plugin_name: str = "") -> Dict[str, str]:
    """Classify a plugin failure from its error text and (authoritatively) its
    plugin name.

    Returns ``{"category": <slug>, "reason": <human>}``. Categories:
    expected-nonbug, symbol-missing, struct-mismatch, timeout,
    unsatisfied-requirement, other. Pure function — encodes the log-signature
    cheat-sheet so a struct change on a brand-new kernel reads as routine, not a
    fire.
    """
    t = (text or "").lower()

    # Plugin NAME is the reliable signal for documented non-bugs.
    short = plugin_name.split(".")[-1].lower() if plugin_name else ""
    for name, reason in EXPECTED_NONBUG_PLUGINS.items():
        key = name.split(".")[-1]
        if short == key or (plugin_name and name in plugin_name.lower()):
            return {"category": "expected-nonbug", "reason": reason}
    if "mac.bash" in t or ("bash" in t and "mac" in t):
        return {"category": "expected-nonbug",
                "reason": "mac.bash is unreliable on some images"}

    # Missing / failed symbol table (ISF) — plugins load but walk 0 objects.
    if ("no matching isf" in t or "symbol_table_name" in t
            or "symbol table requirement was not fulfilled" in t
            or "symbol table requirement" in t
            or "layer_name" in t):
        return {"category": "symbol-missing",
                "reason": "no matching ISF / kernel symbols for this image"}

    # Incomplete ISF (stub struct) or Vol3-plugin-vs-kernel struct drift.
    if ("member not present in template" in t
            or "not present in template" in t):
        return {"category": "struct-mismatch",
                "reason": "incomplete ISF (stub struct) — rebuild with current dwarf2json"}
    if re.search(r"attributeerror.*\.\w+", t) and (
            "struct" in t or "!" in text or "template" in t or "symbol" in t):
        return {"category": "struct-mismatch",
                "reason": "kernel struct changed vs this Volatility version — bump Vol3"}
    if "attributeerror" in t and re.search(r"'\w+' object has no attribute", t):
        return {"category": "struct-mismatch",
                "reason": "kernel struct changed vs this Volatility version — bump Vol3"}

    if "timeout" in t or "timed out" in t:
        return {"category": "timeout",
                "reason": "plugin exceeded its time budget (raise --timeout or use -j 2)"}
    if "unsatisfied requirement" in t or "requirement was not fulfilled" in t:
        return {"category": "unsatisfied-requirement",
                "reason": "a plugin requirement was not met (often symbols/layer)"}

    # Error text that is just the Volatility banner (or empty) means the plugin
    # ran but produced no rows — usually benign, not a failure worth surfacing.
    stripped = (text or "").strip()
    if (not stripped
            or re.fullmatch(r"volatility foundation volatility framework [\d.]+",
                            stripped.lower())):
        return {"category": "empty-result",
                "reason": "no error detail — plugin returned no rows (often benign)"}

    return {"category": "other", "reason": stripped[:160] or "unknown"}


def corroborate_processes(counts: Dict[str, Optional[int]]) -> List[Dict[str, str]]:
    """Cross-check process-listing plugins. ``counts`` maps
    'pslist'/'psscan'/'pstree' to a record count (None = plugin produced no
    output). Pure function. Returns a list of findings (possibly empty = OK).
    """
    pslist = counts.get("pslist")
    psscan = counts.get("psscan")
    pstree = counts.get("pstree")
    findings: List[Dict[str, str]] = []

    if all(v is None for v in (pslist, psscan, pstree)):
        return [{"severity": CRITICAL, "check": "processes",
                 "message": "No process plugin produced any output — extraction "
                            "likely failed or symbols are missing. The Processes "
                            "tab will be empty."}]

    # Bug-#10 signature: pool-scan sees processes but the linked list is empty.
    if (psscan or 0) > 0 and (pslist is None or pslist == 0):
        findings.append({
            "severity": CRITICAL, "check": "processes",
            "message": f"psscan found {psscan} processes but pslist is empty. "
                       f"This is EITHER hidden processes OR a silent pslist "
                       f"failure (the cold-start symbol race). Do not trust the "
                       f"Processes tab until you check psscan output."})
        return findings

    if (pslist or 0) == 0 and (psscan or 0) == 0:
        findings.append({
            "severity": CRITICAL, "check": "processes",
            "message": "Both pslist and psscan recovered 0 processes — almost "
                       "certainly wrong symbols or a bad image, not a real system."})
        return findings

    # Large disagreement — possible hidden/terminated processes (an observation).
    if pslist and psscan and psscan > pslist + max(3, int(pslist * 0.25)):
        findings.append({
            "severity": WARN, "check": "processes",
            "message": f"psscan ({psscan}) exceeds pslist ({pslist}) by "
                       f"{psscan - pslist} — possible hidden or terminated "
                       f"processes. Observation, not a verdict; verify in psscan."})

    if pstree is not None and pslist and pstree == 0:
        findings.append({
            "severity": WARN, "check": "processes",
            "message": "pstree is empty though pslist has processes — the process "
                       "tree in the report may be missing."})
    return findings


# --------------------------------------------------------------------------- #
# Disk-driven assessment
# --------------------------------------------------------------------------- #
def _count(json_dir: Path, pattern: str) -> Optional[int]:
    """Record count for the first plugin JSON matching ``pattern``; None if no
    such file exists (distinguishes 'plugin didn't run' from 'ran, found 0')."""
    if not any(json_dir.glob(f"*{pattern}*.json")):
        return None
    try:
        data = load_json_by_pattern(json_dir, pattern)
        return len(data) if isinstance(data, list) else (1 if data else 0)
    except Exception:
        return None


_LOG_FAIL_RE = re.compile(
    r"([A-Za-z0-9_.]+)\s+FAILED(?:\s*\([^)]*\))?[^:]*:\s*(.+)")


def _classify_log_failures(log_path: Path) -> List[Dict[str, str]]:
    """Best-effort taxonomy of failed plugins from the LOCAL log. Local-only —
    never sent anywhere (see FUTURE_CRASH_REPORTING.md)."""
    out: List[Dict[str, str]] = []
    if not log_path.is_file():
        return out
    seen = set()
    try:
        for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = _LOG_FAIL_RE.search(line)
            if not m:
                continue
            plugin, err = m.group(1), m.group(2)
            if plugin in seen:
                continue
            seen.add(plugin)
            cls = classify_failure(err, plugin)
            out.append({"plugin": plugin, **cls})
    except Exception:
        pass
    return out


def assess(output_dir, os_type: str, mode: Optional[str] = None,
           results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Assess a finished extraction. Reads ``<output_dir>/json`` and the local
    log; writes ``<output_dir>/run_health.json``; returns a health dict with a
    ready-to-print ``banner`` (list of lines)."""
    output_dir = Path(output_dir)
    json_dir = output_dir / "json"
    os_type = os_type if os_type in KEY_PLUGINS else "windows"
    groups = KEY_PLUGINS[os_type]

    counts = {name: _count(json_dir, name) for name in groups["process"]}
    findings = corroborate_processes(counts)

    # Empty-key-plugin (silent empty tab) checks for network + files.
    for tab in ("network", "files"):
        plugs = groups.get(tab, [])
        vals = [_count(json_dir, p) for p in plugs]
        ran = [v for v in vals if v is not None]
        if ran and all(v == 0 for v in ran):
            findings.append({
                "severity": WARN, "check": tab,
                "message": f"The {tab} tab is empty (all of "
                           f"{', '.join(plugs)} returned 0). Could be a quiet "
                           f"host or a plugin failure — verify before relying on it."})

    taxonomy = _classify_log_failures(output_dir / "crescent_toolkit.log")

    severities = [f["severity"] for f in findings]
    if CRITICAL in severities:
        status = "broken"
    elif WARN in severities or any(t["category"] in ("symbol-missing", "struct-mismatch")
                                   for t in taxonomy):
        status = "degraded"
    else:
        status = "healthy"

    health = {
        "status": status,
        "os_type": os_type,
        "mode": mode,
        "process_counts": counts,
        "findings": findings,
        "failure_taxonomy": taxonomy,
        "plugins_ok": (results or {}).get("ok"),
        "plugins_failed": (results or {}).get("fail"),
    }
    health["banner"] = format_banner(health)

    try:
        (output_dir / "run_health.json").write_text(
            json.dumps(health, indent=2), encoding="utf-8")
    except Exception:
        pass
    return health


def format_banner(health: Dict[str, Any]) -> List[str]:
    """Render the health dict as a SUMMARY.txt / console banner (list of lines)."""
    icon = {"healthy": "OK", "degraded": "WARN", "broken": "CRITICAL"}
    counts = health.get("process_counts", {})
    lines = [
        "",
        "-" * 50,
        f"RUN HEALTH: {icon.get(health['status'], '?')}  ({health['status']})",
        "-" * 50,
        "Process corroboration: "
        + ", ".join(f"{k}={'-' if v is None else v}" for k, v in counts.items()),
    ]
    for f in health.get("findings", []):
        tag = {"critical": "[!!]", "warning": "[! ]", "ok": "[ok]"}.get(
            f["severity"], "[  ]")
        lines.append(f"{tag} {f['message']}")
    tax = health.get("failure_taxonomy", [])
    if tax:
        low = {"expected-nonbug", "empty-result"}
        expected = [t for t in tax if t["category"] in low]
        real = [t for t in tax if t["category"] not in low]
        if real:
            lines.append("Failed plugins that need attention:")
            for t in real:
                lines.append(f"     - {t['plugin']}: {t['category']} — {t['reason']}")
        if expected:
            names = ", ".join(sorted({t["plugin"] for t in expected}))
            lines.append(f"Expected / empty ({len(expected)}): {names}")
    if health["status"] == "healthy" and not health.get("findings"):
        lines.append("[ok] No corroboration or empty-tab problems detected.")
    lines.append("-" * 50)
    return lines
