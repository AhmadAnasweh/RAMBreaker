"""crash_report.py — local failure-fingerprint artifact (Step 1 of opt-in crash reporting).

When an extraction hits plugin failures, this writes a **scrubbed, structured**
``<output>/crash_report.json`` next to the results. It is the local, zero-network
half of the design in ``claude context/FUTURE_CRASH_REPORTING.md``: turn every
failed run into a self-diagnosing artifact (host, target kernel/distro, engine,
ISF outcome, per-plugin pass/fail + failure class) that an analyst can read now
and — later, once transport is proven — hand to the tool author manually.

HARD CONSTRAINT (this is a forensics tool over evidence memory):
  * **Whitelist, never blacklist.** Only the fields assembled here are ever
    emitted; a new sensitive field cannot leak by accident.
  * **No image content.** No strings, IOCs, hostnames/IPs, file paths, usernames,
    hashes or dumped files. The kernel banner is parsed down to version+distro
    (the banner embeds the builder ``user@host`` and build path — never sent).
  * **Every free-text field is scrubbed** through :func:`scrub` before it lands:
    hex addresses -> ``<addr>``, absolute paths -> ``<path>``.
  * **Local only.** This module never sends anything. It reads the output dir +
    the run_health taxonomy (already log-derived and local) and writes one file.

The classification of *which* plugin failed and *why* is reused verbatim from
:mod:`modules.run_health` (the ``failure_taxonomy``), so there is a single source
of truth for failure semantics. Every helper here is a pure, unit-testable
function; :func:`write` is the only side-effecting entry point and is wrapped so
it can never affect an extraction.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "crescent-crash-report/1"

# Toolchain pins recorded so the maintainer can tell a tool-env regression from a
# target-image failure without the image. Mirrors TOOLCHAIN.lock.md (the pin is
# the source of truth); kept as constants so this module stays self-contained.
TOOLCHAIN = {
    "vol3_commit_pinned": "634774fd",
    "dwarf2json": "0.9.0",
    "source": "TOOLCHAIN.lock.md",
}


# --------------------------------------------------------------------------- #
# Pure, unit-testable scrubbers / parsers
# --------------------------------------------------------------------------- #
_ADDR = re.compile(r"0x[0-9a-fA-F]{3,}")
_WINPATH = re.compile(r"[A-Za-z]:\\[^\s\"'<>|]+")
_USERPATH = re.compile(r"/(?:home|Users|root|var|tmp|mnt|media)/[^\s\"'<>]*")
_ABSPATH = re.compile(r"/(?:[\w.\-]+/)+[\w.\-]*")
_DIGITS = re.compile(r"\b\d{2,}\b")


def scrub(text: Any) -> str:
    """Redact anything that could carry target data from a free-text string.

    Order matters: addresses first (they contain hex that path rules ignore),
    then Windows drive paths, then known user-data roots, then any remaining
    absolute POSIX path. Pure function — safe to call on any error text before it
    is written. Non-strings are coerced; ``None``/empty pass through unchanged.
    """
    if text is None:
        return ""
    s = str(text)
    if not s:
        return s
    s = _ADDR.sub("<addr>", s)
    s = _WINPATH.sub("<path>", s)
    s = _USERPATH.sub("<path>", s)
    s = _ABSPATH.sub("<path>", s)
    return s


def normalize_error(text: Any) -> str:
    """Scrub + collapse digit runs to ``<n>`` so equivalent errors share one
    string. Used for the run fingerprint (dedup) — not for human display."""
    return _DIGITS.sub("<n>", scrub(text))


def distro_from_banner(banner: str) -> str:
    """Best-effort distro label from a Linux/macOS kernel banner. Mirrors
    linux_resolver._distro_from_banner (kept local to avoid a heavy import)."""
    b = (banner or "").lower()
    if not b:
        return ""
    if "darwin" in b or "root:xnu" in b:
        return "macOS"
    if "kali" in b:
        return "Kali"
    if "debian" in b:
        return "Debian"
    if re.search(r"\.el\d|\.fc\d|red hat|centos|almalinux|rocky", b):
        return "RHEL"
    if "suse" in b:
        return "SUSE"
    if "ubuntu" in b:
        return "Ubuntu"
    return "Linux"


def parse_kernel_banner(banner: str) -> Dict[str, str]:
    """Reduce a full kernel banner to ``{"kernel": <version>, "distro": <name>}``.

    The full banner embeds the builder ``user@host`` and the build path, so the
    banner itself is NEVER retained — only the parsed version string and a distro
    label. Pure function.
    """
    b = banner or ""
    kernel = ""
    m = re.search(r"Linux version (\S+)", b)
    if m:
        kernel = m.group(1)
    else:
        m = re.search(r"Darwin (?:Kernel Version )?([0-9][\w.\-]*)", b)
        if m:
            kernel = m.group(1).rstrip(":")
    return {"kernel": kernel, "distro": distro_from_banner(b)}


def fingerprint(target: Dict[str, Any], failed: List[Dict[str, str]]) -> str:
    """Stable short hash of (target OS/engine/kernel + sorted failure classes).

    Lets the maintainer dedup identical failures across runs/machines without any
    image-derived data. Pure and order-independent over the failure set.
    """
    parts = [
        target.get("os_type", ""),
        target.get("engine", ""),
        target.get("kernel", ""),
        target.get("distro", ""),
    ]
    classes = sorted(
        f"{f.get('plugin', '')}:{f.get('category', '')}" for f in failed
    )
    payload = "|".join(parts + classes)
    return hashlib.sha256(payload.encode("utf-8", "ignore")).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Disk readers (self-contained, output-dir only)
# --------------------------------------------------------------------------- #
def _read_kernel(json_dir: Path) -> Dict[str, str]:
    """Parsed kernel/distro from ``json/linux_kernel.json`` (Linux/macOS runs).
    Returns empty strings when the file is absent (e.g. Windows)."""
    kf = json_dir / "linux_kernel.json"
    if not kf.is_file():
        return {"kernel": "", "distro": ""}
    try:
        data = json.loads(kf.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {"kernel": "", "distro": ""}
    banner = data.get("banner", "") or ""
    parsed = parse_kernel_banner(banner) if banner else {"kernel": "", "distro": ""}
    if not parsed["kernel"]:
        # Fall back to the pre-parsed version field, distro from banner if any.
        parsed["kernel"] = str(data.get("kernel_version", "") or "")
        if not parsed["distro"]:
            parsed["distro"] = distro_from_banner(banner or parsed["kernel"])
    return parsed


def _ok_plugin_names(json_dir: Path) -> List[str]:
    """Names of plugins that produced JSON (plugin identity only — no target
    data). Used to record what actually ran alongside the failures."""
    if not json_dir.is_dir():
        return []
    names = set()
    for p in json_dir.glob("*.json"):
        stem = p.stem
        if stem in ("linux_kernel", "run_health", "crash_report"):
            continue
        names.add(stem)
    return sorted(names)


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #
def build(output_dir, *, os_type: str, engine: str, profile: Optional[str],
          mode: Optional[str], results: Dict[str, Any],
          health: Dict[str, Any], tool_version: str = "6.0",
          host: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Assemble the whitelisted, scrubbed crash-report dict. Pure w.r.t. its
    inputs except for reading ``json/linux_kernel.json`` under ``output_dir`` for
    the parsed kernel/distro. Never raises on bad input — coerces defensively."""
    output_dir = Path(output_dir)
    json_dir = output_dir / "json"
    results = results or {}
    health = health or {}

    if host is None:
        host = {
            "os": platform.system().lower(),
            "arch": platform.machine(),
            "python": platform.python_version(),
        }

    kern = _read_kernel(json_dir)
    target = {
        "os_type": os_type,
        "engine": engine,
        "profile": scrub(profile) if profile else None,
        "kernel": kern["kernel"],
        "distro": kern["distro"],
    }

    taxonomy = health.get("failure_taxonomy", []) or []
    failed_plugins = [
        {
            "name": t.get("plugin", ""),
            "category": t.get("category", "other"),
            "reason": scrub(t.get("reason", "")),
        }
        for t in taxonomy
    ]

    findings = [
        {
            "severity": f.get("severity", ""),
            "check": f.get("check", ""),
            "message": scrub(f.get("message", "")),
        }
        for f in (health.get("findings", []) or [])
    ]

    report = {
        "schema": SCHEMA,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "note": ("Local diagnostic artifact — scrubbed and safe to hand to the "
                 "tool author. Contains NO image content: no strings, IOCs, "
                 "hostnames, IPs, file paths, usernames, hashes or dumped files."),
        "tool_version": tool_version,
        "run": {
            "status": health.get("status", "unknown"),
            "mode": mode,
            "duration_s": round(float(results.get("duration", 0.0)), 1),
            "plugins_ok": results.get("ok"),
            "plugins_failed": results.get("fail"),
            "plugins_skipped": results.get("skipped"),
            "plugins_dep_skipped": results.get("dep_skipped"),
        },
        "host": host,
        "target": target,
        "toolchain": dict(TOOLCHAIN),
        "process_corroboration": health.get("process_counts", {}),
        "findings": findings,
        "failed_plugins": failed_plugins,
        "ok_plugins": _ok_plugin_names(json_dir),
    }
    report["fingerprint"] = fingerprint(target, failed_plugins)
    return report


# Failure categories that are NOT real problems — a run whose only failures are
# these is not "a crash" (run_health rates it healthy), so it gets no report.
_BENIGN = {"expected-nonbug", "empty-result"}


def _should_write(results: Dict[str, Any], health: Dict[str, Any]) -> bool:
    """Only produce a crash report when something *actually* went wrong.

    A crash_report.json sitting in the output dir means "this run had a real
    problem." That must agree with run_health's verdict, so we write when:
      * run_health status is not ``healthy`` (degraded/broken), OR
      * a failed plugin was classified as a *real* failure (anything but an
        expected-nonbug / empty-result), OR
      * plugins failed but none could be classified (unclassified — surface it
        rather than swallow it).
    A healthy run whose only failures are documented non-bugs (e.g. Vol2
    connections/connscan on modern Windows) leaves NO artifact."""
    results = results or {}
    health = health or {}
    if health.get("status", "healthy") != "healthy":
        return True
    taxonomy = health.get("failure_taxonomy", []) or []
    if any(t.get("category") not in _BENIGN for t in taxonomy):
        return True
    # Plugins failed but the taxonomy captured nothing to classify — don't hide it.
    return (results.get("fail") or 0) > 0 and not taxonomy


def write(output_dir, image, vol, mode, results, health) -> Optional[Path]:
    """Write ``<output_dir>/crash_report.json`` iff the run had failures.

    Thin, side-effecting wrapper over :func:`build`, called from each extractor's
    ``write_summary``. ``image`` is accepted for signature symmetry but is never
    read into the report (no image-derived data leaves this function). Returns the
    path written, or ``None`` if the run was clean / on any error (best-effort —
    must never disturb an extraction)."""
    try:
        if not _should_write(results, health):
            return None
        report = build(
            output_dir,
            os_type=getattr(vol, "os_type", "windows"),
            engine=getattr(vol, "vol_version", ""),
            profile=getattr(vol, "profile", None),
            mode=mode,
            results=results,
            health=health,
        )
        out = Path(output_dir) / "crash_report.json"
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        # Step 2 (opt-in transport): no-op unless telemetry was explicitly
        # enabled AND an endpoint is set. Bounded + wrapped — never blocks/breaks.
        maybe_send(report)
        return out
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Step 2 — opt-in transport (default OFF; the report is already scrubbed)
# --------------------------------------------------------------------------- #
# Consent model: OFF unless the analyst explicitly opts in. Opt-in is expressed
# either by `CRESCENT_TELEMETRY=1` (+ `CRESCENT_TELEMETRY_ENDPOINT`) or by a saved
# config written via enable(). `CRESCENT_TELEMETRY=0` / `--no-telemetry`
# (main() maps the flag to the env var) forces OFF unconditionally. Nothing is
# ever sent without an endpoint, and only the whitelisted+scrubbed crash report
# (plus an opt-in install_id) leaves the process. Dedup by fingerprint so one
# unique failure is reported at most once per install.
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _telemetry_config_path() -> Path:
    override = os.environ.get("CRESCENT_TELEMETRY_CONFIG")
    if override:
        return Path(override)
    return Path.home() / ".config" / "rambreaker" / "telemetry.json"


def _load_telemetry_config() -> Dict[str, Any]:
    try:
        return json.loads(_telemetry_config_path().read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_telemetry_config(cfg: Dict[str, Any]) -> None:
    try:
        p = _telemetry_config_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass


def telemetry_enabled(config: Optional[Dict[str, Any]] = None,
                      env: Optional[Dict[str, str]] = None) -> bool:
    """Opt-in, default OFF. Env wins over config: CRESCENT_TELEMETRY in
    {0,false,no,off} forces OFF; in {1,true,yes,on} forces ON; otherwise the saved
    config's ``enabled`` flag decides. Pure given (config, env)."""
    env = os.environ if env is None else env
    val = str(env.get("CRESCENT_TELEMETRY", "")).strip().lower()
    if val in _FALSE:
        return False
    if val in _TRUE:
        return True
    config = _load_telemetry_config() if config is None else config
    return bool(config.get("enabled", False))


def telemetry_endpoint(config: Optional[Dict[str, Any]] = None,
                       env: Optional[Dict[str, str]] = None) -> Optional[str]:
    env = os.environ if env is None else env
    ep = env.get("CRESCENT_TELEMETRY_ENDPOINT")
    if ep:
        return ep
    config = _load_telemetry_config() if config is None else config
    return config.get("endpoint")


def get_install_id(create: bool = False) -> Optional[str]:
    """Stable per-install random id. Only generated/persisted when ``create`` is
    True (i.e. right before an opted-in send) — a disabled install has no id."""
    cfg = _load_telemetry_config()
    iid = cfg.get("install_id")
    if iid or not create:
        return iid
    iid = uuid.uuid4().hex
    cfg["install_id"] = iid
    _save_telemetry_config(cfg)
    return iid


def build_payload(report: Dict[str, Any],
                  install_id: Optional[str]) -> Dict[str, Any]:
    """The already-scrubbed, whitelisted crash report + an opt-in install_id. No
    new unscrubbed fields are ever added — the report itself is the whitelist."""
    payload = dict(report)
    payload["install_id"] = install_id
    return payload


def _should_send(fingerprint: Optional[str], sent: Optional[List[str]],
                 enabled: bool, endpoint: Optional[str]) -> bool:
    """Gate: only when enabled, an endpoint exists, and this fingerprint is new.
    Pure."""
    if not (enabled and endpoint and fingerprint):
        return False
    return fingerprint not in set(sent or [])


def enable(endpoint: str) -> None:
    """Record explicit opt-in + endpoint (the interactive/CLI consent action)."""
    cfg = _load_telemetry_config()
    cfg["enabled"] = True
    cfg["endpoint"] = endpoint
    cfg.setdefault("install_id", uuid.uuid4().hex)
    _save_telemetry_config(cfg)


def disable() -> None:
    """Revoke opt-in. Leaves install_id so re-enabling is stable; clears nothing
    sensitive (there is nothing sensitive stored)."""
    cfg = _load_telemetry_config()
    cfg["enabled"] = False
    _save_telemetry_config(cfg)


def send(payload: Dict[str, Any], endpoint: str, timeout: float = 3.0) -> bool:
    """Best-effort POST of a scrubbed payload to an opted-in endpoint. Bounded
    (short timeout) and fully wrapped — never raises, never blocks a run beyond
    ``timeout``. No endpoint => no-op. Returns True on a 2xx response."""
    if not endpoint:
        return False
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint, data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": f"RAMBreaker/{report_tool_version()}"},
            method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= int(getattr(resp, "status", 200)) < 300
    except Exception:
        return False


def report_tool_version() -> str:
    return "6.0"


def maybe_send(report: Dict[str, Any]) -> bool:
    """Orchestrator called after a crash report is written. Sends the scrubbed
    report exactly once per unique fingerprint, only if telemetry is opted-in and
    an endpoint is configured. No-op (and instant) otherwise. Never raises."""
    try:
        cfg = _load_telemetry_config()
        if not telemetry_enabled(cfg):
            return False
        endpoint = telemetry_endpoint(cfg)
        fp = report.get("fingerprint")
        if not _should_send(fp, cfg.get("sent_fingerprints"), True, endpoint):
            return False
        payload = build_payload(report, get_install_id(create=True))
        if send(payload, endpoint):
            cfg = _load_telemetry_config()  # re-read (get_install_id may have written)
            cfg.setdefault("sent_fingerprints", []).append(fp)
            _save_telemetry_config(cfg)
            return True
        return False
    except Exception:
        return False


def sample_payload() -> Dict[str, Any]:
    """A representative, fully-scrubbed payload to SHOW an analyst before they
    opt in (the design's 'show a sample before asking'). Uses placeholder data —
    reads nothing from any real image."""
    report = {
        "schema": SCHEMA, "generated": "2026-01-01T00:00:00",
        "tool_version": report_tool_version(),
        "run": {"status": "degraded", "mode": "fast", "duration_s": 747.3,
                "plugins_ok": 9, "plugins_failed": 1},
        "host": {"os": "linux", "arch": "x86_64", "python": "3.13.2"},
        "target": {"os_type": "linux", "engine": "vol3", "profile": None,
                   "kernel": "6.12.13-amd64", "distro": "Kali"},
        "toolchain": dict(TOOLCHAIN),
        "process_corroboration": {"pslist": 232, "psscan": None, "pstree": 2},
        "failed_plugins": [{"name": "linux.pagecache.Files", "category": "timeout",
                            "reason": "plugin exceeded its time budget"}],
        "fingerprint": "f7f8c5fa2d55c6c0",
    }
    return build_payload(report, install_id="<generated once on opt-in>")
