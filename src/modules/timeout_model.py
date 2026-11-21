"""Dynamic per-plugin timeouts, fitted from measured runtimes (RAMBreaker v2).

Every plugin run is recorded to <app>/config/timing_samples.jsonl:
    {"plugin", "engine", "os", "size_gb", "duration", "ok", "timed_out", "ts"}
`fit()` turns the samples into <app>/config/timeouts.json:
    per plugin+engine+os:  expected = base_s + per_gb_s * size_gb
    fitted by least squares over the samples (non-negative coefficients;
    with a single dump size the slope is split from the intercept using the
    across-plugin median intercept share), plus per cost-class medians used
    for plugins never measured.
    timeout = clamp(safety_factor * expected + slack_s, min_timeout_s, max_timeout_s)
A timed-out sample is right-censored: the true runtime is > its timeout, so
the plugin's expectation is raised to at least that value.

On timeout the caller kills the plugin, logs it, retries ONCE with
timeout * retry_factor, and marks the result if it times out again.
"""

import json
import os
import statistics
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULTS = {
    "version": 1,
    "safety_factor": 3.0,
    "slack_s": 60,
    "min_timeout_s": 120,
    "max_timeout_s": 4 * 3600,
    "retry_factor": 2.5,
    # used only before any calibration data exists (seconds, per GB of dump)
    "bootstrap": {"light": [5, 3], "medium": [10, 20], "heavy": [30, 120]},
    "classes": {},
    "plugins": {},
}

# Cost classes for plugins with no measurements yet (substring match).
HEAVY = ("netscan", "mftscan", "vadinfo", "handles", "dlllist", "ldrmodules",
         "filescan", "malfind", "svcscan", "sockstat", "library_list", "lsof",
         "elfs", "psaux", "proc.maps", "proc_maps", "list_files", "pagecache",
         "timers", "yarascan", "dumpfiles", "memmap", "vadyarascan", "atomscan",
         "callbacks", "modscan", "driverscan", "psscan", "hivescan", "shimcache",
         "shellbags", "mbrparser", "thrdscan", "poolscanner", "bigpools")
LIGHT = ("info", "pslist", "pstree", "cmdline", "getsids", "envars", "hivelist",
         "banners", "bash", "lsmod", "ifconfig", "ip.addr", "imageinfo",
         "kdbgscan", "crashinfo", "privileges", "sessions", "userassist")

_lock = threading.Lock()


def _cfg_dir() -> Path:
    try:
        from modules.platform_compat import app_root
        d = app_root() / "config"
    except Exception:
        d = Path(__file__).resolve().parent.parent / "config"
    d.mkdir(parents=True, exist_ok=True)
    return d


def cost_class(plugin: str) -> str:
    p = plugin.lower()
    if any(h in p for h in HEAVY):
        return "heavy"
    if any(p.endswith(l) or ("." + l + ".") in p or p == l for l in LIGHT):
        return "light"
    return "medium"


def _key(plugin: str, engine: str, os_type: str) -> str:
    return f"{engine}|{(os_type or 'windows').lower()}|{plugin}"


class TimeoutModel:
    def __init__(self, cfg_dir: Optional[Path] = None):
        self.dir = Path(cfg_dir) if cfg_dir else _cfg_dir()
        self.samples_path = self.dir / "timing_samples.jsonl"
        self.model_path = self.dir / "timeouts.json"
        self.cfg = json.loads(json.dumps(DEFAULTS))
        self.fmt = "raw"            # set by image_size_gb(): format of the current image
        try:
            if self.model_path.is_file():
                self.cfg.update(json.loads(self.model_path.read_text(encoding="utf-8")))
        except Exception:
            pass

    # ---------------------------------------------------------------- estimate
    def expected(self, plugin: str, engine: str, os_type: str, size_gb: float,
                 fmt: Optional[str] = None) -> float:
        """Raw-image estimate x the learned slowdown of this image format.

        Windows crash dumps (PAGEDU64) are read through a page-bitmap layer:
        on the 15.9 GB Win10 dump pool scanners ran 3-9x longer than the raw
        model predicted while list walkers ran faster - so the factor is per
        plugin (measured), with the median as default for unmeasured ones."""
        raw = self._expected_raw(plugin, engine, os_type, size_gb)
        f = (fmt or self.fmt or "raw")
        if f == "raw":
            return raw
        fmts = self.cfg.get("formats") or {}
        fc = fmts.get(f) or {}
        r = (fc.get("plugins") or {}).get(_key(plugin, engine, os_type), {}).get("ratio") \
            or fc.get("default_ratio")
        if not r and f.endswith("+hdd"):
            # no data for this exact profile: borrow the slow-disk slowdown that
            # was measured on other HDD-bound images (median of their defaults)
            hdd = [v.get("default_ratio", 1.0) for k, v in fmts.items() if k.endswith("+hdd")]
            r = statistics.median(hdd) if hdd else None
        return raw * (r or 1.0)

    def _expected_raw(self, plugin: str, engine: str, os_type: str, size_gb: float) -> float:
        m = self.cfg.get("plugins", {}).get(_key(plugin, engine, os_type))
        if m:
            return m["base_s"] + m["per_gb_s"] * size_gb
        cls = cost_class(plugin)
        # Per-OS class medians only: plugin cost differs hugely between target
        # OSes (a Linux lsof took 102 s where Windows heavy plugins took ~11 s
        # on the same-size dump), so never borrow another OS's calibration.
        c = self.cfg.get("classes", {}).get(f"{engine}|{(os_type or 'windows').lower()}|{cls}")
        b, g = self.cfg["bootstrap"][cls]
        boot = b + g * size_gb
        if c and c.get("n_plugins", 0) >= 3:
            return c["base_s"] + c["per_gb_s"] * size_gb
        return max(boot, c["base_s"] + c["per_gb_s"] * size_gb) if c else boot

    def timeout(self, plugin: str, engine: str, os_type: str, size_gb: float) -> int:
        e = self.expected(plugin, engine, os_type, size_gb)
        m = self.cfg.get("plugins", {}).get(_key(plugin, engine, os_type)) or {}
        if self.fmt != "raw":
            fm = ((self.cfg.get("formats") or {}).get(self.fmt) or {}).get("plugins", {}) \
                .get(_key(plugin, engine, os_type))
            if fm:
                m = fm
        # Only ever timed out: the estimate is already a lower bound we have
        # paid for once; a 3x multiplier on it would burn hours on a plugin
        # that is most likely hanging.
        factor = 1.5 if m.get("censored_only") else self.cfg["safety_factor"]
        t = factor * e + self.cfg["slack_s"]
        return int(max(self.cfg["min_timeout_s"], min(self.cfg["max_timeout_s"], t)))

    def retry_timeout(self, first: int) -> int:
        t = first * self.cfg["retry_factor"]
        t = min(t, first + 1800)                      # at most +30 min for the retry
        return int(min(self.cfg["max_timeout_s"] * 1.5, max(t, first + 60)))

    def estimate_total(self, plugins: List[str], engine: str, os_type: str,
                       size_gb: float, jobs: int) -> Tuple[float, Dict[str, float]]:
        """Wall-clock ETA for a batch run on `jobs` parallel workers
        (longest-processing-time-first schedule)."""
        per = {p: self.expected(p, engine, os_type, size_gb) for p in plugins}
        lanes = [0.0] * max(1, jobs)
        for p, d in sorted(per.items(), key=lambda x: -x[1]):
            i = lanes.index(min(lanes))
            lanes[i] += d
        return max(lanes) if lanes else 0.0, per

    # ----------------------------------------------------------------- record
    def record(self, plugin: str, engine: str, os_type: str, size_gb: float,
               duration: float, ok: bool, timed_out: bool, timeout_s: int = 0) -> None:
        # tests / stub engines and tiny fixture images must not skew calibration
        if os.environ.get("RAMBREAKER_NO_CALIBRATION") == "1" or size_gb < 0.05:
            return
        rec = {"plugin": plugin, "engine": engine, "os": (os_type or "windows").lower(),
               "size_gb": round(size_gb, 3), "duration": round(duration, 2), "ok": ok,
               "timed_out": timed_out, "timeout_s": timeout_s, "fmt": self.fmt,
               "cpus": os.cpu_count(), "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
        try:
            with _lock, open(self.samples_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            pass

    def maybe_refit(self) -> bool:
        """Re-fit when runtimes were recorded since the last fit, so every run
        (incl. timeouts = censored lower bounds) calibrates the next one."""
        n = len(self.load_samples())
        if n and n != self.cfg.get("fitted_from_samples"):
            with _lock:
                self.fit()
            return True
        return False

    # -------------------------------------------------------------------- fit
    def load_samples(self) -> List[Dict[str, Any]]:
        out = []
        if self.samples_path.is_file():
            for line in self.samples_path.read_text(encoding="utf-8").splitlines():
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
        return out

    @staticmethod
    def _fit_line(pts: List[Tuple[float, float]], share: float) -> Tuple[float, float]:
        """Non-negative least squares y = a + b x; data from (nearly) one size is
        split by `share`. Sizes spanning < 2x carry no usable slope: with 1.5 and
        2.0 GB Windows dumps the slower small one gave a NEGATIVE slope -> 0 s/GB,
        and a 34.5 GB dump got the same 120 s budget as a 2 GB one."""
        xs = [x for x, _ in pts]
        ys = [y for _, y in pts]
        if max(xs) < 2 * max(min(xs), 0.05):
            y = statistics.median(ys)
            x = max(statistics.median(xs), 0.1)
            return share * y, (1 - share) * y / x
        mx, my = statistics.fmean(xs), statistics.fmean(ys)
        sxx = sum((x - mx) ** 2 for x in xs)
        b = sum((x - mx) * (y - my) for x, y in pts) / sxx if sxx else 0.0
        b = max(0.0, b)
        a = my - b * mx
        if a < 0:                       # NNLS: intercept pinned at 0 -> refit slope
            a = 0.0
            b = sum(x * y for x, y in pts) / max(sum(x * x for x in xs), 1e-9)
        return a, b

    def _fit_formats(self, by_fmt: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """ratio = measured / raw-model estimate, per plugin (median of OK runs,
        raised to the largest timed-out lower bound); default = median ratio."""
        out = {}
        for f, ss in by_fmt.items():
            per: Dict[str, Dict[str, List[float]]] = {}
            for s in ss:
                k = _key(s["plugin"], s["engine"], s["os"])
                raw = max(1.0, self._expected_raw(s["plugin"], s["engine"], s["os"], s["size_gb"]))
                d = per.setdefault(k, {"ok": [], "cens": []})
                if s.get("ok"):
                    d["ok"].append(s["duration"] / raw)
                else:
                    d["cens"].append(max(s["duration"], s.get("timeout_s") or 0) / raw)
            plugs = {}
            for k, d in per.items():
                r = statistics.median(d["ok"]) if d["ok"] else 0.0
                if d["cens"] and max(d["cens"]) > r:
                    r = max(d["cens"])
                plugs[k] = {"ratio": round(max(r, 0.05), 3), "n": len(d["ok"]) + len(d["cens"]),
                            "n_timeouts": len(d["cens"]),
                            "censored_only": bool(d["cens"]) and not d["ok"]}
            rs = [v["ratio"] for v in plugs.values() if not v["censored_only"]]
            out[f] = {"plugins": plugs, "default_ratio": round(max(1.0, statistics.median(rs)), 3)
                      if rs else 1.0, "n_samples": len(ss)}
        return out

    def fit(self) -> Dict[str, Any]:
        samples = self.load_samples()
        groups: Dict[str, List[Dict[str, Any]]] = {}
        other_fmt: Dict[str, List[Dict[str, Any]]] = {}
        for s in samples:
            if not (s.get("ok") or s.get("timed_out")):
                continue                     # crashed runs say nothing about cost
            if (s.get("fmt") or "raw") != "raw":
                other_fmt.setdefault(s["fmt"], []).append(s)
                continue
            groups.setdefault(_key(s["plugin"], s["engine"], s["os"]), []).append(s)
        # intercept share from plugins measured at >=2 sizes (else 0.3)
        shares = []
        for k, ss in groups.items():
            pts = [(s["size_gb"], s["duration"]) for s in ss if s.get("ok")]
            if pts and max(x for x, _ in pts) >= 2 * max(min(x for x, _ in pts), 0.05):
                a, b = self._fit_line(pts, 0.3)
                tot = a + b * statistics.fmean(x for x, _ in pts)
                if tot > 0:
                    shares.append(a / tot)
        share = statistics.median(shares) if shares else 0.3
        plugins = {}
        for k, ss in groups.items():
            pts = [(s["size_gb"], s["duration"]) for s in ss if s.get("ok")]
            # v2.4: a timeout that was FOLLOWED by a successful, faster run of the same
            # plugin on a dump of the same size (+-10 %) is superseded - its cause was
            # fixed or was a one-off (linux.malfind: one 3,599 s timeout from before a
            # Volatility fix kept the estimate at ~1 h for a 2-minute plugin).
            oks = [s for s in ss if s.get("ok")]

            def _superseded(t):
                lim = max(t["duration"], t.get("timeout_s") or 0)
                return any(o.get("ts", "") > t.get("ts", "") and o["duration"] < lim
                           and abs(o["size_gb"] - t["size_gb"]) <= 0.1 * max(t["size_gb"], 0.1)
                           for o in oks)
            cens = [(s["size_gb"], max(s["duration"], s.get("timeout_s") or 0))
                    for s in ss if s.get("timed_out") and not _superseded(s)]
            if pts:
                a, b = self._fit_line(pts, share)
            else:
                a, b = 0.0, 0.0
            # right-censored: expectation must exceed what already timed out
            # Inside the measured size range the deficit lifts the base (cost is
            # driven by process/mapping count more than by dump size, so a slow
            # small image must not inflate the per-GB slope for big ones);
            # beyond it, the slope is raised to reach the censored point.
            max_ok_x = max((x for x, _ in pts), default=0.0)
            for x, y in sorted(cens):
                if a + b * x < y:
                    # strictly smaller than the largest measured size -> base;
                    # at/above it -> slope (an HDD timeout at 34.5 GB must not
                    # give a 2 GB dump a 20-min psscan budget)
                    if pts and x < max_ok_x - 0.05:
                        a = y - b * x
                    else:
                        b = max(b, (y - a) / max(x, 0.1))
            plugins[k] = {"base_s": round(a, 2), "per_gb_s": round(b, 2),
                          "n": len(ss), "n_timeouts": len(cens),
                          "censored_only": bool(cens) and not pts,
                          "max_observed_s": round(max([y for _, y in pts + cens] or [0]), 1),
                          "sizes_gb": sorted({round(x, 2) for x, _ in pts + cens})}
        classes: Dict[str, List[Tuple[float, float]]] = {}
        for k, m in plugins.items():
            eng, osn, plug = k.split("|", 2)
            for kk in (f"{eng}|{osn}|{cost_class(plug)}", f"{eng}|*|{cost_class(plug)}"):
                classes.setdefault(kk, []).append((m["base_s"], m["per_gb_s"]))
        cls_out = {k: {"base_s": round(statistics.median(a for a, _ in v), 2),
                       "per_gb_s": round(statistics.median(b for _, b in v), 2),
                       "n_plugins": len(v)} for k, v in classes.items()}
        self.cfg["plugins"] = plugins
        self.cfg["classes"] = cls_out
        self.cfg["formats"] = self._fit_formats(other_fmt)
        self.cfg["intercept_share"] = round(share, 3)
        self.cfg["fitted_from_samples"] = len(samples)
        self.cfg["fitted_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.cfg["formula"] = ("timeout = clamp(safety_factor * (base_s + per_gb_s * dump_GB) "
                               "* format_ratio + slack_s, min_timeout_s, max_timeout_s); retry "
                               "once at timeout * retry_factor; format_ratio = 1 for raw images, "
                               "formats.<fmt>.plugins.<key>.ratio (or default_ratio) otherwise")
        self.model_path.write_text(json.dumps(self.cfg, indent=2, sort_keys=True),
                                   encoding="utf-8")
        return self.cfg


def import_run_log(model: "TimeoutModel", log_path: Path, image: str,
                   os_type: str) -> int:
    """Back-fill samples from a finished run's crescent_toolkit.log.

    Vol3: '[k/N] <plugin> completed (Xs)' / '<plugin> timed out after Ns'.
    Vol2 runs serially in one background thread, so a Vol2 plugin's
    duration = next Vol2 'Running' timestamp - its own (dot-less names)."""
    import re as _re
    size = image_size_gb(image)
    model.fmt = image_profile(image)
    txt = Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines()
    ts = lambda l: (lambda m: int(m[1]) * 3600 + int(m[2]) * 60 + int(m[3]) if m else None)(
        _re.match(r"\[(\d\d):(\d\d):(\d\d)\]", l))
    n = 0
    v2: List[Tuple[int, str]] = []
    timed_out = set()
    for l in txt:
        m = _re.search(r"\] (\S+) completed \(([\d.]+)s\)", l)
        if m and "." in m.group(1):
            model.record(m.group(1), "vol3", os_type, size, float(m.group(2)), True, False)
            n += 1
            continue
        m = _re.search(r"\] (\S+) timed out after (\d+)s", l)
        if m:
            timed_out.add(m.group(1))
            if "." in m.group(1):
                model.record(m.group(1), "vol3", os_type, size, float(m.group(2)), False,
                             True, int(m.group(2)))
                n += 1
        m = _re.search(r"Running ([a-z0-9_]+) \.\.\.", l)
        if m and ts(l) is not None:
            v2.append((ts(l), m.group(1)))
    for i, (t, p) in enumerate(v2):
        if i + 1 < len(v2):
            d = (v2[i + 1][0] - t) % 86400
        else:
            continue  # last one: no end marker
        to = p in timed_out
        model.record(p, "vol2", os_type, size, float(d), not to, to, int(d) if to else 0)
        n += 1
    return n


def log_eta(log, plugins: List[str], engine: str, os_type: str, image: str,
            jobs: int) -> float:
    """Log (and return) the estimated wall time before a batch starts."""
    try:
        m = get_model()
        try:
            if m.maybe_refit():
                log.info("Timing model re-calibrated from %d recorded plugin runtimes",
                         m.cfg.get("fitted_from_samples", 0))
        except Exception as e:  # calibration must never block a run
            log.debug("timing model refit skipped: %s", e)
        size = image_size_gb(image)
        total, per = m.estimate_total(plugins, engine, os_type, size, jobs)
        slow = sorted(per.items(), key=lambda x: -x[1])[:3]
        try:
            from modules import progress
            progress.emit("batch", plugins=plugins, engine=engine, jobs=jobs,
                          eta_s=round(total, 1),
                          expected={p: round(d, 1) for p, d in per.items()})
        except Exception:
            pass
        log.info("ETA: ~%s for %d plugins on a %.1f GB %s image with %d parallel jobs "
                 "(slowest: %s) - from the calibrated timing model",
                 _fmt(total), len(plugins), size, os_type, jobs,
                 ", ".join(f"{p.split('.')[-1]} ~{_fmt(d)}" for p, d in slow))
        return total
    except Exception as e:
        log.debug("ETA unavailable: %s", e)
        return 0.0


def _fmt(s: float) -> str:
    s = int(s)
    return f"{s // 3600}h{(s % 3600) // 60:02d}m" if s >= 3600 else \
        (f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s")


_MODEL: Optional[TimeoutModel] = None


def get_model() -> TimeoutModel:
    global _MODEL
    if _MODEL is None:
        _MODEL = TimeoutModel()
    return _MODEL


def image_format(image: str) -> str:
    """'crashdump' for Windows kernel/complete crash dumps, else 'raw'."""
    try:
        with open(image, "rb") as f:
            h = f.read(8)
    except OSError:
        return "raw"
    return "crashdump" if h in (b"PAGEDU64", b"PAGEDUMP") else "raw"


def image_profile(image: str) -> str:
    """Format + I/O class the runtime depends on: 'raw', 'crashdump', and a
    '+hdd' suffix when the image is on a spinning disk AND bigger than free RAM
    (it cannot stay in the page cache, so every scan re-reads the disk: Win11
    psscan 185 s from NVMe vs > 635 s from the HDD). Same rule as
    platform_compat.io_limited_jobs."""
    fmt = image_format(image)
    try:
        from modules import platform_compat as pc
        if pc.storage_is_rotational(image) is True:
            if os.path.getsize(image) / (1024 ** 3) > (pc.available_ram_gb() or 0.0):
                fmt += "+hdd"
    except Exception:
        pass
    return fmt


def image_size_gb(image: str) -> float:
    """Size in GB; also tells the shared model which image profile it estimates for."""
    try:
        get_model().fmt = image_profile(image)
    except Exception:
        pass
    try:
        return os.path.getsize(image) / (1024 ** 3)
    except OSError:
        return 1.0
