"""extractor.windows.py — Windows-specific Volatility plugin runner (v6.0)

Extracted from extractor.py for OS-specific split architecture.
Contains Windows PLUGINS, VOL2_EXCLUSIVE, VOL2_XP_ONLY, and the full
Extractor class including _run_targeted_printkey and _run_vol2_exclusive.
"""

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, Future, FIRST_COMPLETED, wait
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from modules.volatility import VolatilityWrapper, vol2_done
from modules.dep_gate import DependencyGate, failure_kind, is_hard_failure
from utils.json_converter import convert_json_to_txt
from modules.platform_compat import split_cmd

PLUGINS: Dict[str, str] = {
    "vol3-windows-fast": "windows.info.Info windows.pslist.PsList windows.pstree.PsTree windows.cmdline.CmdLine windows.netscan.NetScan windows.malfind.Malfind windows.svcscan.SvcScan windows.hashdump.Hashdump windows.registry.hivelist.HiveList windows.registry.printkey.PrintKey windows.filescan.FileScan",
    "vol3-windows-full": "windows.info.Info windows.pslist.PsList windows.psscan.PsScan windows.pstree.PsTree windows.cmdline.CmdLine windows.dlllist.DllList windows.handles.Handles windows.getsids.GetSIDs windows.envars.Envars windows.privileges.Privs windows.sessions.Sessions windows.ldrmodules.LdrModules windows.netstat.NetStat windows.netscan.NetScan windows.malfind.Malfind windows.ssdt.SSDT windows.callbacks.Callbacks windows.registry.hivelist.HiveList windows.registry.hivescan.HiveScan windows.registry.userassist.UserAssist windows.registry.printkey.PrintKey windows.svcscan.SvcScan windows.driverscan.DriverScan windows.driverirp.DriverIrp windows.modules.Modules windows.modscan.ModScan windows.filescan.FileScan windows.mftscan.MFTScan windows.vadinfo.VadInfo windows.mutantscan.MutantScan windows.symlinkscan.SymlinkScan windows.thrdscan.ThrdScan windows.hashdump.Hashdump",
    "vol3-windows-malware": "windows.info.Info windows.pslist.PsList windows.psscan.PsScan windows.pstree.PsTree windows.cmdline.CmdLine windows.malfind.Malfind windows.ssdt.SSDT windows.callbacks.Callbacks windows.ldrmodules.LdrModules windows.driverscan.DriverScan windows.driverirp.DriverIrp windows.modules.Modules windows.handles.Handles windows.hashdump.Hashdump",
    "vol3-windows-network": "windows.info.Info windows.pslist.PsList windows.pstree.PsTree windows.cmdline.CmdLine windows.netscan.NetScan windows.netstat.NetStat windows.svcscan.SvcScan",
    "vol3-windows-persistence": "windows.info.Info windows.pslist.PsList windows.pstree.PsTree windows.cmdline.CmdLine windows.registry.hivelist.HiveList windows.registry.userassist.UserAssist windows.registry.printkey.PrintKey windows.svcscan.SvcScan windows.driverscan.DriverScan windows.modules.Modules windows.callbacks.Callbacks windows.ssdt.SSDT windows.envars.Envars windows.hashdump.Hashdump",
    "vol3-windows-registry": "windows.registry.hivelist.HiveList windows.registry.hivescan.HiveScan windows.registry.userassist.UserAssist windows.registry.printkey.PrintKey",
    "vol2-windows-fast": "imageinfo pslist pstree psscan cmdline cmdscan consoles netscan connections connscan malfind svcscan hashdump hivelist printkey filescan",
    "vol2-windows-full": "imageinfo pslist psscan pstree psxview cmdline cmdscan consoles dlllist handles getsids envars privs sessions ldrmodules netscan netstat connections connscan sockets sockscan malfind ssdt callbacks driverirp driverscan modules modscan filescan mutantscan symlinkscan hivelist userassist shellbags shimcache mftparser svcscan timers atoms atomscan clipboard deskscan messagehooks eventhooks thrdscan vadinfo iehistory hashdump",
    "vol2-windows-malware": "imageinfo pslist psscan pstree psxview cmdline cmdscan consoles malfind ssdt callbacks apihooks ldrmodules driverirp driverscan modules modscan privs vadinfo handles timers hashdump",
    "vol2-windows-network": "imageinfo pslist pstree cmdline cmdscan consoles netscan netstat connections connscan sockets sockscan svcscan",
    "vol2-windows-persistence": "imageinfo pslist pstree cmdline cmdscan consoles hivelist userassist printkey shellbags shimcache svcscan driverscan modules callbacks ssdt envars",
    "vol2-windows-registry": "hivelist hivedump printkey userassist shellbags shimcache",
}

VOL2_EXCLUSIVE = "cmdscan consoles hashdump shellbags shimcache iehistory clipboard deskscan atoms atomscan timers messagehooks eventhooks apihooks"
VOL2_XP_ONLY = "connections connscan sockets sockscan"
VOL2_FAST = {"cmdscan", "consoles", "hashdump", "clipboard", "iehistory"}
VOL2_SLOW = {"timers", "apihooks"}
VALID_MODES = ("fast", "full", "malware", "network", "persistence", "registry")

# parent -> plugins that read the parent's structures and are skipped when the
# parent FAILS (not on a timeout; see modules/dep_gate.py). Scanners that are the
# fallback for a broken list walk are deliberately NOT here: psscan / psxview
# (pslist), modscan (modules) must run exactly when the walk fails.
# windows.netstat builds its tables with netscan's code (one-way dependency).
DEPENDENCIES: Dict[str, Set[str]] = {
    "pslist": {"pstree", "cmdline", "dlllist",
               "handles", "getsids", "envars", "privileges", "sessions",
               "ldrmodules", "malfind", "vadinfo"},
    "netscan": {"netstat"},
    "hivelist": {"userassist", "printkey", "shellbags", "shimcache"},
}


def _short_name(plugin: str) -> str:
    parts = plugin.lower().replace("windows.", "").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


class Extractor:
    """Parallel Volatility plugin runner for Windows images."""

    def __init__(self, vol: VolatilityWrapper, logger: logging.Logger,
                 jobs: int = 4, speed: str = "normal"):
        self.vol = vol
        self.log = logger
        self.jobs = max(1, min(16, jobs))
        self.speed = speed if speed in ("normal", "fast", "fastest") else "normal"
        self._failed_parents: Set[str] = set()
        self._symbol_fix_attempted = False

    def _adaptive_jobs(self, image: str) -> int:
        speed = getattr(self, "speed", "normal")
        if speed == "fastest":
            self.log.info("FASTEST mode: %d jobs (RAM guard OFF, threading disabled)",
                          self.jobs)
            return self.jobs
        avail_gb = None
        from modules.platform_compat import available_ram_gb
        avail_gb = available_ram_gb()  # /proc/meminfo or GlobalMemoryStatusEx
        if not avail_gb:
            return self.jobs
        per_job_gb = 1.0 if speed == "fast" else 1.5
        safe_jobs = max(1, int((avail_gb - 1.0) / per_job_gb))
        if safe_jobs < self.jobs:
            self.log.info("Adaptive jobs: %d → %d (%.1fGB RAM, ~%.1fGB/job, %s mode)",
                          self.jobs, safe_jobs, avail_gb, per_job_gb, speed)
            return safe_jobs
        return self.jobs

    def _warm_cache(self, image: str):
        # Delegate to the shared, progress-aware warmer. It checks the actual
        # SQLite `cache` table — not mere file presence: valid_isf.hashcache is
        # always there, so the old "any files exist?" check skipped warming while
        # the cache was still cold, then the parallel jobs below all raced on the
        # half-built cache and corrupted it. The shared warmer also waits on real
        # progress (no fixed timeout) and reads via temp files (no pipe deadlock).
        from modules import linux_identify
        # 1. Warm Vol3's generic ISF file-index cache (symbol-free, via banners).
        linux_identify.warm_isf_cache(self.vol.vol3_cmd, image, self.log)
        # 2. Windows: also SERIALLY establish this image's kernel symbol table
        #    before the parallel batch launches. The ISF file-index warm above
        #    does NOT build the per-image kernel PDB symbol table — that is built
        #    lazily by the first symbol-dependent plugin. On a cold image the
        #    first parallel batch (info/pslist/psscan/pstree) all trigger that
        #    build at once, race, and all fail 'kernel.symbol_table_name' while
        #    one wins and writes the cache (every later plugin then succeeds).
        #    Doing it once, alone, up front makes every plugin a cache hit.
        if self.vol.os_type == "windows":
            linux_identify.warm_windows_kernel_symbols(
                self.vol.vol3_cmd, image, self.log)

    # Plugins whose whole-image output can be produced per process on demand
    # (Extraction workspace > Memory regions > List regions). When the calibrated
    # model predicts more than ON_DEMAND_MAX_S for this dump they are not run up
    # front: windows.vadinfo ran > 89 min on the 34.5 GB Win11 image and still
    # timed out, delaying the whole report for a raw table.
    ON_DEMAND = ("windows.vadinfo.VadInfo",)
    ON_DEMAND_MAX_S = 1800

    def _on_demand_filter(self, plugins, image):
        try:
            from modules import timeout_model as _tm
            m = _tm.get_model()
            gb = _tm.image_size_gb(image)
        except Exception:
            return plugins
        keep = []
        for p in plugins:
            if p in self.ON_DEMAND:
                exp = m.expected(p, self.vol.vol_version or "vol3", self.vol.os_type, gb)
                if exp > self.ON_DEMAND_MAX_S:
                    self.log.info(
                        "Not running %s up front: predicted ~%d min for this %.1f GB dump. "
                        "Its data is available per process on demand (Extraction > Memory "
                        "regions > List regions).", p, exp // 60, gb)
                    try:
                        from modules import progress as _pg
                        _pg.info(f"{p.split('.')[1]} is skipped for this large dump (~{int(exp // 60)} min); "
                                 "list a process's memory regions on demand in the Extraction workspace")
                    except Exception:
                        pass
                    continue
            keep.append(p)
        return keep

    def run(self, image: str, output_dir: Path, mode: str = "full",
            skip_existing: bool = True) -> Dict[str, Any]:
        if mode not in VALID_MODES:
            self.log.warning("Unknown mode '%s', defaulting to 'full'", mode)
            mode = "full"
        self._mode = mode

        key = f"{self.vol.vol_version}-{self.vol.os_type}-{mode}"
        plugin_str = PLUGINS.get(key, PLUGINS.get(
            f"{self.vol.vol_version}-windows-full", ""))
        plugins = plugin_str.split()
        plugins = self._on_demand_filter(plugins, image)
        try:
            from modules import timeout_model as _tm
            from modules.platform_compat import io_limited_jobs as _ilj
            _tm.log_eta(self.log, plugins, self.vol.vol_version, self.vol.os_type, image,
                        self.jobs if getattr(self, "speed", "normal") == "fastest" else _ilj(image, self.jobs))
        except Exception:
            pass

        self.log.info("Starting extraction: %d plugins (%s - %s mode, %d parallel jobs)",
                      len(plugins), self.vol.vol_version, mode, self.jobs)

        actual_jobs = self._adaptive_jobs(image)
        if getattr(self, "speed", "normal") != "fastest":
            from modules.platform_compat import io_limited_jobs
            actual_jobs = io_limited_jobs(image, actual_jobs, self.log)

        jd = output_dir / "json"
        jd.mkdir(parents=True, exist_ok=True)

        if self.vol.vol_version == "vol3":
            self._warm_cache(image)

        _BAD_MARKERS = (
            "unsatisfied requirement",
            "traceback (most recent call last)",
            "volatility.framework.exceptions",
            "a translation layer requirement was not fulfilled",
            "a symbol table requirement was not fulfilled",
            "exception: ",
        )
        to_run, skipped = [], 0
        resumed_plugins = []
        for p in plugins:
            if skip_existing:
                exp = self._expected_json(p)
                jp = jd / exp
                # A '<name>.json.error' sidecar means the previous run of this
                # plugin failed (including a silent/demoted failure) — re-run it,
                # don't trust the stale/partial JSON left behind.
                if (jd / (exp + ".error")).exists():
                    self.log.info("Resume: re-running %s (previous run failed)", p)
                elif jp.exists() and jp.stat().st_size > 10:
                    try:
                        content = jp.read_text(
                            encoding="utf-8", errors="ignore")[:2000].lower()
                        if not any(m in content for m in _BAD_MARKERS):
                            skipped += 1
                            resumed_plugins.append(p)
                            continue
                        else:
                            self.log.info(
                                "Resume: re-running %s (existing output "
                                "contains failure marker)", p)
                    except Exception:
                        pass
            to_run.append(p)

        if resumed_plugins:
            self.log.info("Resume: skipping %d plugins with valid existing output",
                          len(resumed_plugins))
            try:                      # GUI: show them as done (earlier run), not 'queued'
                from modules import progress as _pgr
                for _rp in resumed_plugins:
                    _pgr.emit("plugin", plugin=_rp, state="cached")
            except Exception:
                pass

        total = len(to_run)
        ok = fail = dep_skipped = 0
        start = time.time()
        self._failed_parents = set()
        # Plugins that fail purely because the kernel symbol table wasn't ready
        # yet (cold-start race in the first parallel batch). By the time the batch
        # finishes, symbols ARE built, so we re-run just these serially — a
        # self-healing net in case the up-front warm-up was skipped or couldn't
        # confirm. Belt-and-suspenders with warm_windows_kernel_symbols().
        symbol_retry: List[str] = []

        vol2_future: Optional[Future] = None
        vol2_pool = None
        if (self.vol.vol_version == "vol3" and self.vol.vol2_cmd
                and self.vol.profile and not self._should_skip_vol2()):
            vol2_pool = ThreadPoolExecutor(max_workers=1)
            vol2_future = vol2_pool.submit(
                self._run_vol2_exclusive, image, output_dir)
            self.log.info("Vol2-exclusive plugins started in background (parallel)")

        # v2.4.1: dependents wait for their parent (modules/dep_gate.py). Before,
        # every plugin was submitted up front, so a failed parent never skipped anything.
        gate = DependencyGate(to_run, DEPENDENCIES, _short_name)
        with ThreadPoolExecutor(max_workers=actual_jobs) as pool:
            futures = {}
            for p in gate.initial():
                futures[pool.submit(self.vol.run_plugin, image, p, output_dir)] = p

            completed = 0
            while futures:
                done, _ = wait(list(futures), return_when=FIRST_COMPLETED)
                for future in done:
                    plug = futures.pop(future)
                    completed += 1
                    actual_total = len(to_run) - dep_skipped
                    res = None
                    try:
                        res = future.result()
                        if res["success"]:
                            ok += 1
                            self.log.info("[%d/%d] %s completed (%.1fs)",
                                          completed, actual_total, plug, res["duration"])
                        else:
                            fail += 1
                            short = _short_name(plug)
                            error_msg = res.get("error", "")
                            _elow = error_msg.lower()
                            if (self.vol.vol_version == "vol3"
                                    and ("symbol_table_name" in _elow
                                         or "symbol table requirement" in _elow)):
                                symbol_retry.append(plug)
                            if short in DEPENDENCIES and is_hard_failure(res):
                                self._failed_parents.add(short)
                                self.log.warning(
                                    "[%d/%d] %s FAILED (will skip dependents: %s): %s",
                                    completed, actual_total, plug,
                                    ", ".join(sorted(DEPENDENCIES[short])),
                                    error_msg[:150])
                            elif short in DEPENDENCIES:
                                self.log.warning(
                                    "[%d/%d] %s FAILED (%s; its dependents still run): %s",
                                    completed, actual_total, plug, failure_kind(res),
                                    error_msg[:150])
                            else:
                                self.log.warning("[%d/%d] %s FAILED: %s",
                                                 completed, actual_total, plug,
                                                 error_msg[:200])
                            if (not self._symbol_fix_attempted
                                    and "unsatisfied requirement" in error_msg.lower()
                                    and self.vol.vol_version == "vol3"):
                                self._try_symbol_download(image)
                    except Exception as exc:
                        fail += 1
                        self.log.error("[%d/%d] %s exception: %s",
                                       completed, actual_total, plug, exc)
                    release, skips = gate.finished(plug, is_hard_failure(res))
                    for child, parent in skips:
                        dep_skipped += 1
                        self.log.info("[SKIP] %s — dependency '%s' failed", child, parent)
                        try:              # GUI: 'skipped (dependency)' + retry button
                            from modules import progress as _pgs
                            _pgs.emit("plugin", plugin=child, state="skipped", parent=parent)
                        except Exception:
                            pass
                    for child in release:
                        futures[pool.submit(self.vol.run_plugin, image, child, output_dir)] = child

        # --- Self-healing: retry symbol-table casualties serially ---
        # If any plugin failed only because the kernel symbol table wasn't ready
        # (cold-start race), it will succeed now that the table is built. Re-run
        # them one at a time (no race) and fold the recoveries into the counts.
        if symbol_retry:
            self.log.info("Retrying %d plugin(s) that failed on a cold kernel "
                          "symbol table (serial, symbols now warm): %s",
                          len(symbol_retry), ", ".join(symbol_retry))
            for plug in symbol_retry:
                try:
                    res = self.vol.run_plugin(image, plug, output_dir)
                except Exception as exc:
                    self.log.error("Serial retry %s exception: %s", plug, exc)
                    continue
                if res.get("success"):
                    ok += 1
                    fail -= 1
                    self._failed_parents.discard(_short_name(plug))
                    self.log.info("Serial retry recovered %s (%.1fs)",
                                  plug, res.get("duration", 0.0))
                else:
                    self.log.warning("Serial retry %s still failed: %s",
                                     plug, res.get("error", "")[:150])

        v2ok = v2f = 0
        if vol2_future is not None:
            try:
                # No global cap: every Vol2 plugin already has its own timeout,
                # so the batch is bounded; a flat 600s join silently dropped
                # the Vol2 counts on slower images.
                self.log.info("Waiting for the background Vol2 batch to finish...")
                v2ok, v2f = vol2_future.result()
            except Exception as e:
                self.log.error("Vol2 background task failed: %r", e)
            finally:
                vol2_pool.shutdown(wait=False)
        elif (self.vol.vol_version == "vol3" and self.vol.vol2_cmd
              and self.vol.profile and not self._should_skip_vol2()):
            v2ok, v2f = self._run_vol2_exclusive(image, output_dir)

        dur = time.time() - start
        self.log.info("Main scan: %d OK, %d failed, %d skipped, %d dep-skipped (%.1fs)",
                      ok, fail, skipped, dep_skipped, dur)

        if self.vol.os_type == "windows":
            self._run_targeted_printkey(image, output_dir)

        self.log.info("Converting JSON to TXT...")
        td = output_dir / "txt"
        c_ok, c_f = convert_json_to_txt(jd, td)
        self.log.info("Converted %d JSON to TXT (%d failed)", c_ok, c_f)

        return {"ok": ok + v2ok, "fail": fail + v2f,
                "skipped": skipped, "dep_skipped": dep_skipped,
                "duration": time.time() - start,
                "json_count": len(list(jd.glob("*.json"))),
                "txt_count": len(list(td.glob("*.txt")))}

    _PERSISTENCE_KEY_PATHS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"SYSTEM\CurrentControlSet\Services",
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        r"SYSTEM\CurrentControlSet\Control\Session Manager",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppInit_DLLs",
        r"SOFTWARE\Classes\Exefile\Shell\Open\Command",
    ]

    def _run_targeted_printkey(self, image: str, output_dir: Path):
        """Run printkey with --key for each persistence path."""
        import json as _json, subprocess as _sp, time as _time
        jd = output_dir / "json"
        combined: list = []

        vol_cmd = (self.vol.vol3_cmd if self.vol.vol_version == "vol3"
                   else self.vol.vol2_cmd)
        if not vol_cmd:
            return

        merged_path = jd / "printkey_persistence_merged.json"
        if merged_path.exists():
            try:
                combined = _json.loads(merged_path.read_text(encoding="utf-8"))
                if combined:
                    self.log.info("Targeted printkey: loaded %d cached entries", len(combined))
                    return
            except Exception:
                pass

        self.log.info("Targeted printkey: scanning %d persistence key paths...",
                      len(self._PERSISTENCE_KEY_PATHS))

        for key_path in self._PERSISTENCE_KEY_PATHS:
            safe = key_path.replace("\\", "_").replace(" ", "_")
            out_path = jd / f"printkey_targeted_{safe}.json"

            if out_path.exists() and out_path.stat().st_size > 10:
                try:
                    data = _json.loads(out_path.read_text(encoding="utf-8", errors="ignore"))
                    if isinstance(data, list):
                        combined.extend(data)
                        continue
                except Exception:
                    pass

            if self.vol.vol_version == "vol3":
                cmd = (split_cmd(vol_cmd) +
                       ["-f", image, "-r", "json",
                        "windows.registry.printkey.PrintKey",
                        "--key", key_path])
            else:
                cmd = (split_cmd(vol_cmd) +
                       ["-f", image, "--profile", self.vol.profile or "",
                        "--output=json", "printkey",
                        "--key", key_path])

            try:
                t0 = _time.time()
                proc = _sp.run(cmd, capture_output=True, text=True, timeout=60)
                json_line = next(
                    (l for l in proc.stdout.splitlines()
                     if l.strip().startswith("{") or l.strip().startswith("[")),
                    None)
                output = json_line.strip() if json_line else ""
                if proc.returncode == 0 and len(output) > 5:
                    try:
                        data = _json.loads(output)
                        if isinstance(data, dict) and "rows" in data and "columns" in data:
                            cols = data["columns"]
                            structured = []
                            for row in data["rows"]:
                                rd = dict(zip(cols, row))
                                if rd.get("ValType", "-") != "-":
                                    structured.append({
                                        "Key":        key_path,
                                        "Hive":       rd.get("Registry", ""),
                                        "Value Name": rd.get("ValName", ""),
                                        "Type":       rd.get("ValType", ""),
                                        "Data":       rd.get("ValData", "").rstrip('\x00'),
                                    })
                            data = structured
                        if isinstance(data, list) and data:
                            out_path.write_text(_json.dumps(data, indent=2),
                                                encoding="utf-8")
                            combined.extend(data)
                            self.log.debug("printkey --key %s: %d entries (%.1fs)",
                                           key_path, len(data), _time.time() - t0)
                    except Exception:
                        pass
            except (_sp.TimeoutExpired, Exception) as e:
                self.log.debug("printkey --key %s: %s", key_path, e)

        if combined:
            merged_path.write_text(_json.dumps(combined, indent=2, default=str),
                                   encoding="utf-8")
            self.log.info("Targeted printkey: %d total entries → %s",
                          len(combined), merged_path)

    def _should_skip_vol2(self) -> bool:
        p = (self.vol.profile or "").lower()
        return any(x in p for x in ("win10", "win11", "win8",
                                     "win2016", "win2019", "win2022"))

    def _try_symbol_download(self, image: str):
        self._symbol_fix_attempted = True
        self.log.info("Symbols missing — attempting Vol3 auto-download...")
        self.log.info("Running windows.info.Info to trigger PDB download...")
        try:
            rc, out, err = self.vol._run_raw(
                self.vol.vol3_cmd, image, "windows.info.Info", 120)
            if rc == 0 and "NTBuildLab" in out:
                self.log.info("Symbol download succeeded! Subsequent plugins should work.")
            else:
                self.log.warning("Symbol auto-download did not resolve the issue.")
                self.log.info("Download manually: https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip")
        except Exception as e:
            self.log.error("Symbol download attempt failed: %s", e)

    def _run_vol2_exclusive(self, image, output_dir):
        """Run Vol2-exclusive plugins. Called from background thread or sequentially."""
        if self.vol.vol_version != "vol3" or not self.vol.vol2_cmd or not self.vol.profile:
            return 0, 0
        if self._should_skip_vol2():
            self.log.info("Win10/11 profile (%s) -- skipping Vol2-exclusive plugins",
                          self.vol.profile)
            return 0, 0
        if not self.vol.check_vol2_compatibility(output_dir):
            self.log.info("Win10/11 detected -- skipping Vol2-exclusive plugins")
            return 0, 0

        plugs = VOL2_EXCLUSIVE.split()
        if getattr(self, "_mode", "full") == "fast":
            # Quick triage: only the cheap, high-value Vol2 extras. The GUI
            # object scans (atoms/deskscan/timers/hooks) are slow and niche;
            # Vol2 `timers` alone ran >10 min on a 2 GB Win7 image.
            plugs = [p for p in plugs if p in VOL2_FAST]
            self.log.info("Fast mode: Vol2 extras limited to %s", ", ".join(plugs))
        if os.environ.get("RAMBREAKER_VOL2_SLOW") != "1":
            # Measured on a 2 GB Win7 image: timers 728 s (empty), apihooks
            # >300 s twice. They only run in the Full DFIR preset.
            slow = [p for p in plugs if p in VOL2_SLOW]
            if slow:
                plugs = [p for p in plugs if p not in VOL2_SLOW]
                self.log.info("Skipping slow Vol2 extras (Full DFIR preset runs them): %s",
                              ", ".join(slow))
        p_lower = (self.vol.profile or "").lower()
        if any(x in p_lower for x in ("xp", "2003", "win2003")):
            plugs += VOL2_XP_ONLY.split()
            self.log.info("XP/2003 profile — including network plugins (connections, sockets)")

        jd = output_dir / "json"
        to_run = []
        for p in plugs:
            exp = self._expected_json(p)
            if vol2_done(jd / exp):
                continue
            to_run.append(p)

        if len(to_run) < len(plugs):
            self.log.info("Vol2 resume: skipping %d already completed", len(plugs) - len(to_run))

        if not to_run:
            return 0, 0

        lanes = self._vol2_lanes(image, len(to_run))
        # slow ones first so they overlap each other instead of running back to back
        to_run.sort(key=lambda x: 0 if x in VOL2_SLOW else 1)
        self.log.info("Running %d Vol2-exclusive plugins (%d at a time)...", len(to_run), lanes)
        ok = fail = 0
        if lanes <= 1:
            for p in to_run:
                r = self.vol.run_plugin(image, p, output_dir, version="vol2")
                if r["success"]:
                    ok += 1
                else:
                    fail += 1
        else:
            # v2.4: the Vol2 extras used to run strictly one after another. In the
            # Full DFIR preset timers (~12 min) + apihooks (~17 min) alone kept the
            # whole pipeline waiting ~31 min on a 2 GB Win7 dump; side by side the
            # wait is the longest single plugin. Each plugin is its own python2
            # process (one CPU core each), so they do not slow each other down.
            with ThreadPoolExecutor(max_workers=lanes) as pool:
                futs = [pool.submit(self.vol.run_plugin, image, p, output_dir, version="vol2")
                        for p in to_run]
                for f in futs:
                    try:
                        r = f.result()
                    except Exception as exc:
                        self.log.error("Vol2 plugin exception: %s", exc)
                        r = {"success": False}
                    if r.get("success"):
                        ok += 1
                    else:
                        fail += 1
        self.log.info("Vol2 extras: %d OK, %d failed", ok, fail)
        return ok, fail

    def _vol2_lanes(self, image, n_plugins: int) -> int:
        """How many Vol2 extras may run at once: up to 3, never more than a quarter of
        the CPU threads (the Vol3 batch runs at the same time), 1 on a spinning disk
        with a dump too big for the file cache, and 1 when RAM is short."""
        if os.environ.get("RAMBREAKER_VOL2_LANES", "").isdigit():
            return max(1, min(8, int(os.environ["RAMBREAKER_VOL2_LANES"])))
        lanes = max(1, min(3, (os.cpu_count() or 2) // 4, n_plugins))
        try:
            from modules.platform_compat import io_limited_jobs, available_ram_gb
            if getattr(self, "speed", "normal") != "fastest":
                lanes = min(lanes, io_limited_jobs(image, lanes))
                avail = available_ram_gb()
                if avail:
                    lanes = min(lanes, max(1, int((avail - 2.0) / 1.0)))
        except Exception:
            pass
        return max(1, lanes)

    def _expected_json(self, plugin):
        if "." in plugin:
            return plugin.replace(".", "_") + ".json"
        return plugin + "_vol2.json"

    def write_summary(self, output_dir, image, mode, results):
        s = output_dir / "SUMMARY.txt"
        lines = [
            "CresCent RAM Forensics Toolkit - Analysis Summary",
            "=" * 50,
            f"Image:      {image}", f"OS:         {self.vol.os_type}",
            f"Mode:       {mode}", f"Volatility: {self.vol.vol_version}",
            f"Profile:    {self.vol.profile or 'N/A'}",
            f"Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Duration:   {results['duration']:.1f}s",
            f"JSON files: {results['json_count']}",
            f"TXT files:  {results['txt_count']}",
            f"Succeeded:  {results['ok']}", f"Failed:     {results['fail']}",
            f"Skipped:    {results['skipped']}",
            f"Dep-skipped:{results.get('dep_skipped', 0)}",
        ]
        s.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.log.info("Summary written to %s", s)

        # Run-health: corroboration guard + failure taxonomy. Appends a health
        # banner to SUMMARY.txt, writes run_health.json, and logs loud warnings
        # for red flags so a silently-incomplete run can't pass as clean.
        try:
            from modules import run_health
            health = run_health.assess(output_dir, self.vol.os_type, mode, results)
            with open(s, "a", encoding="utf-8") as fh:
                fh.write("\n".join(health["banner"]) + "\n")
            for f in health.get("findings", []):
                lvl = (self.log.error if f["severity"] == run_health.CRITICAL
                       else self.log.warning if f["severity"] == run_health.WARN
                       else self.log.info)
                lvl("RUN HEALTH: %s", f["message"])
            if health["status"] != "healthy":
                self.log.warning("RUN HEALTH status: %s", health["status"])
            # Failure fingerprint: on any failure, drop a scrubbed, local-only
            # crash_report.json (Step 1 of opt-in crash reporting) an analyst can
            # hand to the tool author. Best-effort — never disturbs extraction.
            try:
                from modules import crash_report
                cr = crash_report.write(output_dir, image, self.vol, mode,
                                        results, health)
                if cr:
                    self.log.warning("Failure fingerprint written: %s", cr)
            except Exception as e:
                self.log.warning("crash_report skipped: %s", e)
        except Exception as e:
            self.log.warning("run_health assessment skipped: %s", e)
