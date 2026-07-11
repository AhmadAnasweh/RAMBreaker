"""extractor.windows.py — Windows-specific Volatility plugin runner (v6.0)

Extracted from extractor.py for OS-specific split architecture.
Contains Windows PLUGINS, VOL2_EXCLUSIVE, VOL2_XP_ONLY, and the full
Extractor class including _run_targeted_printkey and _run_vol2_exclusive.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from modules.volatility import VolatilityWrapper
from utils.json_converter import convert_json_to_txt

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
VALID_MODES = ("fast", "full", "malware", "network", "persistence", "registry")

DEPENDENCIES: Dict[str, Set[str]] = {
    "pslist": {"pstree", "psscan", "psxview", "cmdline", "dlllist",
               "handles", "getsids", "envars", "privileges", "sessions",
               "ldrmodules", "malfind", "vadinfo"},
    "netscan": {"netstat"},
    "netstat": {"netscan"},
    "hivelist": {"userassist", "printkey", "shellbags", "shimcache"},
    "modules": {"modscan"},
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
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        avail_gb = int(line.split()[1]) / (1024 ** 2)
                        break
        except Exception:
            pass
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

    def run(self, image: str, output_dir: Path, mode: str = "full",
            skip_existing: bool = True) -> Dict[str, Any]:
        if mode not in VALID_MODES:
            self.log.warning("Unknown mode '%s', defaulting to 'full'", mode)
            mode = "full"

        key = f"{self.vol.vol_version}-{self.vol.os_type}-{mode}"
        plugin_str = PLUGINS.get(key, PLUGINS.get(
            f"{self.vol.vol_version}-windows-full", ""))
        plugins = plugin_str.split()

        self.log.info("Starting extraction: %d plugins (%s - %s mode, %d parallel jobs)",
                      len(plugins), self.vol.vol_version, mode, self.jobs)

        actual_jobs = self._adaptive_jobs(image)

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
                if jp.exists() and jp.stat().st_size > 10:
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

        with ThreadPoolExecutor(max_workers=actual_jobs) as pool:
            futures = {}
            for p in to_run:
                short = _short_name(p)
                skip_reason = self._check_dependency(short)
                if skip_reason:
                    dep_skipped += 1
                    self.log.info("[SKIP] %s — dependency '%s' failed", p, skip_reason)
                    continue
                futures[pool.submit(self.vol.run_plugin, image, p, output_dir)] = p

            completed = 0
            actual_total = len(futures)
            for future in as_completed(futures):
                plug = futures[future]
                completed += 1
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
                        if short in DEPENDENCIES:
                            self._failed_parents.add(short)
                            children = DEPENDENCIES[short]
                            self.log.warning(
                                "[%d/%d] %s FAILED (will skip dependents: %s): %s",
                                completed, actual_total, plug,
                                ", ".join(sorted(children)),
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
                v2ok, v2f = vol2_future.result(timeout=600)
            except Exception as e:
                self.log.error("Vol2 background task failed: %s", e)
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
                cmd = (vol_cmd.split() +
                       ["-f", image, "-r", "json",
                        "windows.registry.printkey.PrintKey",
                        "--key", key_path])
            else:
                cmd = (vol_cmd.split() +
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

    def _check_dependency(self, short_name: str) -> Optional[str]:
        for parent, children in DEPENDENCIES.items():
            if short_name in children and parent in self._failed_parents:
                return parent
        return None

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
        p_lower = (self.vol.profile or "").lower()
        if any(x in p_lower for x in ("xp", "2003", "win2003")):
            plugs += VOL2_XP_ONLY.split()
            self.log.info("XP/2003 profile — including network plugins (connections, sockets)")

        jd = output_dir / "json"
        to_run = []
        for p in plugs:
            exp = self._expected_json(p)
            if (jd / exp).exists() and (jd / exp).stat().st_size > 10:
                continue
            to_run.append(p)

        if len(to_run) < len(plugs):
            self.log.info("Vol2 resume: skipping %d already completed", len(plugs) - len(to_run))

        if not to_run:
            return 0, 0

        self.log.info("Running %d Vol2-exclusive plugins...", len(to_run))
        ok = fail = 0
        for p in to_run:
            r = self.vol.run_plugin(image, p, output_dir, version="vol2")
            if r["success"]:
                ok += 1
            else:
                fail += 1
        self.log.info("Vol2 extras: %d OK, %d failed", ok, fail)
        return ok, fail

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
