"""extractor.linux.py — Linux-specific Volatility plugin runner (v6.0)

Extracted from extractor.py for OS-specific split architecture.
Contains Linux PLUGINS only. No VOL2_EXCLUSIVE or VOL2_XP_ONLY.
No Windows-specific methods (_run_targeted_printkey, _run_vol2_exclusive).
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from modules.volatility import VolatilityWrapper
from utils.json_converter import convert_json_to_txt

PLUGINS: Dict[str, str] = {
    "vol3-linux-fast": "linux.pslist.PsList linux.pstree.PsTree linux.psaux.PsAux linux.bash.Bash linux.lsmod.Lsmod linux.check_modules.Check_modules linux.sockstat.Sockstat linux.lsof.Lsof linux.proc.Maps linux.pagecache.Files",
    "vol3-linux-full": "linux.pslist.PsList linux.pstree.PsTree linux.psaux.PsAux linux.bash.Bash linux.sockstat.Sockstat linux.lsmod.Lsmod linux.check_modules.Check_modules linux.check_syscall.Check_syscall linux.tty_check.tty_check linux.elfs.Elfs linux.envars.Envars linux.library_list.LibraryList linux.lsof.Lsof linux.mountinfo.MountInfo linux.malfind.Malfind linux.ip.Addr linux.proc.Maps linux.pagecache.Files",
    "vol3-linux-malware": "linux.pslist.PsList linux.pstree.PsTree linux.bash.Bash linux.lsmod.Lsmod linux.check_modules.Check_modules linux.check_syscall.Check_syscall linux.tty_check.tty_check linux.elfs.Elfs linux.sockstat.Sockstat linux.malfind.Malfind",
    "vol3-linux-network": "linux.pslist.PsList linux.pstree.PsTree linux.sockstat.Sockstat linux.lsof.Lsof linux.ip.Addr",
    "vol2-linux-fast": "linux_pslist linux_pstree linux_psaux linux_bash linux_lsmod linux_check_modules linux_lsof linux_proc_maps",
    "vol2-linux-full": "linux_pslist linux_pstree linux_psaux linux_bash linux_ifconfig linux_netstat linux_lsmod linux_check_modules linux_check_syscall linux_dmesg linux_enumerate_files linux_lsof linux_mount linux_elfs linux_proc_maps",
    "vol2-linux-malware": "linux_pslist linux_pstree linux_bash linux_lsmod linux_check_modules linux_check_syscall linux_elfs linux_proc_maps linux_hidden_modules linux_malfind",
    "vol2-linux-network": "linux_pslist linux_pstree linux_ifconfig linux_netstat linux_lsof",
}

VALID_MODES = ("fast", "full", "malware", "network")

DEPENDENCIES: Dict[str, Set[str]] = {
    "pslist": {"pstree", "psscan", "psaux", "lsof"},
}


def _short_name(plugin: str) -> str:
    parts = plugin.lower().replace("linux.", "").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


class Extractor:
    """Parallel Volatility plugin runner for Linux images."""

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
            self.log.info("FASTEST mode: %d jobs (RAM guard OFF)", self.jobs)
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
        linux_identify.warm_isf_cache(self.vol.vol3_cmd, image, self.log)

    def run(self, image: str, output_dir: Path, mode: str = "full",
            skip_existing: bool = True) -> Dict[str, Any]:
        if mode not in VALID_MODES:
            self.log.warning("Unknown mode '%s', defaulting to 'full'", mode)
            mode = "full"

        key = f"{self.vol.vol_version}-linux-{mode}"
        plugin_str = PLUGINS.get(key, PLUGINS.get("vol3-linux-full", ""))
        plugins = plugin_str.split()

        self.log.info("Starting Linux extraction: %d plugins (%s - %s mode, %d parallel jobs)",
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

        ok = fail = dep_skipped = 0
        start = time.time()
        self._failed_parents = set()

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
                except Exception as exc:
                    fail += 1
                    self.log.error("[%d/%d] %s exception: %s",
                                   completed, actual_total, plug, exc)

        dur = time.time() - start
        self.log.info("Main scan: %d OK, %d failed, %d skipped, %d dep-skipped (%.1fs)",
                      ok, fail, skipped, dep_skipped, dur)

        self.log.info("Converting JSON to TXT...")
        td = output_dir / "txt"
        c_ok, c_f = convert_json_to_txt(jd, td)
        self.log.info("Converted %d JSON to TXT (%d failed)", c_ok, c_f)

        return {"ok": ok, "fail": fail,
                "skipped": skipped, "dep_skipped": dep_skipped,
                "duration": time.time() - start,
                "json_count": len(list(jd.glob("*.json"))),
                "txt_count": len(list(td.glob("*.txt")))}

    def _check_dependency(self, short_name: str) -> Optional[str]:
        for parent, children in DEPENDENCIES.items():
            if short_name in children and parent in self._failed_parents:
                return parent
        return None

    def _expected_json(self, plugin):
        if "." in plugin:
            return plugin.replace(".", "_") + ".json"
        return plugin + "_vol2.json"

    def write_summary(self, output_dir, image, mode, results):
        s = output_dir / "SUMMARY.txt"
        lines = [
            "CresCent RAM Forensics Toolkit - Analysis Summary",
            "=" * 50,
            f"Image:      {image}", f"OS:         linux",
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
            health = run_health.assess(output_dir, "linux", mode, results)
            with open(s, "a", encoding="utf-8") as fh:
                fh.write("\n".join(health["banner"]) + "\n")
            for f in health.get("findings", []):
                lvl = (self.log.error if f["severity"] == run_health.CRITICAL
                       else self.log.warning if f["severity"] == run_health.WARN
                       else self.log.info)
                lvl("RUN HEALTH: %s", f["message"])
            if health["status"] != "healthy":
                self.log.warning("RUN HEALTH status: %s", health["status"])
        except Exception as e:
            self.log.warning("run_health assessment skipped: %s", e)
