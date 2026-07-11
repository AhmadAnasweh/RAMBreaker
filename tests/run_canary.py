#!/usr/bin/env python3
"""Tier-B canary — drive the REAL extraction pipeline against a fake Vol3.

Run:  python3 tests/run_canary.py     (exit 0 = all pass)

Unlike the pure Tier-A suite (`run_tests.py`), this exercises the parts that only
break at runtime: the subprocess call, stdout/stderr parsing, the silent-failure
demotion, the `.json.error` resume sidecar, resume skip/re-run selection,
`write_summary -> run_health -> crash_report`, and HTML-report generation from
attacker-controlled strings. It needs no memory image — `fixtures/canary/
fake_vol3.py` stands in for Volatility and emits canned per-plugin output. The
one Vol3-internal step we cannot fake (ISF cache warm-up) is stubbed out.
"""

import json
import logging
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
STUB = Path(__file__).resolve().parent / "fixtures" / "canary" / "fake_vol3.py"

from modules.volatility import VolatilityWrapper          # noqa: E402
from modules.extractor import Extractor                   # noqa: E402
from modules.logger import CrescentLogger                 # noqa: E402
from modules.html_report import HTMLReportGenerator       # noqa: E402

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  PASS  {name}")
    else:
        _FAIL += 1
        print(f"  FAIL  {name}   {detail}")


def _build_vol():
    vol = VolatilityWrapper(logging.getLogger("canary-vol"))
    vol.os_type = "linux"
    vol.vol_version = "vol3"
    vol.vol3_cmd = f"{sys.executable} {STUB}"
    vol.vol2_cmd = None
    vol.profile = None
    return vol


def main():
    tmp = Path(tempfile.mkdtemp(prefix="canary_"))
    try:
        img = tmp / "fake.lime"
        img.write_bytes(b"\x00" * 4096)          # tiny stand-in; the stub ignores it
        out = tmp / "out"
        out.mkdir()
        clog = CrescentLogger(str(out), quiet=True)   # writes crescent_toolkit.log
        vol = _build_vol()
        ext = Extractor(vol, clog.get_logger("EXTRACTOR"), jobs=2, speed="fast")
        ext._warm_cache = lambda *a, **k: None        # isolate from real Vol3 cache

        # ---- first extraction ----
        print("[canary: extraction]")
        results = ext.run(str(img), out, "fast")
        ext.write_summary(out, str(img), "fast", results)
        jd = out / "json"

        check("success plugin produced JSON",
              (jd / "linux_pslist_PsList.json").exists())
        check("pool-scan (psscan) produced JSON",
              (jd / "linux_psscan_PsScan.json").exists())
        check("silent struct failure DEMOTED -> .error sidecar",
              (jd / "linux_lsmod_Lsmod.json.error").exists())
        check("hard failure -> .error sidecar",
              (jd / "linux_proc_Maps.json.error").exists())
        check("success plugin has NO sidecar",
              not (jd / "linux_pslist_PsList.json.error").exists())
        check("clean-empty plugin NOT demoted (no sidecar)",
              not (jd / "linux_sockstat_Sockstat.json.error").exists(),
              detail="sockstat is a legit empty result")
        check("failure count >= 2 (demote + hardfail)",
              results.get("fail", 0) >= 2, detail=str(results))
        check("json_count excludes .error sidecars",
              results.get("json_count", 0) >= 5, detail=str(results))

        # ---- run_health + crash_report wiring ----
        print("[canary: health + crash report]")
        check("run_health.json written", (out / "run_health.json").exists())
        check("crash_report.json written (real failures)",
              (out / "crash_report.json").exists())
        health = json.loads((out / "run_health.json").read_text())
        check("status degraded/broken (not healthy)",
              health["status"] in ("degraded", "broken"), detail=health["status"])
        checks = " ".join(f["check"] for f in health.get("findings", []))
        check("network tab flagged empty (sockstat=0)", "network" in checks,
              detail=checks)
        cr = json.loads((out / "crash_report.json").read_text())
        cats = {p["category"] for p in cr.get("failed_plugins", [])}
        names = {p["name"] for p in cr.get("failed_plugins", [])}
        check("crash_report taxonomy has the demoted plugin",
              any("lsmod" in n for n in names), detail=str(names))
        check("crash_report classifies struct-mismatch",
              "struct-mismatch" in cats, detail=str(cats))
        check("crash_report leaks no builder/host path",
              "/tmp/" not in json.dumps(cr) and "canary_" not in json.dumps(cr))

        # ---- resume: success plugins skipped, failures re-run ----
        print("[canary: resume]")
        results2 = ext.run(str(img), out, "fast")
        check("resume skips the good-content plugins",
              results2.get("skipped", 0) >= 4, detail=str(results2))
        check("resume re-runs the failed plugins",
              results2.get("fail", 0) >= 2, detail=str(results2))
        check("sidecars persist after failed re-run",
              (jd / "linux_lsmod_Lsmod.json.error").exists())

        # ---- HTML report from attacker-controlled strings ----
        print("[canary: report + XSS]")
        gen = HTMLReportGenerator(clog.get_logger("HTML"), "linux")
        report = gen.generate(out)
        html = Path(report).read_text(encoding="utf-8")
        check("report.html generated", Path(report).exists() and len(html) > 1000)
        check("hostile process name NOT live in report",
              "<script>alert(1)</script>" not in html)
        check("hostile process name present only encoded",
              "\\u003cscript\\u003ealert(1)" in html)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("-" * 50)
    print(f"CANARY RESULT: {_PASS} passed, {_FAIL} failed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
