#!/usr/bin/env python3
"""Tier-A golden tests — fast, no memory images, zero third-party deps.

Run:  python3 tests/run_tests.py     (exit 0 = all pass, non-zero = failure)

These pin the pure, kernel-independent logic — the parsing/health/IOC code that
is *your* code, not Volatility's — so old bugs (e.g. the Bug-#10 silent-empty
process list) can't silently come back. They deliberately do NOT drive
Volatility; the canary matrix (a later step) covers real images.
"""

import sys
import json
import logging
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIX = Path(__file__).resolve().parent / "fixtures"

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


# --------------------------------------------------------------------------- #
def test_corroborate_processes():
    from modules import run_health as rh
    C = rh.CRITICAL
    print("[corroborate_processes]")

    ok = rh.corroborate_processes({"pslist": 37, "psscan": 37, "pstree": 37})
    check("healthy run -> no findings", ok == [], detail=str(ok))

    bug10 = rh.corroborate_processes({"pslist": 0, "psscan": 120, "pstree": 0})
    check("Bug-#10 (pslist=0, psscan=120) -> CRITICAL",
          any(f["severity"] == C for f in bug10), detail=str(bug10))
    check("Bug-#10 message names psscan",
          any("psscan" in f["message"] for f in bug10))

    empty = rh.corroborate_processes({"pslist": 0, "psscan": 0, "pstree": 0})
    check("all-empty -> CRITICAL", any(f["severity"] == C for f in empty))

    none = rh.corroborate_processes({"pslist": None, "psscan": None, "pstree": None})
    check("no plugins ran -> CRITICAL", any(f["severity"] == C for f in none))

    hidden = rh.corroborate_processes({"pslist": 40, "psscan": 60, "pstree": 40})
    check("psscan>>pslist -> WARN (not critical)",
          hidden and all(f["severity"] != C for f in hidden), detail=str(hidden))


def test_classify_failure():
    from modules import run_health as rh
    print("[classify_failure]")
    cases = {
        "AttributeError: 'taint_flag' object has no attribute 'module'": "struct-mismatch",
        "Member not present in template: mnt": "struct-mismatch",
        "No matching ISF for this banner": "symbol-missing",
        "A symbol table requirement was not fulfilled": "symbol-missing",
        "plugin timed out after 600s": "timeout",
    }
    for text, expected in cases.items():
        got = rh.classify_failure(text)["category"]
        check(f"{expected:16} <- {text[:40]!r}", got == expected, detail=f"got {got}")

    # Expected-nonbugs are recognised by PLUGIN NAME, regardless of error text.
    banner = "Volatility Foundation Volatility Framework 2.6.1"
    for name in ("connections", "connscan", "sockets", "sockstat"):
        got = rh.classify_failure(banner, name)["category"]
        check(f"expected-nonbug by name: {name}", got == "expected-nonbug",
              detail=f"got {got}")

    # Banner-only / empty error = benign empty result, not a real failure.
    check("banner-only error -> empty-result",
          rh.classify_failure(banner, "ssdt")["category"] == "empty-result")
    check("empty error -> empty-result",
          rh.classify_failure("", "whatever")["category"] == "empty-result")


def test_assess_fixtures():
    from modules import run_health as rh
    print("[assess() on fixtures]")

    good = rh.assess(FIX / "good_win", "windows")
    check("healthy fixture -> status healthy",
          good["status"] == "healthy", detail=good["status"])
    check("healthy fixture -> no critical findings",
          all(f["severity"] != rh.CRITICAL for f in good["findings"]))

    bug = rh.assess(FIX / "bug10_win", "windows")
    check("Bug-#10 fixture -> status broken",
          bug["status"] == "broken", detail=bug["status"])
    check("Bug-#10 fixture -> critical process finding",
          any(f["check"] == "processes" and f["severity"] == rh.CRITICAL
              for f in bug["findings"]))


def test_ioc_extractor():
    from modules.ioc_extractor import IOCExtractor
    print("[ioc_extractor.scan_single_string]")
    ie = IOCExtractor(logging.getLogger("test"))

    def cats(s):
        return {r["category"] for r in ie.scan_single_string(s)}

    def matches(s):
        return {r["match"] for r in ie.scan_single_string(s)}

    check("plain prose -> NO IOCs (false-positive guard)",
          cats("hello world this is a normal sentence") == set(),
          detail=str(cats("hello world this is a normal sentence")))
    check("public IP -> network category",
          "network" in cats("attacker at 203.0.113.45 connected"))
    check("URL -> network category",
          "network" in cats("beacon to http://evil.example.com/c2"))
    check("email -> email category",
          "email" in cats("contact bad.actor@evil.com"))
    btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    check("bitcoin address -> crypto, exact match",
          "crypto" in cats(f"pay {btc}") and btc in matches(f"pay {btc}"))


# Frozen whitelist of top-level keys crash_report.build may ever emit. A new key
# here must be a deliberate, reviewed change — this guards against a future field
# silently carrying image-derived data into the handoff artifact.
_CRASH_KEYS = {
    "schema", "generated", "note", "tool_version", "run", "host", "target",
    "toolchain", "process_corroboration", "findings", "failed_plugins",
    "ok_plugins", "fingerprint",
}


def test_crash_report():
    from modules import crash_report as cr
    from modules import run_health as rh
    print("[crash_report]")

    # --- scrub(): every sensitive shape is redacted ---
    s = cr.scrub("read /home/kali/case/dump.raw at 0xdeadbeef and "
                 "C:\\Users\\victim\\m.exe")
    check("scrub redacts unix user path", "/home/kali" not in s, detail=s)
    check("scrub redacts windows path", "victim" not in s, detail=s)
    check("scrub redacts hex address", "0xdeadbeef" not in s, detail=s)
    check("scrub inserts placeholders", "<path>" in s and "<addr>" in s, detail=s)

    # --- parse_kernel_banner(): version+distro only, builder identity dropped ---
    banner = ("Linux version 6.1.0-kali9-amd64 (devel@buildbox) "
              "(gcc 13) #1 SMP Kali 6.1.27-1kali1")
    pk = cr.parse_kernel_banner(banner)
    check("banner -> kernel version", pk["kernel"] == "6.1.0-kali9-amd64",
          detail=str(pk))
    check("banner -> distro Kali", pk["distro"] == "Kali", detail=str(pk))
    check("banner builder user@host NOT retained",
          "buildbox" not in json.dumps(pk) and "devel@" not in json.dumps(pk))
    check("ubuntu banner -> Ubuntu",
          cr.distro_from_banner("Linux version 5.15.0-91 (Ubuntu 11.4)") == "Ubuntu")

    # --- fingerprint(): 16 hex chars, order-independent ---
    tgt = {"os_type": "linux", "engine": "vol3", "kernel": "6.1", "distro": "Kali"}
    f1 = cr.fingerprint(tgt, [{"plugin": "a", "category": "x"},
                              {"plugin": "b", "category": "y"}])
    f2 = cr.fingerprint(tgt, [{"plugin": "b", "category": "y"},
                              {"plugin": "a", "category": "x"}])
    check("fingerprint stable + order-independent",
          f1 == f2 and len(f1) == 16, detail=f"{f1} vs {f2}")

    # --- build(): whitelisted keys only, correct status, no leakage ---
    health = {
        "status": "degraded",
        "process_counts": {"pslist": 5, "psscan": 5, "pstree": 5},
        "findings": [{"severity": "warning", "check": "files",
                      "message": "empty at /home/zztopsecret/case 0xCAFEB0BE"}],
        "failure_taxonomy": [{"plugin": "linux.lsof.Lsof",
                              "category": "struct-mismatch",
                              "reason": "read /home/zzanalyst/x on 0x41414141"}],
    }
    rep = cr.build(FIX / "good_win", os_type="linux", engine="vol3", profile=None,
                   mode="full",
                   results={"ok": 10, "fail": 1, "duration": 12.3,
                            "skipped": 0, "dep_skipped": 0},
                   health=health)
    check("build emits only whitelisted keys",
          set(rep) == _CRASH_KEYS, detail=str(set(rep) ^ _CRASH_KEYS))
    check("build carries status through", rep["run"]["status"] == "degraded")
    check("build maps taxonomy -> failed_plugins",
          rep["failed_plugins"] and rep["failed_plugins"][0]["name"] == "linux.lsof.Lsof")
    blob = json.dumps(rep)
    check("build leaks NO target path", "zztopsecret" not in blob
          and "zzanalyst" not in blob, detail="path leaked into report")
    check("build leaks NO raw address", "0xCAFEB0BE" not in blob
          and "0x41414141" not in blob)
    check("build scrubs into placeholders", "<path>" in blob and "<addr>" in blob)

    # --- _should_write(): fires on real trouble, silent on benign-only ---
    sw = cr._should_write
    check("healthy + no failures -> no report",
          sw({"fail": 0}, {"status": "healthy", "failure_taxonomy": []}) is False)
    check("healthy + only expected-nonbug/empty -> no report",
          sw({"fail": 2}, {"status": "healthy",
             "failure_taxonomy": [{"category": "expected-nonbug"},
                                  {"category": "empty-result"}]}) is False)
    check("healthy + a real failure (timeout) -> report",
          sw({"fail": 1}, {"status": "healthy",
             "failure_taxonomy": [{"category": "timeout"}]}) is True)
    check("degraded status -> report",
          sw({"fail": 0}, {"status": "degraded", "failure_taxonomy": []}) is True)
    check("failures present but unclassified -> report",
          sw({"fail": 3}, {"status": "healthy", "failure_taxonomy": []}) is True)

    # --- write(): artifact only on real failure; benign/clean runs leave nothing ---
    v = types.SimpleNamespace(os_type="windows", vol_version="vol3", profile=None)
    good_health = rh.assess(FIX / "good_win", "windows")
    none_path = cr.write(FIX / "good_win", "img.raw", v,
                         "full", {"ok": 5, "fail": 0}, good_health)
    check("healthy run writes NO crash_report", none_path is None, detail=str(none_path))

    bug_health = rh.assess(FIX / "bug10_win", "windows")
    out = cr.write(FIX / "bug10_win", "img.raw", v,
                   "full", {"ok": 1, "fail": 0, "duration": 3.0}, bug_health)
    try:
        check("broken run writes crash_report.json",
              out is not None and Path(out).is_file(), detail=str(out))
        if out and Path(out).is_file():
            data = json.loads(Path(out).read_text())
            check("written report has broken status",
                  data["run"]["status"] == "broken", detail=str(data["run"]))
            check("ok_plugins excludes bookkeeping files",
                  "run_health" not in data["ok_plugins"]
                  and "crash_report" not in data["ok_plugins"])
    finally:
        if out and Path(out).is_file():
            Path(out).unlink()  # keep fixtures pristine


def test_vol3_demotion():
    from modules.volatility import (_vol3_success, _is_empty_result,
                                    _is_plugin_exception, _write_error_marker)
    print("[vol3 silent-failure demotion]")
    ATTR = "AttributeError: 'module' object has no attribute 'taint_flag'"

    # _is_empty_result
    check("'[]' is empty", _is_empty_result("[]"))
    check("'[\\n]' is empty (whitespace-tolerant)", _is_empty_result("[\n]"))
    check("real rows not empty", not _is_empty_result('[{"pid":1}]'))

    # _is_plugin_exception — systemic only, no benign demotes
    check("AttributeError -> exception", _is_plugin_exception(ATTR))
    check("not-present-in-template -> exception",
          _is_plugin_exception("Member not present in template: mnt"))
    check("clean banner -> not exception",
          not _is_plugin_exception("Volatility 3 Framework 2.28.1"))
    check("warning -> not exception (won't demote)",
          not _is_plugin_exception("UserWarning: deprecated"))
    check("empty stderr -> not exception", not _is_plugin_exception(""))

    # _vol3_success — the core new-kernel demotion
    check("linux rc0 + rows -> success",
          _vol3_success(0, '[{"pid":1}]', "", "linux"))
    check("linux rc0 + clean-empty -> success (no false demote)",
          _vol3_success(0, "[]", "", "linux"))
    check("linux rc0 + EMPTY + struct exc -> DEMOTED to fail",
          not _vol3_success(0, "[]", ATTR, "linux"))
    check("linux rc0 + ROWS + struct exc -> kept (evidence-preserving)",
          _vol3_success(0, '[{"pid":1}]', ATTR, "linux"))
    check("mac rc0 + empty + struct exc -> DEMOTED",
          not _vol3_success(0, "[]", ATTR, "mac"))
    check("rc!=0 -> fail", not _vol3_success(1, '[{"pid":1}]', "", "linux"))
    check("stdout 'Unsatisfied requirement' -> fail",
          not _vol3_success(0, "Unsatisfied requirement for kernel", "", "linux"))
    check("windows rc0 + empty -> fail (unchanged)",
          not _vol3_success(0, "[]", "", "windows"))
    check("windows rc0 + real rows -> success (unchanged)",
          _vol3_success(0, '[{"pid":1,"name":"System"}]', "", "windows"))

    # _write_error_marker — resume sidecar lifecycle (fixes cache poisoning)
    import tempfile, shutil
    d = Path(tempfile.mkdtemp())
    try:
        jp = d / "linux_lsmod_Lsmod.json"
        jp.write_text("[]")
        marker = Path(str(jp) + ".error")
        _write_error_marker(jp, False, ATTR)
        check("failure leaves .error sidecar",
              marker.exists() and "taint_flag" in marker.read_text())
        _write_error_marker(jp, True, "")
        check("success clears .error sidecar", not marker.exists())
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    for t in (test_corroborate_processes, test_classify_failure,
              test_assess_fixtures, test_ioc_extractor, test_crash_report,
              test_vol3_demotion):
        try:
            t()
        except Exception as exc:  # a crashing test is a failing test
            global _FAIL
            _FAIL += 1
            print(f"  FAIL  {t.__name__} raised {type(exc).__name__}: {exc}")
    print("-" * 50)
    print(f"RESULT: {_PASS} passed, {_FAIL} failed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
