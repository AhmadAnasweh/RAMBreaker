#!/usr/bin/env python3
"""Tier-A golden tests — fast, no memory images, zero third-party deps.

Run:  python3 tests/run_tests.py     (exit 0 = all pass, non-zero = failure)

These pin the pure, kernel-independent logic — the parsing/health/IOC code that
is *your* code, not Volatility's — so old bugs (e.g. the Bug-#10 silent-empty
process list) can't silently come back. They deliberately do NOT drive
Volatility; the canary matrix (a later step) covers real images.
"""

import sys
import logging
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


def main():
    for t in (test_corroborate_processes, test_classify_failure,
              test_assess_fixtures, test_ioc_extractor):
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
